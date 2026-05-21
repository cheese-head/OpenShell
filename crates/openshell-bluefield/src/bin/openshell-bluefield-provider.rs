// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Parser;
use miette::{IntoDiagnostic, Result};
use openshell_bluefield::backend::{
    BlueFieldAttachmentBackend, BlueFieldHardwareActuator, FileLeaseStore,
};
use openshell_bluefield::command::SystemCommandRunner;
use openshell_bluefield::config::{BlueFieldProviderConfig, BlueFieldVfioMode};
use openshell_bluefield::network::{FlowOwnerPolicy, OvsOfctlExecutor};
use openshell_bluefield::provider::AttachmentProviderService;
use openshell_bluefield::vfio::SysfsVfioDeviceManager;
use openshell_core::VERSION;
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "openshell-bluefield-provider")]
#[command(version = VERSION)]
struct Args {
    #[arg(long, env = "OPENSHELL_BLUEFIELD_PROVIDER_CONFIG")]
    config: Option<PathBuf>,

    #[arg(long, env = "OPENSHELL_BLUEFIELD_PROVIDER_BIND")]
    bind_address: Option<SocketAddr>,

    #[arg(long, env = "OPENSHELL_LOG_LEVEL", default_value = "info")]
    log_level: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&args.log_level)),
        )
        .init();

    let mut config = load_config(args.config.as_ref())?;
    if let Some(bind_address) = args.bind_address {
        config.bind_address = bind_address;
    }

    let backend_config = config.backend_config();
    let leases = FileLeaseStore::new(config.lease_path.clone());
    let actuator = BlueFieldHardwareActuator::new(
        SysfsVfioDeviceManager::new(config.sysfs_pci_devices_path.clone()),
        OvsOfctlExecutor::new(SystemCommandRunner).with_program(config.ovs_ofctl.clone()),
        FlowOwnerPolicy::default().with_bridge(config.ovs_bridge.clone()),
    )
    .with_vfio_enabled(matches!(config.vfio_mode, BlueFieldVfioMode::Managed));
    let backend =
        BlueFieldAttachmentBackend::with_lease_store_and_actuator(backend_config, leases, actuator)
            .map_err(|err| miette::miette!("{err}"))?;
    let bind_address = config.bind_address;
    let vf_slots = config.vf_pool.len();
    let ovs_bridge = config.ovs_bridge.clone();
    let lease_path = config.lease_path.clone();

    info!(
        address = %bind_address,
        ovs_bridge = %ovs_bridge,
        lease_path = %lease_path.display(),
        vf_slots,
        "Starting BlueField attachment provider"
    );
    let mut server = Server::builder();
    if let Some(tls) = server_tls_config(config.tls.as_ref())? {
        install_rustls_provider();
        server = server.tls_config(tls).into_diagnostic()?;
    }

    server
        .add_service(AttachmentProviderService::new(backend).into_grpc_server())
        .serve_with_shutdown(bind_address, async {
            tokio::signal::ctrl_c().await.ok();
            info!("Received shutdown signal, stopping BlueField provider");
        })
        .await
        .into_diagnostic()
}

fn load_config(path: Option<&PathBuf>) -> Result<BlueFieldProviderConfig> {
    path.map_or_else(
        || Ok(BlueFieldProviderConfig::default()),
        |path| {
            BlueFieldProviderConfig::load_from_file(path).map_err(|err| miette::miette!("{err}"))
        },
    )
}

fn server_tls_config(
    tls: Option<&openshell_bluefield::config::BlueFieldProviderTlsConfig>,
) -> Result<Option<ServerTlsConfig>> {
    let Some(tls) = tls else {
        return Ok(None);
    };

    let cert = std::fs::read(&tls.cert)
        .map_err(|err| miette::miette!("read TLS cert {}: {err}", tls.cert.display()))?;
    let key = std::fs::read(&tls.key)
        .map_err(|err| miette::miette!("read TLS key {}: {err}", tls.key.display()))?;
    let mut config = ServerTlsConfig::new().identity(Identity::from_pem(cert, key));
    if let Some(client_ca) = &tls.client_ca {
        let ca = std::fs::read(client_ca)
            .map_err(|err| miette::miette!("read client CA {}: {err}", client_ca.display()))?;
        config = config.client_ca_root(Certificate::from_pem(ca));
    }
    Ok(Some(config))
}

fn install_rustls_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}
