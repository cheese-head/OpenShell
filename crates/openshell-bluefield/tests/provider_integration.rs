// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(unix)]

use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use openshell_bluefield::backend::{
    BlueFieldAttachmentBackend, BlueFieldAttachmentBackendConfig, BlueFieldHardwareActuator,
    BlueFieldInventory, BlueFieldVfSlot, FileLeaseStore,
};
use openshell_bluefield::command::SystemCommandRunner;
use openshell_bluefield::network::{FlowOwnerPolicy, OvsOfctlExecutor};
use openshell_bluefield::provider::AttachmentProviderService;
use openshell_bluefield::vfio::SysfsVfioDeviceManager;
use openshell_core::proto::attachment::v1 as proto;
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::Server;

#[tokio::test]
async fn grpc_provider_attaches_reconciles_and_detaches_bluefield_vf() {
    let dir = tempfile::tempdir().unwrap();
    let pci_bus = fake_pci_bus(dir.path());
    let ovs_log = dir.path().join("ovs.log");
    let ovs_ofctl = fake_ovs_ofctl(dir.path(), &ovs_log);
    let lease_path = dir.path().join("leases.pb");

    let inventory = BlueFieldInventory::empty().with_vf_slot(
        BlueFieldVfSlot::new("vf0", "0000:03:00.2")
            .with_mac("02:00:00:00:00:10")
            .with_representor("pf0vf0"),
    );
    let backend_config = BlueFieldAttachmentBackendConfig::new("bf-a").with_inventory(inventory);
    let leases = FileLeaseStore::new(&lease_path);
    let actuator = BlueFieldHardwareActuator::new(
        SysfsVfioDeviceManager::new(pci_bus.join("devices")),
        OvsOfctlExecutor::new(SystemCommandRunner).with_program(ovs_ofctl),
        FlowOwnerPolicy::default().with_bridge("br-test"),
    )
    .with_vfio_enabled(true);
    let backend =
        BlueFieldAttachmentBackend::with_lease_store_and_actuator(backend_config, leases, actuator)
            .unwrap();
    let address = spawn_provider(backend).await;
    let mut client = proto::attachment_provider_client::AttachmentProviderClient::connect(format!(
        "http://{address}"
    ))
    .await
    .unwrap();

    let lease = client
        .attach(attach_request("sandbox-1"))
        .await
        .unwrap()
        .into_inner()
        .lease
        .unwrap();

    assert_eq!(lease.attachment_id, "bluefield-sandbox-1");
    assert_eq!(
        std::fs::read_to_string(pci_bus.join("devices/0000:03:00.2/driver_override")).unwrap(),
        "vfio-pci\n"
    );
    assert_eq!(
        std::fs::read_to_string(pci_bus.join("drivers_probe")).unwrap(),
        "0000:03:00.2\n"
    );
    assert_ovs_log_contains(&ovs_log, "add-flow br-test");
    assert!(lease_path.exists());

    client
        .reconcile(proto::ReconcileRequest {
            lease: Some(lease.clone()),
        })
        .await
        .unwrap();
    assert_eq!(ovs_log_lines(&ovs_log).len(), 2);

    fake_vfio_driver_binding(&pci_bus);
    client
        .detach(proto::DetachRequest { lease: Some(lease) })
        .await
        .unwrap();

    assert_ovs_log_contains(&ovs_log, "del-flows br-test");
    assert_eq!(
        std::fs::read_to_string(pci_bus.join("drivers/vfio-pci/unbind")).unwrap(),
        "0000:03:00.2\n"
    );

    let list = client
        .list(proto::ListRequest {})
        .await
        .unwrap()
        .into_inner();
    assert!(list.leases.is_empty());
}

#[tokio::test]
async fn grpc_provider_prebound_mode_skips_vfio_sysfs_and_programs_ovs() {
    let dir = tempfile::tempdir().unwrap();
    let pci_bus = fake_pci_bus(dir.path());
    let ovs_log = dir.path().join("ovs.log");
    let ovs_ofctl = fake_ovs_ofctl(dir.path(), &ovs_log);

    let inventory = BlueFieldInventory::empty()
        .with_vf_slot(BlueFieldVfSlot::new("vf0", "0000:03:00.2").with_representor("pf0vf0"));
    let backend_config = BlueFieldAttachmentBackendConfig::new("bf-a").with_inventory(inventory);
    let actuator = BlueFieldHardwareActuator::new(
        SysfsVfioDeviceManager::new(pci_bus.join("devices")),
        OvsOfctlExecutor::new(SystemCommandRunner).with_program(ovs_ofctl),
        FlowOwnerPolicy::default().with_bridge("br-test"),
    )
    .with_vfio_enabled(false);
    let backend = BlueFieldAttachmentBackend::with_lease_store_and_actuator(
        backend_config,
        FileLeaseStore::new(dir.path().join("leases.pb")),
        actuator,
    )
    .unwrap();
    let address = spawn_provider(backend).await;
    let mut client = proto::attachment_provider_client::AttachmentProviderClient::connect(format!(
        "http://{address}"
    ))
    .await
    .unwrap();

    let lease = client
        .attach(attach_request("sandbox-1"))
        .await
        .unwrap()
        .into_inner()
        .lease
        .unwrap();

    assert_eq!(
        std::fs::read_to_string(pci_bus.join("devices/0000:03:00.2/driver_override")).unwrap(),
        ""
    );
    assert_eq!(
        std::fs::read_to_string(pci_bus.join("drivers_probe")).unwrap(),
        ""
    );
    assert_ovs_log_contains(&ovs_log, "add-flow br-test");

    client
        .detach(proto::DetachRequest { lease: Some(lease) })
        .await
        .unwrap();

    assert_ovs_log_contains(&ovs_log, "del-flows br-test");
    assert_eq!(
        std::fs::read_to_string(pci_bus.join("drivers/vfio-pci/unbind")).unwrap(),
        ""
    );
}

async fn spawn_provider<B>(backend: B) -> SocketAddr
where
    B: openshell_bluefield::provider::AttachmentProviderBackend,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let service = AttachmentProviderService::new(backend).into_grpc_server();
    tokio::spawn(async move {
        Server::builder()
            .add_service(service)
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .unwrap();
    });
    address
}

fn fake_pci_bus(root: &Path) -> PathBuf {
    let pci_bus = root.join("bus/pci");
    let device = pci_bus.join("devices/0000:03:00.2");
    std::fs::create_dir_all(&device).unwrap();
    std::fs::create_dir_all(pci_bus.join("drivers/vfio-pci")).unwrap();
    std::fs::write(device.join("driver_override"), "").unwrap();
    std::fs::write(pci_bus.join("drivers_probe"), "").unwrap();
    std::fs::write(pci_bus.join("drivers/vfio-pci/unbind"), "").unwrap();
    pci_bus
}

fn fake_vfio_driver_binding(pci_bus: &Path) {
    let device = pci_bus.join("devices/0000:03:00.2");
    let driver = pci_bus.join("drivers/vfio-pci");
    std::os::unix::fs::symlink(driver, device.join("driver")).unwrap();
}

fn fake_ovs_ofctl(root: &Path, log: &Path) -> String {
    let script = root.join("ovs-ofctl");
    std::fs::write(
        &script,
        format!("#!/bin/sh\nprintf '%s\\n' \"$*\" >> {}\n", shell_quote(log)),
    )
    .unwrap();
    let mut permissions = std::fs::metadata(&script).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&script, permissions).unwrap();
    script.to_string_lossy().into_owned()
}

fn shell_quote(path: &Path) -> String {
    format!("'{}'", path.to_string_lossy().replace('\'', "'\\''"))
}

fn assert_ovs_log_contains(log: &Path, needle: &str) {
    let contents = std::fs::read_to_string(log).unwrap();
    assert!(
        contents.contains(needle),
        "OVS log did not contain {needle:?}: {contents}"
    );
}

fn ovs_log_lines(log: &Path) -> Vec<String> {
    std::fs::read_to_string(log)
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect()
}

fn attach_request(sandbox_id: &str) -> proto::AttachRequest {
    proto::AttachRequest {
        sandbox_id: sandbox_id.to_string(),
        sandbox_name: format!("{sandbox_id}-name"),
        image_ref: Some("example.test/rootfs:latest".to_string()),
        consumer: "qemu".to_string(),
        rootfs: Some(proto::RootfsConfig::default()),
        network: Vec::new(),
        devices: Vec::new(),
    }
}
