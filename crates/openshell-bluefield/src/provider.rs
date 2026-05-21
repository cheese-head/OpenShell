// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! gRPC adapter for `OpenShell`'s generic attachment-provider contract.
//!
//! The VM driver talks to `openshell.attachment.v1.AttachmentProvider`.
//! This module implements that generated tonic service and delegates the
//! `BlueField`-specific work to an [`AttachmentProviderBackend`].

use openshell_core::proto::attachment::v1 as proto;
use thiserror::Error;
use tonic::{Code, Request, Response, Status};

pub use proto::attachment_provider_server::AttachmentProviderServer;

pub const CAPABILITY_NETWORK_OVS: &str = "network:ovs";
pub const CAPABILITY_NETWORK_VDPA: &str = "network:vdpa";
pub const CAPABILITY_NETWORK_VFIO_PCI: &str = "network:vfio-pci";
pub const CAPABILITY_STORAGE_PROVIDER_PROVISIONED: &str = "storage:provider-provisioned";

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{message}")]
pub struct AttachmentProviderError {
    code: Code,
    message: String,
}

impl AttachmentProviderError {
    pub fn invalid_argument(message: impl Into<String>) -> Self {
        Self::new(Code::InvalidArgument, message)
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(Code::NotFound, message)
    }

    pub fn failed_precondition(message: impl Into<String>) -> Self {
        Self::new(Code::FailedPrecondition, message)
    }

    pub fn unavailable(message: impl Into<String>) -> Self {
        Self::new(Code::Unavailable, message)
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(Code::Internal, message)
    }

    pub fn code(&self) -> Code {
        self.code
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    fn new(code: Code, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl From<AttachmentProviderError> for Status {
    fn from(value: AttachmentProviderError) -> Self {
        Self::new(value.code, value.message)
    }
}

pub type AttachmentProviderResult<T> = Result<T, AttachmentProviderError>;

#[tonic::async_trait]
pub trait AttachmentProviderBackend: std::fmt::Debug + Send + Sync + 'static {
    async fn health(&self) -> AttachmentProviderResult<proto::HealthResponse>;

    async fn attach(
        &self,
        request: proto::AttachRequest,
    ) -> AttachmentProviderResult<proto::AttachmentLease>;

    async fn detach(&self, lease: proto::AttachmentLease) -> AttachmentProviderResult<()>;

    async fn list(&self) -> AttachmentProviderResult<Vec<proto::AttachmentLease>>;

    async fn reconcile(
        &self,
        lease: proto::AttachmentLease,
    ) -> AttachmentProviderResult<proto::ReconcileResponse>;
}

#[derive(Debug, Clone)]
pub struct AttachmentProviderService<B> {
    backend: B,
}

impl<B> AttachmentProviderService<B>
where
    B: AttachmentProviderBackend,
{
    pub fn new(backend: B) -> Self {
        Self { backend }
    }

    pub fn backend(&self) -> &B {
        &self.backend
    }

    pub fn into_backend(self) -> B {
        self.backend
    }

    pub fn into_grpc_server(self) -> AttachmentProviderServer<Self> {
        AttachmentProviderServer::new(self)
    }
}

#[tonic::async_trait]
impl<B> proto::attachment_provider_server::AttachmentProvider for AttachmentProviderService<B>
where
    B: AttachmentProviderBackend,
{
    async fn health(
        &self,
        _request: Request<proto::HealthRequest>,
    ) -> Result<Response<proto::HealthResponse>, Status> {
        Ok(Response::new(self.backend.health().await?))
    }

    async fn attach(
        &self,
        request: Request<proto::AttachRequest>,
    ) -> Result<Response<proto::AttachResponse>, Status> {
        let request = request.into_inner();
        validate_attach_request(&request)?;
        let lease = self.backend.attach(request).await?;
        validate_lease(&lease)?;
        Ok(Response::new(proto::AttachResponse { lease: Some(lease) }))
    }

    async fn detach(
        &self,
        request: Request<proto::DetachRequest>,
    ) -> Result<Response<proto::DetachResponse>, Status> {
        let lease = required_lease(request.into_inner().lease, "detach")?;
        self.backend.detach(lease).await?;
        Ok(Response::new(proto::DetachResponse {}))
    }

    async fn list(
        &self,
        _request: Request<proto::ListRequest>,
    ) -> Result<Response<proto::ListResponse>, Status> {
        let leases = self.backend.list().await?;
        for lease in &leases {
            validate_lease(lease)?;
        }
        Ok(Response::new(proto::ListResponse { leases }))
    }

    async fn reconcile(
        &self,
        request: Request<proto::ReconcileRequest>,
    ) -> Result<Response<proto::ReconcileResponse>, Status> {
        let lease = required_lease(request.into_inner().lease, "reconcile")?;
        let response = self.backend.reconcile(lease).await?;
        Ok(Response::new(normalize_reconcile_response(response)))
    }
}

fn validate_attach_request(request: &proto::AttachRequest) -> AttachmentProviderResult<()> {
    validate_required("sandbox_id", &request.sandbox_id)?;
    validate_required("sandbox_name", &request.sandbox_name)?;
    if request.consumer != "qemu" {
        return Err(AttachmentProviderError::invalid_argument(format!(
            "BlueField attachment provider supports consumer 'qemu', got '{}'",
            request.consumer
        )));
    }
    if request.rootfs.is_none() {
        return Err(AttachmentProviderError::invalid_argument(
            "attach request missing rootfs",
        ));
    }
    Ok(())
}

fn required_lease(
    lease: Option<proto::AttachmentLease>,
    operation: &str,
) -> AttachmentProviderResult<proto::AttachmentLease> {
    let lease = lease.ok_or_else(|| {
        AttachmentProviderError::invalid_argument(format!("{operation} request missing lease"))
    })?;
    validate_lease(&lease)?;
    Ok(lease)
}

fn validate_lease(lease: &proto::AttachmentLease) -> AttachmentProviderResult<()> {
    validate_required("attachment_id", &lease.attachment_id)
}

fn validate_required(field: &str, value: &str) -> AttachmentProviderResult<()> {
    if value.trim().is_empty() {
        return Err(AttachmentProviderError::invalid_argument(format!(
            "{field} is required"
        )));
    }
    Ok(())
}

fn normalize_reconcile_response(response: proto::ReconcileResponse) -> proto::ReconcileResponse {
    if response.outcome == proto::ReconcileOutcome::Unspecified as i32 {
        proto::ReconcileResponse {
            outcome: proto::ReconcileOutcome::Continue as i32,
            reason: response.reason,
        }
    } else {
        response
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};

    use tokio::net::TcpListener;
    use tokio_stream::wrappers::TcpListenerStream;
    use tonic::transport::Server;

    use super::*;
    use crate::provider::proto::attachment_provider_client::AttachmentProviderClient;
    use crate::provider::proto::attachment_provider_server::AttachmentProvider as _;

    #[derive(Debug, Default)]
    struct RecordingBackend {
        attached: Mutex<Vec<String>>,
        detached: Mutex<Vec<String>>,
    }

    #[tonic::async_trait]
    impl AttachmentProviderBackend for Arc<RecordingBackend> {
        async fn health(&self) -> AttachmentProviderResult<proto::HealthResponse> {
            Ok(proto::HealthResponse {
                healthy: true,
                message: "ready".to_string(),
                capabilities: vec![
                    CAPABILITY_NETWORK_OVS.to_string(),
                    CAPABILITY_NETWORK_VFIO_PCI.to_string(),
                ],
            })
        }

        async fn attach(
            &self,
            request: proto::AttachRequest,
        ) -> AttachmentProviderResult<proto::AttachmentLease> {
            self.attached
                .lock()
                .unwrap()
                .push(request.sandbox_id.clone());
            Ok(proto::AttachmentLease {
                attachment_id: format!("bf-{}", request.sandbox_id),
                generation: 1,
                plan: Some(proto::AttachmentPlan {
                    replace_network: true,
                    ..Default::default()
                }),
                metadata: std::iter::once(("sandbox_id".to_string(), request.sandbox_id)).collect(),
            })
        }

        async fn detach(&self, lease: proto::AttachmentLease) -> AttachmentProviderResult<()> {
            self.detached.lock().unwrap().push(lease.attachment_id);
            Ok(())
        }

        async fn list(&self) -> AttachmentProviderResult<Vec<proto::AttachmentLease>> {
            Ok(self
                .attached
                .lock()
                .unwrap()
                .iter()
                .map(|sandbox_id| proto::AttachmentLease {
                    attachment_id: format!("bf-{sandbox_id}"),
                    generation: 1,
                    plan: Some(proto::AttachmentPlan::default()),
                    metadata: HashMap::default(),
                })
                .collect())
        }

        async fn reconcile(
            &self,
            _lease: proto::AttachmentLease,
        ) -> AttachmentProviderResult<proto::ReconcileResponse> {
            Ok(proto::ReconcileResponse {
                outcome: proto::ReconcileOutcome::Unspecified as i32,
                reason: String::new(),
            })
        }
    }

    #[tokio::test]
    async fn service_rejects_non_qemu_consumer_before_backend_attach() {
        let backend = Arc::new(RecordingBackend::default());
        let service = AttachmentProviderService::new(backend.clone());

        let error = service
            .attach(Request::new(proto::AttachRequest {
                consumer: "libkrun".to_string(),
                ..attach_request("sandbox-1")
            }))
            .await
            .unwrap_err();

        assert_eq!(error.code(), Code::InvalidArgument);
        assert!(backend.attached.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn service_delegates_attach_detach_and_reconcile() {
        let backend = Arc::new(RecordingBackend::default());
        let service = AttachmentProviderService::new(backend.clone());

        let lease = service
            .attach(Request::new(attach_request("sandbox-1")))
            .await
            .unwrap()
            .into_inner()
            .lease
            .unwrap();
        assert_eq!(lease.attachment_id, "bf-sandbox-1");

        service
            .detach(Request::new(proto::DetachRequest {
                lease: Some(lease.clone()),
            }))
            .await
            .unwrap();
        assert_eq!(
            backend.detached.lock().unwrap().as_slice(),
            ["bf-sandbox-1"]
        );

        let reconcile = service
            .reconcile(Request::new(proto::ReconcileRequest { lease: Some(lease) }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(reconcile.outcome, proto::ReconcileOutcome::Continue as i32);
    }

    #[tokio::test]
    async fn generated_grpc_client_can_call_bluefield_service() {
        let backend = Arc::new(RecordingBackend::default());
        let address = spawn_service(AttachmentProviderService::new(backend.clone())).await;
        let mut client = AttachmentProviderClient::connect(format!("http://{address}"))
            .await
            .unwrap();

        let health = client
            .health(proto::HealthRequest {})
            .await
            .unwrap()
            .into_inner();
        assert!(health.healthy);
        assert_eq!(health.capabilities[0], CAPABILITY_NETWORK_OVS);

        let lease = client
            .attach(attach_request("sandbox-2"))
            .await
            .unwrap()
            .into_inner()
            .lease
            .unwrap();

        assert_eq!(lease.attachment_id, "bf-sandbox-2");
        assert_eq!(backend.attached.lock().unwrap().as_slice(), ["sandbox-2"]);
    }

    async fn spawn_service(
        service: AttachmentProviderService<Arc<RecordingBackend>>,
    ) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            Server::builder()
                .add_service(service.into_grpc_server())
                .serve_with_incoming(TcpListenerStream::new(listener))
                .await
                .unwrap();
        });
        address
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
}
