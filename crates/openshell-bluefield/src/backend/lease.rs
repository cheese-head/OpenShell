// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Lease storage for `BlueField` attachment state.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use openshell_core::proto::attachment::v1 as proto;
use prost::Message;

use crate::provider::{AttachmentProviderError, AttachmentProviderResult};

#[tonic::async_trait]
pub trait LeaseStore: std::fmt::Debug + Send + Sync + 'static {
    async fn put(&self, lease: proto::AttachmentLease) -> AttachmentProviderResult<()>;

    async fn remove(
        &self,
        attachment_id: &str,
    ) -> AttachmentProviderResult<Option<proto::AttachmentLease>>;

    async fn list(&self) -> AttachmentProviderResult<Vec<proto::AttachmentLease>>;
}

#[derive(Debug, Clone, Default)]
pub struct InMemoryLeaseStore {
    leases: Arc<Mutex<HashMap<String, proto::AttachmentLease>>>,
}

impl InMemoryLeaseStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[derive(Debug, Clone)]
pub struct FileLeaseStore {
    path: Arc<PathBuf>,
    lock: Arc<Mutex<()>>,
}

impl FileLeaseStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: Arc::new(path.into()),
            lock: Arc::new(Mutex::new(())),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[tonic::async_trait]
impl LeaseStore for FileLeaseStore {
    async fn put(&self, lease: proto::AttachmentLease) -> AttachmentProviderResult<()> {
        let _guard = self.lock_file()?;
        let mut leases = self.read_leases()?;
        if let Some(existing) = leases
            .iter_mut()
            .find(|stored| stored.attachment_id == lease.attachment_id)
        {
            *existing = lease;
        } else {
            leases.push(lease);
        }
        self.write_leases(&leases)
    }

    async fn remove(
        &self,
        attachment_id: &str,
    ) -> AttachmentProviderResult<Option<proto::AttachmentLease>> {
        let _guard = self.lock_file()?;
        let mut leases = self.read_leases()?;
        let Some(index) = leases
            .iter()
            .position(|lease| lease.attachment_id == attachment_id)
        else {
            return Ok(None);
        };
        let removed = leases.remove(index);
        self.write_leases(&leases)?;
        Ok(Some(removed))
    }

    async fn list(&self) -> AttachmentProviderResult<Vec<proto::AttachmentLease>> {
        let _guard = self.lock_file()?;
        self.read_leases()
    }
}

impl FileLeaseStore {
    fn lock_file(&self) -> AttachmentProviderResult<std::sync::MutexGuard<'_, ()>> {
        self.lock.lock().map_err(|err| {
            AttachmentProviderError::internal(format!("file lease store lock poisoned: {err}"))
        })
    }

    fn read_leases(&self) -> AttachmentProviderResult<Vec<proto::AttachmentLease>> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }

        let bytes = std::fs::read(self.path()).map_err(|err| {
            AttachmentProviderError::internal(format!(
                "read lease store '{}': {err}",
                self.path.display()
            ))
        })?;
        let mut leases = Vec::new();
        let mut remaining = bytes.as_slice();
        while !remaining.is_empty() {
            let lease =
                proto::AttachmentLease::decode_length_delimited(&mut remaining).map_err(|err| {
                    AttachmentProviderError::internal(format!(
                        "decode lease store '{}': {err}",
                        self.path.display()
                    ))
                })?;
            leases.push(lease);
        }
        Ok(leases)
    }

    fn write_leases(&self, leases: &[proto::AttachmentLease]) -> AttachmentProviderResult<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).map_err(|err| {
                AttachmentProviderError::internal(format!(
                    "create lease store directory '{}': {err}",
                    parent.display()
                ))
            })?;
        }

        let mut bytes = Vec::new();
        for lease in leases {
            lease.encode_length_delimited(&mut bytes).map_err(|err| {
                AttachmentProviderError::internal(format!(
                    "encode lease '{}': {err}",
                    lease.attachment_id
                ))
            })?;
        }

        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, bytes).map_err(|err| {
            AttachmentProviderError::internal(format!(
                "write lease store '{}': {err}",
                tmp.display()
            ))
        })?;
        std::fs::rename(&tmp, self.path()).map_err(|err| {
            AttachmentProviderError::internal(format!(
                "replace lease store '{}' with '{}': {err}",
                self.path.display(),
                tmp.display()
            ))
        })
    }
}

#[tonic::async_trait]
impl LeaseStore for InMemoryLeaseStore {
    async fn put(&self, lease: proto::AttachmentLease) -> AttachmentProviderResult<()> {
        let mut leases = self.lock_leases()?;
        leases.insert(lease.attachment_id.clone(), lease);
        Ok(())
    }

    async fn remove(
        &self,
        attachment_id: &str,
    ) -> AttachmentProviderResult<Option<proto::AttachmentLease>> {
        let mut leases = self.lock_leases()?;
        Ok(leases.remove(attachment_id))
    }

    async fn list(&self) -> AttachmentProviderResult<Vec<proto::AttachmentLease>> {
        let leases = self.lock_leases()?;
        Ok(leases.values().cloned().collect())
    }
}

impl InMemoryLeaseStore {
    fn lock_leases(
        &self,
    ) -> AttachmentProviderResult<std::sync::MutexGuard<'_, HashMap<String, proto::AttachmentLease>>>
    {
        self.leases.lock().map_err(|err| {
            AttachmentProviderError::internal(format!("in-memory lease store poisoned: {err}"))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn file_lease_store_persists_leases_across_instances() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("leases.pb");
        let store = FileLeaseStore::new(&path);

        store.put(lease("bf-sandbox-1")).await.unwrap();

        let reopened = FileLeaseStore::new(&path);
        assert_eq!(reopened.list().await.unwrap(), vec![lease("bf-sandbox-1")]);
    }

    #[tokio::test]
    async fn file_lease_store_replaces_and_removes_leases() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("leases.pb");
        let store = FileLeaseStore::new(&path);
        let mut updated = lease("bf-sandbox-1");
        updated.generation = 2;

        store.put(lease("bf-sandbox-1")).await.unwrap();
        store.put(updated.clone()).await.unwrap();
        assert_eq!(store.list().await.unwrap(), vec![updated.clone()]);

        assert_eq!(store.remove("bf-sandbox-1").await.unwrap(), Some(updated));
        assert!(store.list().await.unwrap().is_empty());
    }

    fn lease(attachment_id: &str) -> proto::AttachmentLease {
        proto::AttachmentLease {
            attachment_id: attachment_id.to_string(),
            generation: 1,
            plan: Some(proto::AttachmentPlan::default()),
            metadata: HashMap::new(),
        }
    }
}
