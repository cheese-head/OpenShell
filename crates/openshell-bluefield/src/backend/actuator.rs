// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Hardware actuation for leased `BlueField` attachments.

use openshell_core::proto::attachment::v1 as proto;

use crate::backend::inventory::{METADATA_VF_HOST_BDF, METADATA_VF_REPRESENTOR};
use crate::command::{CommandRunner, SystemCommandRunner};
use crate::network::{
    Action, FlowKind, FlowOwnerPolicy, FlowProgrammer, FlowSpec, Match, OPENSHELL_TABLE_ADMISSION,
    OPENSHELL_TABLE_FORWARD, OvsExecutionError, OvsFlowProgrammer, OvsOfctlExecutor,
    SandboxFlowPlan, flow_id_from_str,
};
use crate::provider::{AttachmentProviderError, AttachmentProviderResult};
use crate::vfio::{SysfsVfioDeviceManager, VfioDeviceId, VfioDeviceManager};

pub trait AttachmentActuator: std::fmt::Debug + Send + Sync + 'static {
    fn prepare_attach(&self, lease: &proto::AttachmentLease) -> AttachmentProviderResult<()>;

    fn cleanup_detach(&self, lease: &proto::AttachmentLease) -> AttachmentProviderResult<()>;

    fn reconcile_lease(&self, lease: &proto::AttachmentLease) -> AttachmentProviderResult<()>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct NoopAttachmentActuator;

impl AttachmentActuator for NoopAttachmentActuator {
    fn prepare_attach(&self, _lease: &proto::AttachmentLease) -> AttachmentProviderResult<()> {
        Ok(())
    }

    fn cleanup_detach(&self, _lease: &proto::AttachmentLease) -> AttachmentProviderResult<()> {
        Ok(())
    }

    fn reconcile_lease(&self, _lease: &proto::AttachmentLease) -> AttachmentProviderResult<()> {
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct BlueFieldHardwareActuator<V = SysfsVfioDeviceManager, R = SystemCommandRunner> {
    vfio: V,
    vfio_enabled: bool,
    flow_programmer: OvsFlowProgrammer,
    ovs: OvsOfctlExecutor<R>,
    flow_policy: FlowOwnerPolicy,
}

impl BlueFieldHardwareActuator<SysfsVfioDeviceManager, SystemCommandRunner> {
    pub fn system(flow_policy: FlowOwnerPolicy) -> Self {
        Self::new(
            SysfsVfioDeviceManager::system(),
            OvsOfctlExecutor::system(),
            flow_policy,
        )
    }
}

impl<V, R> BlueFieldHardwareActuator<V, R>
where
    V: VfioDeviceManager,
    R: CommandRunner,
{
    pub fn new(vfio: V, ovs: OvsOfctlExecutor<R>, flow_policy: FlowOwnerPolicy) -> Self {
        Self {
            vfio,
            vfio_enabled: true,
            flow_programmer: OvsFlowProgrammer,
            ovs,
            flow_policy,
        }
    }

    #[must_use]
    pub fn with_vfio_enabled(mut self, vfio_enabled: bool) -> Self {
        self.vfio_enabled = vfio_enabled;
        self
    }

    fn prepare_vf(&self, lease: &proto::AttachmentLease) -> AttachmentProviderResult<()> {
        if !self.vfio_enabled {
            return Ok(());
        }
        let Some(bdf) = lease.metadata.get(METADATA_VF_HOST_BDF) else {
            return Ok(());
        };
        self.vfio
            .prepare_for_passthrough(&VfioDeviceId::new(bdf.clone()))
            .map(|_| ())
            .map_err(|err| AttachmentProviderError::failed_precondition(err.to_string()))
    }

    fn release_vf(&self, lease: &proto::AttachmentLease) -> AttachmentProviderResult<()> {
        if !self.vfio_enabled {
            return Ok(());
        }
        let Some(bdf) = lease.metadata.get(METADATA_VF_HOST_BDF) else {
            return Ok(());
        };
        self.vfio
            .release_from_passthrough(&VfioDeviceId::new(bdf.clone()))
            .map_err(|err| AttachmentProviderError::failed_precondition(err.to_string()))
    }

    fn install_flows(&self, lease: &proto::AttachmentLease) -> AttachmentProviderResult<()> {
        let Some(representor) = lease.metadata.get(METADATA_VF_REPRESENTOR) else {
            return Ok(());
        };
        let plan = self.endpoint_flow_plan(lease, representor)?;
        let commands = self
            .flow_programmer
            .install_commands(&plan)
            .map_err(|err| AttachmentProviderError::internal(err.to_string()))?;
        self.ovs
            .execute_all(&commands)
            .map_err(ovs_execution_error)?;
        Ok(())
    }

    fn delete_flows(&self, lease: &proto::AttachmentLease) -> AttachmentProviderResult<()> {
        if !lease.metadata.contains_key(METADATA_VF_REPRESENTOR) {
            return Ok(());
        }
        let flow_id = flow_id_from_str(&lease.attachment_id);
        let cookie = self.flow_policy.cookie(FlowKind::Endpoint, flow_id);
        let command = self
            .flow_programmer
            .delete_cookie_command(&self.flow_policy.bridge, cookie)
            .map_err(|err| AttachmentProviderError::internal(err.to_string()))?;
        self.ovs.execute(&command).map_err(ovs_execution_error)
    }

    fn endpoint_flow_plan(
        &self,
        lease: &proto::AttachmentLease,
        representor: &str,
    ) -> AttachmentProviderResult<SandboxFlowPlan> {
        let flow_id = flow_id_from_str(&lease.attachment_id);
        let flow = self
            .flow_policy
            .stamp(
                &FlowSpec::new(FlowKind::Endpoint, flow_id, OPENSHELL_TABLE_ADMISSION, 100)
                    .add_match(Match::InPort(representor.to_string()))
                    .add_action(Action::GotoTable(OPENSHELL_TABLE_FORWARD)),
            )
            .map_err(|err| AttachmentProviderError::internal(err.to_string()))?;
        Ok(SandboxFlowPlan {
            sandbox_id: lease
                .metadata
                .get("sandbox_id")
                .cloned()
                .unwrap_or_else(|| lease.attachment_id.clone()),
            bridge: self.flow_policy.bridge.clone(),
            flows: vec![flow],
        })
    }
}

impl<V, R> AttachmentActuator for BlueFieldHardwareActuator<V, R>
where
    V: VfioDeviceManager,
    R: CommandRunner,
{
    fn prepare_attach(&self, lease: &proto::AttachmentLease) -> AttachmentProviderResult<()> {
        self.prepare_vf(lease)?;
        self.install_flows(lease)
    }

    fn cleanup_detach(&self, lease: &proto::AttachmentLease) -> AttachmentProviderResult<()> {
        self.delete_flows(lease)?;
        self.release_vf(lease)
    }

    fn reconcile_lease(&self, lease: &proto::AttachmentLease) -> AttachmentProviderResult<()> {
        self.prepare_attach(lease)
    }
}

fn ovs_execution_error(err: OvsExecutionError) -> AttachmentProviderError {
    AttachmentProviderError::unavailable(format!("OVS command failed: {err}"))
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use crate::command::{CommandError, CommandResult, CommandSpec};
    use crate::vfio::{PreparedVfioDevice, VfioDeviceError};

    use super::*;

    #[derive(Debug, Clone, Default)]
    struct RecordingVfio {
        prepared: Arc<Mutex<Vec<String>>>,
        released: Arc<Mutex<Vec<String>>>,
    }

    impl VfioDeviceManager for RecordingVfio {
        fn prepare_for_passthrough(
            &self,
            id: &VfioDeviceId,
        ) -> Result<PreparedVfioDevice, VfioDeviceError> {
            self.prepared.lock().unwrap().push(id.bdf.clone());
            Ok(PreparedVfioDevice {
                id: id.clone(),
                iommu_group: Some("7".to_string()),
            })
        }

        fn release_from_passthrough(&self, id: &VfioDeviceId) -> Result<(), VfioDeviceError> {
            self.released.lock().unwrap().push(id.bdf.clone());
            Ok(())
        }
    }

    #[derive(Debug, Clone, Default)]
    struct RecordingRunner {
        commands: Arc<Mutex<Vec<CommandSpec>>>,
    }

    impl CommandRunner for RecordingRunner {
        fn run(&self, spec: &CommandSpec) -> Result<CommandResult, CommandError> {
            self.commands.lock().unwrap().push(spec.clone());
            Ok(CommandResult {
                stdout: String::new(),
                stderr: String::new(),
            })
        }
    }

    #[test]
    fn hardware_actuator_prepares_vf_and_installs_flow() {
        let vfio = RecordingVfio::default();
        let runner = RecordingRunner::default();
        let prepared = vfio.prepared.clone();
        let commands = runner.commands.clone();
        let actuator = BlueFieldHardwareActuator::new(
            vfio,
            OvsOfctlExecutor::new(runner),
            FlowOwnerPolicy::default(),
        );

        actuator.prepare_attach(&lease()).unwrap();

        assert_eq!(prepared.lock().unwrap().as_slice(), ["0000:03:00.2"]);
        let commands = commands.lock().unwrap();
        assert_eq!(commands.len(), 1);
        assert_eq!(commands[0].program, "ovs-ofctl");
        assert_eq!(commands[0].args[2], "add-flow");
        assert!(commands[0].args[4].contains("in_port=pf0vf0"));
    }

    #[test]
    fn hardware_actuator_deletes_flow_and_releases_vf() {
        let vfio = RecordingVfio::default();
        let runner = RecordingRunner::default();
        let released = vfio.released.clone();
        let commands = runner.commands.clone();
        let actuator = BlueFieldHardwareActuator::new(
            vfio,
            OvsOfctlExecutor::new(runner),
            FlowOwnerPolicy::default(),
        );

        actuator.cleanup_detach(&lease()).unwrap();

        let commands = commands.lock().unwrap();
        assert_eq!(commands.len(), 1);
        assert_eq!(commands[0].args[2], "del-flows");
        assert_eq!(released.lock().unwrap().as_slice(), ["0000:03:00.2"]);
    }

    #[test]
    fn prebound_actuator_skips_vfio_and_still_programs_ovs() {
        let vfio = RecordingVfio::default();
        let runner = RecordingRunner::default();
        let prepared = vfio.prepared.clone();
        let released = vfio.released.clone();
        let commands = runner.commands.clone();
        let actuator = BlueFieldHardwareActuator::new(
            vfio,
            OvsOfctlExecutor::new(runner),
            FlowOwnerPolicy::default(),
        )
        .with_vfio_enabled(false);

        actuator.prepare_attach(&lease()).unwrap();
        actuator.cleanup_detach(&lease()).unwrap();

        assert!(prepared.lock().unwrap().is_empty());
        assert!(released.lock().unwrap().is_empty());
        let commands = commands.lock().unwrap();
        assert_eq!(commands.len(), 2);
        assert_eq!(commands[0].args[2], "add-flow");
        assert_eq!(commands[1].args[2], "del-flows");
    }

    fn lease() -> proto::AttachmentLease {
        proto::AttachmentLease {
            attachment_id: "bf-sandbox-1".to_string(),
            generation: 1,
            plan: Some(proto::AttachmentPlan::default()),
            metadata: [
                ("sandbox_id".to_string(), "sandbox-1".to_string()),
                (METADATA_VF_HOST_BDF.to_string(), "0000:03:00.2".to_string()),
                (METADATA_VF_REPRESENTOR.to_string(), "pf0vf0".to_string()),
            ]
            .into_iter()
            .collect(),
        }
    }
}
