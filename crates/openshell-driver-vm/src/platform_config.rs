// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::runtime::VmBackend;
use openshell_core::proto::compute::v1::{
    DriverSandbox as Sandbox, DriverSandboxTemplate as SandboxTemplate,
};
use tonic::Status;

const VM_RUNTIME_CLASS_LIBKRUN: &str = "libkrun";
const VM_RUNTIME_CLASS_QEMU: &str = "qemu";
const PLATFORM_CONFIG_RUNTIME_CLASS_NAME: &str = "runtime_class_name";

#[allow(clippy::result_large_err)]
pub fn sandbox_launch_backend(sandbox: &Sandbox) -> Result<VmBackend, Status> {
    let spec = sandbox
        .spec
        .as_ref()
        .ok_or_else(|| Status::invalid_argument("sandbox spec is required"))?;
    let requested_backend = sandbox_requested_vm_backend(sandbox)?;

    if spec.gpu {
        if requested_backend == Some(VmBackend::Libkrun) {
            return Err(Status::failed_precondition(
                "GPU sandboxes require template.platform_config.runtime_class_name=qemu or an empty runtime_class_name",
            ));
        }
        return Ok(VmBackend::Qemu);
    }

    Ok(requested_backend.unwrap_or(VmBackend::Libkrun))
}

#[allow(clippy::result_large_err)]
fn sandbox_requested_vm_backend(sandbox: &Sandbox) -> Result<Option<VmBackend>, Status> {
    let Some(template) = sandbox
        .spec
        .as_ref()
        .and_then(|spec| spec.template.as_ref())
    else {
        return Ok(None);
    };

    template_requested_vm_backend(template)
}

#[allow(clippy::result_large_err)]
fn template_requested_vm_backend(template: &SandboxTemplate) -> Result<Option<VmBackend>, Status> {
    let Some(runtime_class_name) = template_runtime_class_name(template)? else {
        return Ok(None);
    };

    match runtime_class_name {
        VM_RUNTIME_CLASS_LIBKRUN => Ok(Some(VmBackend::Libkrun)),
        VM_RUNTIME_CLASS_QEMU => Ok(Some(VmBackend::Qemu)),
        other => Err(Status::failed_precondition(format!(
            "unsupported vm template.platform_config.runtime_class_name '{other}'; supported values are '{VM_RUNTIME_CLASS_LIBKRUN}' and '{VM_RUNTIME_CLASS_QEMU}'"
        ))),
    }
}

#[allow(clippy::result_large_err)]
fn template_runtime_class_name(template: &SandboxTemplate) -> Result<Option<&str>, Status> {
    let Some(platform_config) = template.platform_config.as_ref() else {
        return Ok(None);
    };

    for field in platform_config.fields.keys() {
        if field != PLATFORM_CONFIG_RUNTIME_CLASS_NAME {
            return Err(Status::failed_precondition(format!(
                "vm sandboxes only support template.platform_config.runtime_class_name; unsupported field '{field}'"
            )));
        }
    }

    let Some(value) = platform_config
        .fields
        .get(PLATFORM_CONFIG_RUNTIME_CLASS_NAME)
    else {
        return Ok(None);
    };
    let Some(kind) = value.kind.as_ref() else {
        return Err(Status::invalid_argument(
            "template.platform_config.runtime_class_name must be a string",
        ));
    };
    let prost_types::value::Kind::StringValue(runtime_class_name) = kind else {
        return Err(Status::invalid_argument(
            "template.platform_config.runtime_class_name must be a string",
        ));
    };
    let runtime_class_name = runtime_class_name.trim();
    if runtime_class_name.is_empty() {
        Ok(None)
    } else {
        Ok(Some(runtime_class_name))
    }
}
