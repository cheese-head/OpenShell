// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Backend boundary for neutral `BlueField` flow programs.

use core::fmt;

use crate::program::{FlowHandle, FlowProgram};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlowBackendError {
    Unimplemented(String),
    Unsupported(String),
    Apply(String),
    Remove(String),
}

impl FlowBackendError {
    #[must_use]
    pub fn unimplemented(message: impl Into<String>) -> Self {
        Self::Unimplemented(message.into())
    }

    #[must_use]
    pub fn unsupported(message: impl Into<String>) -> Self {
        Self::Unsupported(message.into())
    }
}

impl fmt::Display for FlowBackendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unimplemented(message) => write!(f, "flow backend unimplemented: {message}"),
            Self::Unsupported(message) => write!(f, "flow program unsupported: {message}"),
            Self::Apply(message) => write!(f, "flow backend apply failed: {message}"),
            Self::Remove(message) => write!(f, "flow backend remove failed: {message}"),
        }
    }
}

impl std::error::Error for FlowBackendError {}

pub type FlowBackendResult<T> = Result<T, FlowBackendError>;

/// Programs a backend from the neutral [`FlowProgram`] IR.
pub trait FlowBackend: fmt::Debug + Send + Sync {
    fn apply(&self, program: &FlowProgram) -> FlowBackendResult<()>;
    fn remove(&self, flows: &[FlowHandle]) -> FlowBackendResult<()>;
}
