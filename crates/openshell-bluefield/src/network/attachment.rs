// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Network attachment state derived from a leased `BlueField` VF.

use crate::backend::BlueFieldVfSlot;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlueFieldNetworkAttachment {
    pub slot_id: String,
    pub host_bdf: String,
    pub representor: Option<String>,
    pub mac: Option<String>,
}

impl BlueFieldNetworkAttachment {
    pub fn from_vf_slot(slot: &BlueFieldVfSlot) -> Self {
        Self {
            slot_id: slot.id.clone(),
            host_bdf: slot.host_bdf.clone(),
            representor: slot.representor.clone(),
            mac: slot.mac.clone(),
        }
    }
}
