// Copyright 2026 Petri Koistinen
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied. See the License for the specific language governing
// permissions and limitations under the License.

//! The BLE transport profile `fi.refineid.rapp.ble` for sessions (RAPP
//! v26.11.2 sections 2.2, 5.1 to 5.3; hierarchy specification section
//! 3.3): the requester is the GATT client and the phone the GATT server.
//!
//! Everything but `freebsd` (FreeBSD only) is platform-neutral and runs on synthetic
//! bytes: [`att`] encodes and decodes the ATT PDUs, [`gatt`] runs the
//! connection setup of section 5.2 over an [`gatt::AttBearer`], [`hci`]
//! drives a bounded LE scan over an [`hci::HciChannel`], [`advertising`]
//! reads the advertising reports, and [`transport`] carries RAPP frames
//! as SAR messages (section 5.3). Pairing never runs over BLE: both
//! phone applications refuse a pairing preamble there.

pub mod advertising;
pub mod att;
#[cfg(target_os = "freebsd")]
pub mod freebsd;
pub mod gatt;
pub mod hci;
pub mod transport;
