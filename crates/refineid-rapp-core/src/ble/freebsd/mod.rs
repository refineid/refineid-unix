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

//! The BLE transport on FreeBSD's netgraph Bluetooth stack: a raw HCI
//! socket scans, and an L2CAP socket on the fixed ATT channel carries one
//! LE connection's PDUs, one per `send` and `recv`.
//!
//! Both work for an unprivileged user once root has loaded `ng_l2cap` and
//! `ng_btsocket`, started the adapter, and enabled LE (observed on
//! FreeBSD 15.1; `doc/install-freebsd.md` lists the commands): the
//! kernel's raw HCI filter lets any user send LE Set Scan Parameters and
//! LE Set Scan Enable (`ng_btsocket_hci_raw.c`), and connecting an L2CAP
//! socket to the ATT channel makes the kernel create the LE connection.

mod sys;

use std::io;
use std::time::{Duration, Instant};

use refineid_rapp::RoutingPreamble;

use super::advertising::{LeAddressType, RappAdvertiser};
use super::gatt::{AttBearer, BearerError};
use super::hci::{
    self, EVENT_COMMAND_COMPLETE, EVENT_COMMAND_STATUS, EVENT_LE_META, HCI_EVENT_FRAME_LIMIT,
    HCI_EVENT_PACKET, HciChannel, ScanError,
};
use super::transport::{BleFrameTransport, BleOpenError};

/// The HCI node of the first USB Bluetooth adapter (ng_ubt(4)).
const HCI_NODE: &str = "ubt0hci";
/// `NG_L2CAP_MTU_DEFAULT`, the L2CAP incoming MTU, which bounds every
/// PDU the kernel delivers (`ng_l2cap.h`).
const L2CAP_MTU_DEFAULT: usize = 672;
/// How long an LE connection may take: as long as one TCP connect of the
/// stream tier. The phone answers the connection request within a
/// connection interval of its next advertisement.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// How long the GATT setup may take: about ten transactions, each a few
/// connection intervals; an engineering bound, not a specified one.
const SETUP_TIMEOUT: Duration = Duration::from_secs(10);

/// A filter bit of `hccontrol`: the code minus one (`bit_set(mask,
/// CODE - 1)`).
const fn filter_bit(code: u8) -> usize {
    code as usize - 1
}

/// The raw HCI socket of the scan.
#[derive(Debug)]
struct HciSocket(sys::Socket);

impl HciChannel for HciSocket {
    fn send(&mut self, frame: &[u8]) -> Result<(), BearerError> {
        self.0.send(frame).map_err(|_| BearerError::Failed)
    }

    fn receive(&mut self, deadline: Instant) -> Result<Vec<u8>, BearerError> {
        let mut buffer = [0u8; HCI_EVENT_FRAME_LIMIT];
        let timeout = deadline.saturating_duration_since(Instant::now());
        match self.0.receive(&mut buffer, timeout) {
            Ok(None) => Err(BearerError::TimedOut),
            Ok(Some(0)) => Err(BearerError::Closed),
            Ok(Some(length)) => Ok(buffer[..length].to_vec()),
            Err(_) => Err(BearerError::Failed),
        }
    }
}

/// Scans for `window` and returns the RAPP advertisers heard, strongest
/// first.
///
/// # Errors
/// [`ScanError`] when the adapter cannot be opened, refuses the scan, or
/// fails.
pub fn scan(window: Duration) -> Result<Vec<RappAdvertiser>, ScanError> {
    let socket = sys::open_hci(
        HCI_NODE,
        &[filter_bit(HCI_EVENT_PACKET)],
        &[
            filter_bit(EVENT_COMMAND_COMPLETE),
            filter_bit(EVENT_COMMAND_STATUS),
            filter_bit(EVENT_LE_META),
        ],
    )
    .map_err(|_| ScanError::Channel(BearerError::Failed))?;
    hci::scan(&mut HciSocket(socket), window)
}

/// The ATT channel of one LE connection.
#[derive(Debug)]
pub struct AttSocket(sys::Socket);

impl AttBearer for AttSocket {
    fn send(&mut self, pdu: &[u8]) -> Result<(), BearerError> {
        self.0.send(pdu).map_err(|error| closed_or_failed(&error))
    }

    fn receive(&mut self, deadline: Instant) -> Result<Vec<u8>, BearerError> {
        let mut buffer = [0u8; L2CAP_MTU_DEFAULT];
        let timeout = deadline.saturating_duration_since(Instant::now());
        match self.0.receive(&mut buffer, timeout) {
            Ok(None) => Err(BearerError::TimedOut),
            Ok(Some(0)) => Err(BearerError::Closed),
            Ok(Some(length)) => Ok(buffer[..length].to_vec()),
            Err(error) => Err(closed_or_failed(&error)),
        }
    }
}

/// A peer that dropped the link is a close; anything else a failure.
fn closed_or_failed(error: &io::Error) -> BearerError {
    match error.kind() {
        io::ErrorKind::ConnectionReset
        | io::ErrorKind::NotConnected
        | io::ErrorKind::BrokenPipe => BearerError::Closed,
        _ => BearerError::Failed,
    }
}

/// Why a BLE dial reached no session phase.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BleDialError {
    /// The LE connection was not made in time.
    ConnectTimedOut,
    /// The LE connection failed.
    ConnectFailed,
    /// The GATT setup or the routing preamble failed.
    Open(BleOpenError),
}

/// Connects to `advertiser`, sets up the RAPP channel and sends
/// `preamble`.
///
/// # Errors
/// [`BleDialError`] for every failure; the connection drops with it.
pub fn dial(
    advertiser: &RappAdvertiser,
    preamble: &RoutingPreamble,
    receive_deadline: Duration,
) -> Result<BleFrameTransport<AttSocket>, BleDialError> {
    let random = advertiser.address_type() == LeAddressType::Random;
    let socket = sys::connect_att(advertiser.address().octets(), random, CONNECT_TIMEOUT).map_err(
        |error| match error.kind() {
            io::ErrorKind::TimedOut => BleDialError::ConnectTimedOut,
            _ => BleDialError::ConnectFailed,
        },
    )?;
    BleFrameTransport::open(
        AttSocket(socket),
        preamble,
        receive_deadline,
        Instant::now() + SETUP_TIMEOUT,
    )
    .map_err(BleDialError::Open)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    /// How long the smoke scan listens.
    const SMOKE_WINDOW: Duration = Duration::from_secs(3);

    /// Scans the adapter and prints only how many RAPP advertisers it
    /// heard; needs the root setup of `doc/install-freebsd.md` and a
    /// phone nearby. Never prints an address.
    #[test]
    #[ignore = "needs a Bluetooth adapter"]
    fn smoke_scan_counts_rapp_advertisers() {
        match super::scan(SMOKE_WINDOW) {
            Ok(heard) => println!("rapp advertisers heard: {}", heard.len()),
            Err(error) => println!("scan failed: {error:?}"),
        }
    }
}
