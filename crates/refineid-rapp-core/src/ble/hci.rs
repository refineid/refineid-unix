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

//! A bounded LE scan for RAPP advertisers over raw HCI (Bluetooth Core
//! Specification v5.4, Vol 4, Part E): LE Set Scan Parameters (section
//! 7.8.10), LE Set Scan Enable (section 7.8.11), and the LE Advertising
//! Reports between them (section 7.7.65.2).
//!
//! Raw HCI frames carry the packet indicator first, as the UART transport
//! does (Vol 4, Part A, section 2): a command is `[0x01][opcode][length]
//! [parameters]` and an event `[0x04][code][length][parameters]`, with
//! multi-octet fields little-endian (Vol 4, Part E, section 5.4). Scanning
//! is disabled when the scan ends, however it ends.

use std::time::{Duration, Instant};

use super::advertising::{self, AdvertisingError, RappAdvertiser, RappAdvertisers};
use super::gatt::BearerError;

/// The HCI command packet indicator (Vol 4, Part A, section 2;
/// FreeBSD's `NG_HCI_CMD_PKT`).
pub const HCI_COMMAND_PACKET: u8 = 0x01;
/// The HCI event packet indicator (FreeBSD's `NG_HCI_EVENT_PKT`).
pub const HCI_EVENT_PACKET: u8 = 0x04;
/// The LE Controller command group (Vol 4, Part E, section 7.8).
const OGF_LE: u16 = 0x08;
/// The bit position of the group in an opcode (Vol 4, Part E, section
/// 5.4.1).
const OGF_SHIFT: u32 = 10;
/// LE Set Scan Parameters (section 7.8.10).
const OCF_LE_SET_SCAN_PARAMETERS: u16 = 0x000B;
/// LE Set Scan Enable (section 7.8.11).
const OCF_LE_SET_SCAN_ENABLE: u16 = 0x000C;
/// The opcode of LE Set Scan Parameters.
pub const LE_SET_SCAN_PARAMETERS: u16 = (OGF_LE << OGF_SHIFT) | OCF_LE_SET_SCAN_PARAMETERS;
/// The opcode of LE Set Scan Enable.
pub const LE_SET_SCAN_ENABLE: u16 = (OGF_LE << OGF_SHIFT) | OCF_LE_SET_SCAN_ENABLE;

/// The Command Complete event (section 7.7.14).
pub const EVENT_COMMAND_COMPLETE: u8 = 0x0E;
/// The Command Status event (section 7.7.15).
pub const EVENT_COMMAND_STATUS: u8 = 0x0F;
/// The LE Meta event (section 7.7.65).
pub const EVENT_LE_META: u8 = 0x3E;
/// The LE Advertising Report subevent (section 7.7.65.2).
pub const SUBEVENT_LE_ADVERTISING_REPORT: u8 = 0x02;

/// The status Success (Vol 1, Part F, section 1.3).
pub const STATUS_SUCCESS: u8 = 0x00;
/// The status Command Disallowed: section 7.8.10 answers it while
/// scanning is enabled.
pub const STATUS_COMMAND_DISALLOWED: u8 = 0x0C;

/// `LE_Scan_Type` active: the controller asks each advertiser for its
/// scan response.
const SCAN_TYPE_ACTIVE: u8 = 0x01;
/// `Own_Address_Type` public.
const OWN_ADDRESS_PUBLIC: u8 = 0x00;
/// `Scanning_Filter_Policy` accepting every advertiser.
const FILTER_ACCEPT_ALL: u8 = 0x00;
/// `LE_Scan_Enable` on and off.
const SCAN_ENABLED: u8 = 0x01;
const SCAN_DISABLED: u8 = 0x00;
/// `Filter_Duplicates` on: one report per advertiser and kind, which is
/// all a scan for phones needs.
const FILTER_DUPLICATES: u8 = 0x01;
/// `Filter_Duplicates` off.
const KEEP_DUPLICATES: u8 = 0x00;

/// The unit of scan interval and window (section 7.8.10).
const SCAN_TIME_UNIT_MICROS: u128 = 625;
/// The scan interval, and the window: equal, so the controller listens
/// all the time the bounded scan runs, moving to the next advertising
/// channel each interval. 100 ms is `hccontrol le_scan`'s interval.
const SCAN_INTERVAL: Duration = Duration::from_millis(100);
/// [`SCAN_INTERVAL`] in units, within section 7.8.10's 0x0004 to 0x4000.
#[allow(
    clippy::cast_possible_truncation,
    reason = "160 units fit a u16; the compile-time assertion below holds it"
)]
const SCAN_INTERVAL_UNITS: u16 = (SCAN_INTERVAL.as_micros() / SCAN_TIME_UNIT_MICROS) as u16;
/// The fewest and most units section 7.8.10 allows.
const SCAN_UNITS_MIN: u16 = 0x0004;
const SCAN_UNITS_MAX: u16 = 0x4000;
const _: () =
    assert!(SCAN_INTERVAL_UNITS >= SCAN_UNITS_MIN && SCAN_INTERVAL_UNITS <= SCAN_UNITS_MAX);

/// How long a command waits for its Command Complete or Command Status:
/// FreeBSD's `hccontrol` waits the kernel's
/// `net.bluetooth.hci.command_timeout` (5 seconds by default) and one
/// more.
pub const HCI_COMMAND_TIMEOUT: Duration = Duration::from_secs(6);

/// Octets of the packet indicator and the event header (code, length).
const EVENT_HEADER_SIZE: usize = 3;
/// The longest event parameters (Vol 4, Part E, section 5.4.4).
const EVENT_PARAMETERS_LIMIT: usize = 255;
/// The longest raw HCI event frame.
pub const HCI_EVENT_FRAME_LIMIT: usize = EVENT_HEADER_SIZE + EVENT_PARAMETERS_LIMIT;
/// Octets before the opcode of a Command Complete: the command credit.
const COMPLETE_OPCODE_OFFSET: usize = 1;
/// Octets of a Command Status: status, credit, opcode.
const COMMAND_STATUS_SIZE: usize = 4;
/// The opcode's offset in a Command Status.
const STATUS_OPCODE_OFFSET: usize = 2;
/// Octets of an opcode.
const OPCODE_SIZE: usize = 2;

/// One raw HCI socket bound to a controller.
pub trait HciChannel {
    /// Sends one command frame.
    ///
    /// # Errors
    /// [`BearerError`] when the socket is unusable.
    fn send(&mut self, frame: &[u8]) -> Result<(), BearerError>;

    /// Receives the next event frame, waiting until `deadline`.
    ///
    /// # Errors
    /// [`BearerError::TimedOut`] at the deadline, and another
    /// [`BearerError`] when the socket is unusable.
    fn receive(&mut self, deadline: Instant) -> Result<Vec<u8>, BearerError>;
}

/// What a controller said to a command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommandOutcome {
    /// Success.
    Success,
    /// Command Disallowed.
    Disallowed,
    /// Any other status.
    Failed,
}

impl CommandOutcome {
    const fn from_status(status: u8) -> Self {
        match status {
            STATUS_SUCCESS => Self::Success,
            STATUS_COMMAND_DISALLOWED => Self::Disallowed,
            _ => Self::Failed,
        }
    }
}

/// One event, typed as far as the scan reads it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HciEvent {
    /// Command Complete or Command Status for `opcode`.
    Answer {
        /// The command answered.
        opcode: u16,
        /// Its status.
        outcome: CommandOutcome,
    },
    /// LE Advertising Reports.
    Advertising(Vec<advertising::AdvertisingReport>),
    /// Any other event.
    Other,
}

/// An event frame the scan refuses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HciEventError {
    /// Not an event packet.
    NotAnEvent,
    /// The parameter length disagrees with the frame.
    Length,
    /// An answer too short for its fields.
    Truncated,
    /// The advertising report does not decode.
    Advertising(AdvertisingError),
}

impl HciEvent {
    /// Decodes one raw event frame.
    ///
    /// # Errors
    /// [`HciEventError`] for a frame whose fields the specification
    /// refuses.
    pub fn decode(frame: &[u8]) -> Result<Self, HciEventError> {
        let [indicator, code, length] = frame
            .get(..EVENT_HEADER_SIZE)
            .and_then(|header| <[u8; EVENT_HEADER_SIZE]>::try_from(header).ok())
            .ok_or(HciEventError::Length)?;
        if indicator != HCI_EVENT_PACKET {
            return Err(HciEventError::NotAnEvent);
        }
        let parameters = &frame[EVENT_HEADER_SIZE..];
        if parameters.len() != usize::from(length) {
            return Err(HciEventError::Length);
        }
        let opcode_at = |offset: usize| {
            parameters
                .get(offset..offset + OPCODE_SIZE)
                .and_then(|bytes| <[u8; OPCODE_SIZE]>::try_from(bytes).ok())
                .map(u16::from_le_bytes)
                .ok_or(HciEventError::Truncated)
        };
        match code {
            EVENT_COMMAND_COMPLETE => {
                let opcode = opcode_at(COMPLETE_OPCODE_OFFSET)?;
                let status = parameters
                    .get(COMPLETE_OPCODE_OFFSET + OPCODE_SIZE)
                    .ok_or(HciEventError::Truncated)?;
                Ok(Self::Answer {
                    opcode,
                    outcome: CommandOutcome::from_status(*status),
                })
            }
            EVENT_COMMAND_STATUS => {
                if parameters.len() != COMMAND_STATUS_SIZE {
                    return Err(HciEventError::Truncated);
                }
                Ok(Self::Answer {
                    opcode: opcode_at(STATUS_OPCODE_OFFSET)?,
                    outcome: CommandOutcome::from_status(parameters[0]),
                })
            }
            EVENT_LE_META => match parameters.split_first() {
                Some((&SUBEVENT_LE_ADVERTISING_REPORT, reports)) => {
                    advertising::decode_reports(reports)
                        .map(Self::Advertising)
                        .map_err(HciEventError::Advertising)
                }
                Some(_) => Ok(Self::Other),
                None => Err(HciEventError::Truncated),
            },
            _ => Ok(Self::Other),
        }
    }
}

/// One command frame.
fn command(opcode: u16, parameters: &[u8]) -> Vec<u8> {
    let mut frame = vec![HCI_COMMAND_PACKET];
    frame.extend_from_slice(&opcode.to_le_bytes());
    frame.push(u8::try_from(parameters.len()).unwrap_or(u8::MAX));
    frame.extend_from_slice(parameters);
    frame
}

/// LE Set Scan Parameters: active, continuous, public own address,
/// every advertiser (section 7.8.10).
#[must_use]
pub fn set_scan_parameters() -> Vec<u8> {
    let mut parameters = vec![SCAN_TYPE_ACTIVE];
    parameters.extend_from_slice(&SCAN_INTERVAL_UNITS.to_le_bytes());
    parameters.extend_from_slice(&SCAN_INTERVAL_UNITS.to_le_bytes());
    parameters.push(OWN_ADDRESS_PUBLIC);
    parameters.push(FILTER_ACCEPT_ALL);
    command(LE_SET_SCAN_PARAMETERS, &parameters)
}

/// LE Set Scan Enable on, filtering duplicates, or off (section 7.8.11).
#[must_use]
pub fn set_scan_enable(enabled: bool) -> Vec<u8> {
    let parameters = if enabled {
        [SCAN_ENABLED, FILTER_DUPLICATES]
    } else {
        [SCAN_DISABLED, KEEP_DUPLICATES]
    };
    command(LE_SET_SCAN_ENABLE, &parameters)
}

/// Why a scan heard nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScanError {
    /// The socket closed, failed, or a command went unanswered.
    Channel(BearerError),
    /// The controller refused a command.
    Refused(CommandOutcome),
}

impl From<BearerError> for ScanError {
    fn from(error: BearerError) -> Self {
        Self::Channel(error)
    }
}

/// Sends `frame` for `opcode` and waits for its answer.
fn run<C: HciChannel>(
    channel: &mut C,
    opcode: u16,
    frame: &[u8],
) -> Result<CommandOutcome, ScanError> {
    channel.send(frame)?;
    let deadline = Instant::now() + HCI_COMMAND_TIMEOUT;
    loop {
        let event = channel.receive(deadline)?;
        if let Ok(HciEvent::Answer {
            opcode: answered,
            outcome,
        }) = HciEvent::decode(&event)
            && answered == opcode
        {
            return Ok(outcome);
        }
    }
}

/// Runs a command that must succeed.
fn succeed<C: HciChannel>(channel: &mut C, opcode: u16, frame: &[u8]) -> Result<(), ScanError> {
    match run(channel, opcode, frame)? {
        CommandOutcome::Success => Ok(()),
        outcome => Err(ScanError::Refused(outcome)),
    }
}

/// Scans for `window` and returns the RAPP advertisers heard, strongest
/// first. A scan a previous program left enabled makes the parameters
/// Command Disallowed (section 7.8.10); it is disabled and the parameters
/// sent again.
///
/// # Errors
/// [`ScanError`] when the controller refuses the scan or the socket
/// fails.
pub fn scan<C: HciChannel>(
    channel: &mut C,
    window: Duration,
) -> Result<Vec<RappAdvertiser>, ScanError> {
    match run(channel, LE_SET_SCAN_PARAMETERS, &set_scan_parameters())? {
        CommandOutcome::Success => {}
        CommandOutcome::Disallowed => {
            succeed(channel, LE_SET_SCAN_ENABLE, &set_scan_enable(false))?;
            succeed(channel, LE_SET_SCAN_PARAMETERS, &set_scan_parameters())?;
        }
        outcome @ CommandOutcome::Failed => return Err(ScanError::Refused(outcome)),
    }
    let heard = succeed(channel, LE_SET_SCAN_ENABLE, &set_scan_enable(true))
        .and_then(|()| listen(channel, Instant::now() + window));
    if let Err(error) = succeed(channel, LE_SET_SCAN_ENABLE, &set_scan_enable(false)) {
        refineid_dev_errors::report!(Rapp, "BLE scan not disabled", error);
    }
    heard.map(RappAdvertisers::strongest_first)
}

/// Notes every advertising report until `until`.
fn listen<C: HciChannel>(channel: &mut C, until: Instant) -> Result<RappAdvertisers, ScanError> {
    let mut heard = RappAdvertisers::default();
    loop {
        let frame = match channel.receive(until) {
            Ok(frame) => frame,
            Err(BearerError::TimedOut) => return Ok(heard),
            Err(error) => return Err(ScanError::Channel(error)),
        };
        match HciEvent::decode(&frame) {
            Ok(HciEvent::Advertising(reports)) => {
                for report in &reports {
                    heard.note(report);
                }
            }
            Ok(_) => {}
            Err(error) => {
                refineid_dev_errors::report!(Rapp, "BLE advertising report refused", error);
            }
        }
    }
}

/// Events a controller sends, for the tests of this module tree.
#[cfg(test)]
pub(crate) mod fixtures {
    use super::{
        COMMAND_STATUS_SIZE, EVENT_COMMAND_COMPLETE, EVENT_COMMAND_STATUS, EVENT_LE_META,
        HCI_EVENT_PACKET, SUBEVENT_LE_ADVERTISING_REPORT,
    };

    /// The command credit a controller grants.
    const CREDIT: u8 = 1;

    fn event(code: u8, parameters: &[u8]) -> Vec<u8> {
        let mut frame = vec![
            HCI_EVENT_PACKET,
            code,
            u8::try_from(parameters.len()).expect("fits"),
        ];
        frame.extend_from_slice(parameters);
        frame
    }

    pub(crate) fn command_complete(opcode: u16, status: u8) -> Vec<u8> {
        let mut parameters = vec![CREDIT];
        parameters.extend_from_slice(&opcode.to_le_bytes());
        parameters.push(status);
        event(EVENT_COMMAND_COMPLETE, &parameters)
    }

    pub(crate) fn command_status(opcode: u16, status: u8) -> Vec<u8> {
        let mut parameters = Vec::with_capacity(COMMAND_STATUS_SIZE);
        parameters.push(status);
        parameters.push(CREDIT);
        parameters.extend_from_slice(&opcode.to_le_bytes());
        event(EVENT_COMMAND_STATUS, &parameters)
    }

    pub(crate) fn advertising(reports: &[u8]) -> Vec<u8> {
        let mut parameters = vec![SUBEVENT_LE_ADVERTISING_REPORT];
        parameters.extend_from_slice(reports);
        event(EVENT_LE_META, &parameters)
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "test fixtures are constructed to be infallible"
)]
mod tests {
    use std::time::Duration;

    use super::super::advertising::fixtures::{
        self as air, ADDRESS_TYPE_RANDOM, EVENT_CONNECTABLE, address,
    };
    use super::super::gatt::BearerError;
    use super::super::gatt::script::{ScriptedBearer, Step};
    use super::fixtures::{advertising, command_complete, command_status};
    use super::{
        CommandOutcome, HciEvent, HciEventError, LE_SET_SCAN_ENABLE, LE_SET_SCAN_PARAMETERS,
        STATUS_COMMAND_DISALLOWED, STATUS_SUCCESS, ScanError, scan, set_scan_enable,
        set_scan_parameters,
    };

    /// A status other than Success or Command Disallowed: Unknown HCI
    /// Command (Vol 1, Part F, section 1.3).
    const STATUS_UNKNOWN_COMMAND: u8 = 0x01;
    const PHONE: &str = "02:00:00:00:00:01";
    /// A signal strength, in dBm.
    const RSSI: i8 = -60;
    /// A scan that ends at once: the script runs out.
    const WINDOW: Duration = Duration::ZERO;

    fn phone_event() -> Vec<u8> {
        advertising(&air::event(&[air::report(
            EVENT_CONNECTABLE,
            ADDRESS_TYPE_RANDOM,
            address(PHONE),
            &air::rapp_data(),
            RSSI,
        )]))
    }

    #[test]
    fn a_scan_hears_the_phone_and_is_disabled() {
        let mut channel = ScriptedBearer::new(vec![
            Step::Sent(set_scan_parameters()),
            Step::Peer(command_complete(LE_SET_SCAN_PARAMETERS, STATUS_SUCCESS)),
            Step::Sent(set_scan_enable(true)),
            Step::Peer(command_complete(LE_SET_SCAN_ENABLE, STATUS_SUCCESS)),
            Step::Peer(phone_event()),
            Step::Silence,
            Step::Sent(set_scan_enable(false)),
            Step::Peer(command_complete(LE_SET_SCAN_ENABLE, STATUS_SUCCESS)),
        ]);
        let heard = scan(&mut channel, WINDOW).unwrap();
        assert_eq!(heard.len(), 1);
        assert_eq!(heard[0].address().octets(), address(PHONE));
    }

    #[test]
    fn a_scan_left_enabled_is_disabled_first() {
        let mut channel = ScriptedBearer::new(vec![
            Step::Sent(set_scan_parameters()),
            Step::Peer(command_complete(
                LE_SET_SCAN_PARAMETERS,
                STATUS_COMMAND_DISALLOWED,
            )),
            Step::Sent(set_scan_enable(false)),
            Step::Peer(command_complete(LE_SET_SCAN_ENABLE, STATUS_SUCCESS)),
            Step::Sent(set_scan_parameters()),
            Step::Peer(command_complete(LE_SET_SCAN_PARAMETERS, STATUS_SUCCESS)),
            Step::Sent(set_scan_enable(true)),
            Step::Peer(command_complete(LE_SET_SCAN_ENABLE, STATUS_SUCCESS)),
            Step::Silence,
            Step::Sent(set_scan_enable(false)),
            Step::Peer(command_complete(LE_SET_SCAN_ENABLE, STATUS_SUCCESS)),
        ]);
        assert_eq!(scan(&mut channel, WINDOW), Ok(Vec::new()));
    }

    #[test]
    fn a_failing_scan_still_disables_scanning() {
        let mut channel = ScriptedBearer::new(vec![
            Step::Sent(set_scan_parameters()),
            Step::Peer(command_complete(LE_SET_SCAN_PARAMETERS, STATUS_SUCCESS)),
            Step::Sent(set_scan_enable(true)),
            Step::Peer(command_status(LE_SET_SCAN_ENABLE, STATUS_UNKNOWN_COMMAND)),
            Step::Sent(set_scan_enable(false)),
            Step::Peer(command_complete(LE_SET_SCAN_ENABLE, STATUS_SUCCESS)),
        ]);
        assert_eq!(
            scan(&mut channel, WINDOW),
            Err(ScanError::Refused(CommandOutcome::Failed))
        );
        let mut channel = ScriptedBearer::new(vec![
            Step::Sent(set_scan_parameters()),
            Step::Peer(command_complete(LE_SET_SCAN_PARAMETERS, STATUS_SUCCESS)),
            Step::Sent(set_scan_enable(true)),
            Step::Peer(command_complete(LE_SET_SCAN_ENABLE, STATUS_SUCCESS)),
            Step::Close,
        ]);
        assert_eq!(
            scan(&mut channel, WINDOW),
            Err(ScanError::Channel(BearerError::Closed))
        );
    }

    #[test]
    fn malformed_events_are_refused() {
        let mut frame = command_complete(LE_SET_SCAN_ENABLE, STATUS_SUCCESS);
        frame.pop();
        assert_eq!(HciEvent::decode(&frame), Err(HciEventError::Length));
        let mut frame = phone_event();
        let last = frame.len() - 1;
        frame.truncate(last);
        frame[super::EVENT_HEADER_SIZE - 1] -= 1;
        assert!(matches!(
            HciEvent::decode(&frame),
            Err(HciEventError::Advertising(_))
        ));
        assert_eq!(
            HciEvent::decode(&set_scan_parameters()),
            Err(HciEventError::NotAnEvent)
        );
    }
}
