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

//! The GATT client connection setup of RAPP v26.11.2 section 5.2 over one
//! ATT bearer, and the channel it leaves open.
//!
//! Setup runs, in order: the MTU exchange (Bluetooth Core Specification
//! v5.4, Vol 3, Part G, section 4.3.1), Discover All Primary Services
//! (section 4.4.1), Discover All Characteristics of the RAPP service
//! (section 4.6.1), Discover All Characteristic Descriptors of the
//! Channel Characteristic (section 4.7.1), and the write of `0x0002` to
//! its CCCD (section 4.12.3). One request is outstanding at a time, each
//! bounded by the ATT transaction timeout (Vol 3, Part F, section 3.3.3).
//!
//! While it waits, the link answers the phone at once: every indication
//! is confirmed, every request is refused (the requester runs no GATT
//! server), a phone's own MTU exchange is answered, and notifications and
//! commands are ignored. Only indications of the Channel Characteristic
//! carry RAPP fragments; every other is confirmed and dropped.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use refineid_rapp::ble_sar::BLE_SAR_SEQUENCE_LIMIT;

use super::att::{
    self, AttDecodeError, AttErrorCode, AttHandle, AttributeType, CCCD_INDICATIONS, CCCD_TYPE,
    CHARACTERISTIC_TYPE, CharacteristicDeclaration, HandleRange, NegotiatedMtu,
    OP_FIND_INFORMATION_REQ, OP_READ_BY_GROUP_TYPE_REQ, OP_READ_BY_TYPE_REQ, OP_WRITE_REQ,
    PRIMARY_SERVICE_TYPE, PROPERTY_EXTENDED, PROPERTY_INDICATE, PROPERTY_READ, PROPERTY_WRITE,
    PeerPdu, RAPP_BOOTSTRAP_UUID, RAPP_CHANNEL_UUID, RAPP_SERVICE_UUID,
};

/// How long one ATT transaction may stay outstanding (Vol 3, Part F,
/// section 3.3.3); past it no further PDU may be sent on the bearer.
pub const ATT_TRANSACTION_TIMEOUT: Duration = Duration::from_secs(30);

/// The most channel indications held for the transport: every fragment of
/// one longest SAR message (RAPP v26.11.2 section 5.3).
const PENDING_INDICATION_LIMIT: usize = BLE_SAR_SEQUENCE_LIMIT;

/// One ATT bearer: the L2CAP ATT channel of one LE connection, carrying
/// whole PDUs.
pub trait AttBearer {
    /// Sends one PDU.
    ///
    /// # Errors
    /// [`BearerError`] when the bearer is closed or failed.
    fn send(&mut self, pdu: &[u8]) -> Result<(), BearerError>;

    /// Receives the next PDU, waiting until `deadline`.
    ///
    /// # Errors
    /// [`BearerError::TimedOut`] at the deadline, [`BearerError::Closed`]
    /// when the peer closed the connection, and [`BearerError::Failed`]
    /// otherwise.
    fn receive(&mut self, deadline: Instant) -> Result<Vec<u8>, BearerError>;
}

/// Why a bearer moved no PDU.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BearerError {
    /// The peer closed the connection.
    Closed,
    /// The deadline passed with nothing received.
    TimedOut,
    /// The bearer failed.
    Failed,
}

/// Why the link failed; every case drops the connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GattError {
    /// The phone closed the connection.
    Closed,
    /// The deadline passed: a transaction timed out, or no indication
    /// arrived in time.
    TimedOut,
    /// The bearer failed.
    BearerFailed,
    /// A PDU from the phone did not decode.
    Malformed(AttDecodeError),
    /// The negotiated MTU is below 512 (section 5.2 item 1).
    MtuTooSmall,
    /// No RAPP primary service.
    ServiceMissing,
    /// The RAPP service lacks the Channel or Bootstrap Characteristic.
    CharacteristicMissing,
    /// A RAPP characteristic declares properties other than section 5.1's.
    PropertiesRefused,
    /// The Channel Characteristic has no CCCD.
    CccdMissing,
    /// The phone answered a request with an error.
    ErrorResponse(AttErrorCode),
    /// A response that answers no outstanding request.
    UnexpectedResponse,
    /// More channel indications arrived than one message can hold.
    IndicationBacklog,
}

impl From<BearerError> for GattError {
    fn from(error: BearerError) -> Self {
        match error {
            BearerError::Closed => Self::Closed,
            BearerError::TimedOut => Self::TimedOut,
            BearerError::Failed => Self::BearerFailed,
        }
    }
}

/// The RAPP service's three attributes, found with the properties section
/// 5.1 assigns.
///
/// The Channel Characteristic must declare Write and Indicate and the
/// Bootstrap Characteristic Read (section 5.1); either may also declare
/// Extended Properties, which iOS adds by itself (observed: iOS declares
/// the channel `0xa8`, Android `0x28`). Any other property bit is
/// refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RappService {
    channel_value: AttHandle,
    channel_cccd: AttHandle,
    bootstrap_value: AttHandle,
}

impl RappService {
    fn discovered(
        channel: &CharacteristicDeclaration,
        channel_cccd: AttHandle,
        bootstrap: &CharacteristicDeclaration,
    ) -> Result<Self, GattError> {
        if !channel
            .properties
            .are(PROPERTY_WRITE | PROPERTY_INDICATE, PROPERTY_EXTENDED)
            || !bootstrap.properties.are(PROPERTY_READ, PROPERTY_EXTENDED)
        {
            return Err(GattError::PropertiesRefused);
        }
        Ok(Self {
            channel_value: channel.value,
            channel_cccd,
            bootstrap_value: bootstrap.value,
        })
    }

    /// The Channel Characteristic value.
    #[must_use]
    pub const fn channel_value(&self) -> AttHandle {
        self.channel_value
    }

    /// The Channel Characteristic's CCCD.
    #[must_use]
    pub const fn channel_cccd(&self) -> AttHandle {
        self.channel_cccd
    }

    /// The Bootstrap Characteristic value; sessions never read it.
    #[must_use]
    pub const fn bootstrap_value(&self) -> AttHandle {
        self.bootstrap_value
    }
}

/// One indication of the Channel Characteristic: a SAR fragment in
/// transit, and when it arrived.
#[derive(Debug)]
pub struct ChannelIndication {
    /// The fragment.
    pub fragment: Vec<u8>,
    /// When it arrived.
    pub arrived: Instant,
}

/// A bearer with the phone's PDUs answered as they come.
#[derive(Debug)]
struct Answering<B> {
    bearer: B,
    channel: Option<AttHandle>,
    pending: VecDeque<ChannelIndication>,
}

impl<B: AttBearer> Answering<B> {
    /// Receives one PDU and answers it; a response is returned.
    fn receive(&mut self, deadline: Instant) -> Result<Option<PeerPdu>, GattError> {
        let bytes = self.bearer.receive(deadline)?;
        match PeerPdu::decode(&bytes).map_err(GattError::Malformed)? {
            PeerPdu::Indication { handle, value } => {
                self.bearer.send(&att::handle_value_confirmation())?;
                if Some(handle) == self.channel {
                    if self.pending.len() >= PENDING_INDICATION_LIMIT {
                        return Err(GattError::IndicationBacklog);
                    }
                    self.pending.push_back(ChannelIndication {
                        fragment: value,
                        arrived: Instant::now(),
                    });
                }
                Ok(None)
            }
            PeerPdu::Request(refusal) => {
                self.bearer.send(&refusal.encode())?;
                Ok(None)
            }
            PeerPdu::ExchangeMtuRequest => {
                self.bearer.send(&att::exchange_mtu_response())?;
                Ok(None)
            }
            PeerPdu::Notification | PeerPdu::Command => Ok(None),
            response => Ok(Some(response)),
        }
    }

    /// Sends `request` and returns its response, by `deadline` and the
    /// transaction timeout.
    fn transact(&mut self, request: &[u8], deadline: Instant) -> Result<PeerPdu, GattError> {
        let deadline = deadline.min(Instant::now() + ATT_TRANSACTION_TIMEOUT);
        self.bearer.send(request)?;
        loop {
            if let Some(response) = self.receive(deadline)? {
                return Ok(response);
            }
        }
    }
}

/// What a response other than the expected one says.
enum OtherAnswer {
    /// `Attribute Not Found` to the request: a discovery found nothing
    /// more.
    NotFound,
    /// Any other answer, and the failure it is.
    Failed(GattError),
}

impl OtherAnswer {
    /// Reads `response` to the request with `request_opcode`.
    fn of(response: PeerPdu, request_opcode: u8) -> Self {
        match response {
            PeerPdu::ErrorResponse {
                request_opcode: opcode,
                code,
            } if opcode == request_opcode => match code {
                AttErrorCode::AttributeNotFound => Self::NotFound,
                code => Self::Failed(GattError::ErrorResponse(code)),
            },
            _ => Self::Failed(GattError::UnexpectedResponse),
        }
    }

    /// The failure, with `not_found` standing for `Attribute Not Found`.
    fn failure(self, not_found: GattError) -> GattError {
        match self {
            Self::NotFound => not_found,
            Self::Failed(error) => error,
        }
    }
}

/// A set-up RAPP channel: indications on, ready for the routing preamble
/// (section 5.2 item 3).
#[derive(Debug)]
pub struct GattLink<B> {
    answering: Answering<B>,
    mtu: NegotiatedMtu,
    service: RappService,
}

impl<B: AttBearer> GattLink<B> {
    /// Sets up the RAPP channel on `bearer` by `deadline`.
    ///
    /// # Errors
    /// [`GattError`] for every failure; the bearer is dropped with it.
    pub fn set_up(bearer: B, deadline: Instant) -> Result<Self, GattError> {
        let mut answering = Answering {
            bearer,
            channel: None,
            pending: VecDeque::new(),
        };
        let mtu = match answering.transact(&att::exchange_mtu_request(), deadline)? {
            PeerPdu::ExchangeMtuResponse { server_rx_mtu } => {
                NegotiatedMtu::from_exchange(server_rx_mtu).ok_or(GattError::MtuTooSmall)?
            }
            other => {
                return Err(OtherAnswer::of(other, att::OP_EXCHANGE_MTU_REQ)
                    .failure(GattError::ErrorResponse(AttErrorCode::AttributeNotFound)));
            }
        };
        let service = discover_service(&mut answering, deadline)?;
        let declarations = discover_characteristics(&mut answering, service, deadline)?;
        let find = |uuid| {
            declarations
                .iter()
                .find(|declaration| declaration.uuid == AttributeType::Long(uuid))
                .ok_or(GattError::CharacteristicMissing)
        };
        let channel = find(RAPP_CHANNEL_UUID)?;
        let bootstrap = find(RAPP_BOOTSTRAP_UUID)?;
        let descriptors = channel_descriptors(channel, &declarations, service)?;
        let cccd = discover_cccd(&mut answering, descriptors, deadline)?;
        let service = RappService::discovered(channel, cccd, bootstrap)?;
        answering.channel = Some(service.channel_value);
        let mut link = Self {
            answering,
            mtu,
            service,
        };
        link.write(cccd, &CCCD_INDICATIONS.to_le_bytes(), deadline)?;
        Ok(link)
    }

    /// The negotiated MTU.
    #[must_use]
    pub const fn mtu(&self) -> NegotiatedMtu {
        self.mtu
    }

    /// The RAPP service found.
    #[must_use]
    pub const fn service(&self) -> RappService {
        self.service
    }

    /// Writes one SAR fragment to the Channel Characteristic and waits for
    /// its Write Response: one fragment in flight (section 5.2).
    ///
    /// # Errors
    /// [`GattError`] when the write fails or times out.
    pub fn write_channel(&mut self, fragment: &[u8]) -> Result<(), GattError> {
        let channel = self.service.channel_value;
        self.write(channel, fragment, Instant::now() + ATT_TRANSACTION_TIMEOUT)
    }

    fn write(
        &mut self,
        handle: AttHandle,
        value: &[u8],
        deadline: Instant,
    ) -> Result<(), GattError> {
        match self
            .answering
            .transact(&att::write_request(handle, value), deadline)?
        {
            PeerPdu::WriteResponse => Ok(()),
            other => Err(OtherAnswer::of(other, OP_WRITE_REQ)
                .failure(GattError::ErrorResponse(AttErrorCode::AttributeNotFound))),
        }
    }

    /// The next indication of the Channel Characteristic, held or received
    /// by `deadline`.
    ///
    /// # Errors
    /// [`GattError::TimedOut`] at the deadline, and [`GattError`] for every
    /// failure of the link.
    pub fn next_channel_indication(
        &mut self,
        deadline: Instant,
    ) -> Result<ChannelIndication, GattError> {
        loop {
            if let Some(indication) = self.answering.pending.pop_front() {
                return Ok(indication);
            }
            if self.answering.receive(deadline)?.is_some() {
                return Err(GattError::UnexpectedResponse);
            }
        }
    }
}

/// The RAPP primary service's handle range (Vol 3, Part G, section
/// 4.4.1).
fn discover_service<B: AttBearer>(
    answering: &mut Answering<B>,
    deadline: Instant,
) -> Result<HandleRange, GattError> {
    let mut remaining = Some(HandleRange::all());
    while let Some(range) = remaining {
        let request = att::read_by_group_type_request(range, PRIMARY_SERVICE_TYPE);
        let groups = match answering.transact(&request, deadline)? {
            PeerPdu::ReadByGroupTypeResponse(groups) => groups,
            other => {
                return Err(OtherAnswer::of(other, OP_READ_BY_GROUP_TYPE_REQ)
                    .failure(GattError::ServiceMissing));
            }
        };
        if groups
            .iter()
            .any(|group| !range.contains(group.range.start()))
        {
            return Err(GattError::Malformed(AttDecodeError::InvertedRange));
        }
        if let Some(group) = groups
            .iter()
            .find(|group| group.uuid == AttributeType::Long(RAPP_SERVICE_UUID))
        {
            return Ok(group.range);
        }
        remaining = groups
            .iter()
            .map(|group| group.range.end())
            .max()
            .and_then(|last| range.after(last));
    }
    Err(GattError::ServiceMissing)
}

/// Every characteristic declaration of `service` (Vol 3, Part G, section
/// 4.6.1), in handle order.
fn discover_characteristics<B: AttBearer>(
    answering: &mut Answering<B>,
    service: HandleRange,
    deadline: Instant,
) -> Result<Vec<CharacteristicDeclaration>, GattError> {
    let mut found: Vec<CharacteristicDeclaration> = Vec::new();
    let mut remaining = Some(service);
    while let Some(range) = remaining {
        let request = att::read_by_type_request(range, CHARACTERISTIC_TYPE);
        let declarations = match answering.transact(&request, deadline)? {
            PeerPdu::ReadByTypeResponse(declarations) => declarations,
            other => match OtherAnswer::of(other, OP_READ_BY_TYPE_REQ) {
                OtherAnswer::NotFound => break,
                OtherAnswer::Failed(error) => return Err(error),
            },
        };
        if declarations
            .iter()
            .any(|declaration| !range.contains(declaration.declaration))
        {
            return Err(GattError::Malformed(AttDecodeError::InvertedRange));
        }
        remaining = declarations
            .iter()
            .map(|declaration| declaration.declaration)
            .max()
            .and_then(|last| range.after(last));
        found.extend(declarations);
    }
    found.sort_by_key(|declaration| declaration.declaration);
    Ok(found)
}

/// The handles where the channel's descriptors lie: after its value, up
/// to the next declaration or the end of the service (Vol 3, Part G,
/// section 4.7.1).
fn channel_descriptors(
    channel: &CharacteristicDeclaration,
    declarations: &[CharacteristicDeclaration],
    service: HandleRange,
) -> Result<HandleRange, GattError> {
    let start = channel.value.next().ok_or(GattError::CccdMissing)?;
    let end = match declarations
        .iter()
        .map(|declaration| declaration.declaration)
        .find(|&declaration| declaration > channel.declaration)
    {
        Some(next) => AttHandle::new(next.get() - 1).ok_or(GattError::CccdMissing)?,
        None => service.end(),
    };
    HandleRange::new(start, end).ok_or(GattError::CccdMissing)
}

/// The channel's CCCD among the descriptors in `range` (Vol 3, Part G,
/// section 4.7.1).
fn discover_cccd<B: AttBearer>(
    answering: &mut Answering<B>,
    range: HandleRange,
    deadline: Instant,
) -> Result<AttHandle, GattError> {
    let mut remaining = Some(range);
    while let Some(range) = remaining {
        let request = att::find_information_request(range);
        let descriptors = match answering.transact(&request, deadline)? {
            PeerPdu::FindInformationResponse(descriptors) => descriptors,
            other => {
                return Err(
                    OtherAnswer::of(other, OP_FIND_INFORMATION_REQ).failure(GattError::CccdMissing)
                );
            }
        };
        if descriptors
            .iter()
            .any(|descriptor| !range.contains(descriptor.handle))
        {
            return Err(GattError::Malformed(AttDecodeError::InvertedRange));
        }
        if let Some(cccd) = descriptors
            .iter()
            .find(|descriptor| descriptor.uuid == AttributeType::Short(CCCD_TYPE))
        {
            return Ok(cccd.handle);
        }
        remaining = descriptors
            .iter()
            .map(|descriptor| descriptor.handle)
            .max()
            .and_then(|last| range.after(last));
    }
    Err(GattError::CccdMissing)
}

/// A scripted bearer and the phone side of a setup, for the tests of this
/// module tree.
#[cfg(test)]
pub(crate) mod script {
    use std::collections::VecDeque;
    use std::time::Instant;

    use super::super::att::fixtures::{self, Wire};
    use super::super::att::{
        self, CCCD_INDICATIONS, CCCD_TYPE, CHARACTERISTIC_TYPE, ERROR_ATTRIBUTE_NOT_FOUND,
        HandleRange, OP_READ_BY_TYPE_REQ, PRIMARY_SERVICE_TYPE, PROPERTY_INDICATE, PROPERTY_READ,
        PROPERTY_WRITE, RAPP_BOOTSTRAP_UUID, RAPP_CHANNEL_UUID, RAPP_SERVICE_UUID,
    };
    use super::super::hci::HciChannel;
    use super::{AttBearer, BearerError};

    /// One step of a scripted exchange.
    #[derive(Clone, Debug)]
    pub(crate) enum Step {
        /// The requester sends this PDU.
        Sent(Vec<u8>),
        /// The phone sends this PDU.
        Peer(Vec<u8>),
        /// The peer sends nothing until the deadline.
        Silence,
        /// The peer closes the connection; every later call fails.
        Close,
    }

    /// A bearer that plays a script and checks every PDU sent against it;
    /// a receive past the script's end times out.
    #[derive(Debug)]
    pub(crate) struct ScriptedBearer {
        steps: VecDeque<Step>,
    }

    impl ScriptedBearer {
        pub(crate) fn new(steps: Vec<Step>) -> Self {
            Self {
                steps: steps.into(),
            }
        }
    }

    impl Drop for ScriptedBearer {
        fn drop(&mut self) {
            if !std::thread::panicking() {
                assert!(
                    !self.steps.iter().any(|step| matches!(step, Step::Sent(_))),
                    "the requester left scripted PDUs unsent: {:?}",
                    self.steps
                );
            }
        }
    }

    impl ScriptedBearer {
        fn play_send(&mut self, pdu: &[u8]) -> Result<(), BearerError> {
            if matches!(self.steps.front(), Some(Step::Close)) {
                return Err(BearerError::Closed);
            }
            match self.steps.pop_front() {
                Some(Step::Sent(expected)) => {
                    assert_eq!(pdu, expected.as_slice(), "the requester sent another PDU");
                    Ok(())
                }
                other => panic!("the requester sent {pdu:?} where the script holds {other:?}"),
            }
        }

        fn play_receive(&mut self) -> Result<Vec<u8>, BearerError> {
            match self.steps.front() {
                Some(Step::Peer(_) | Step::Silence) => match self.steps.pop_front() {
                    Some(Step::Peer(pdu)) => Ok(pdu),
                    _ => Err(BearerError::TimedOut),
                },
                Some(Step::Close) => Err(BearerError::Closed),
                Some(Step::Sent(expected)) => {
                    panic!("the requester waits where the script expects {expected:?}")
                }
                None => Err(BearerError::TimedOut),
            }
        }
    }

    impl AttBearer for ScriptedBearer {
        fn send(&mut self, pdu: &[u8]) -> Result<(), BearerError> {
            self.play_send(pdu)
        }

        fn receive(&mut self, _deadline: Instant) -> Result<Vec<u8>, BearerError> {
            self.play_receive()
        }
    }

    impl HciChannel for ScriptedBearer {
        fn send(&mut self, frame: &[u8]) -> Result<(), BearerError> {
            self.play_send(frame)
        }

        fn receive(&mut self, _deadline: Instant) -> Result<Vec<u8>, BearerError> {
            self.play_receive()
        }
    }

    /// The phone's receive MTU.
    pub(crate) const PHONE_MTU: u16 = 517;
    /// The GAP service, listed before the RAPP service (Assigned
    /// Numbers, section 3.4).
    pub(crate) const GAP_SERVICE: u16 = 0x1800;
    pub(crate) const GAP_START: u16 = 0x0001;
    pub(crate) const GAP_END: u16 = 0x0005;
    pub(crate) const SERVICE_START: u16 = 0x0010;
    pub(crate) const CHANNEL_DECLARATION: u16 = 0x0011;
    pub(crate) const CHANNEL_VALUE: u16 = 0x0012;
    pub(crate) const CHANNEL_CCCD: u16 = 0x0013;
    pub(crate) const BOOTSTRAP_DECLARATION: u16 = 0x0014;
    pub(crate) const BOOTSTRAP_VALUE: u16 = 0x0015;
    pub(crate) const SERVICE_END: u16 = BOOTSTRAP_VALUE;
    /// The channel's properties as section 5.1 assigns them.
    pub(crate) const CHANNEL_PROPERTIES: u8 = PROPERTY_WRITE | PROPERTY_INDICATE;

    pub(crate) fn range(start: u16, end: u16) -> HandleRange {
        HandleRange::new(fixtures::handle(start), fixtures::handle(end))
            .expect("a fixture range is ordered")
    }

    /// The MTU exchange answered with `phone_mtu`.
    pub(crate) fn mtu_steps(phone_mtu: u16) -> Vec<Step> {
        vec![
            Step::Sent(att::exchange_mtu_request()),
            Step::Peer(fixtures::exchange_mtu_response(phone_mtu)),
        ]
    }

    /// Service discovery finding the GAP service, then the RAPP service.
    pub(crate) fn service_steps() -> Vec<Step> {
        vec![
            Step::Sent(att::read_by_group_type_request(
                HandleRange::all(),
                PRIMARY_SERVICE_TYPE,
            )),
            Step::Peer(fixtures::read_by_group_type_response(&[(
                GAP_START,
                GAP_END,
                Wire::Short(GAP_SERVICE),
            )])),
            Step::Sent(att::read_by_group_type_request(
                range(GAP_END + 1, att::LAST_HANDLE),
                PRIMARY_SERVICE_TYPE,
            )),
            Step::Peer(fixtures::read_by_group_type_response(&[(
                SERVICE_START,
                SERVICE_END,
                Wire::Long(RAPP_SERVICE_UUID),
            )])),
        ]
    }

    /// Characteristic discovery with the channel declaring
    /// `channel_properties`.
    pub(crate) fn characteristic_steps(channel_properties: u8) -> Vec<Step> {
        vec![
            Step::Sent(att::read_by_type_request(
                range(SERVICE_START, SERVICE_END),
                CHARACTERISTIC_TYPE,
            )),
            Step::Peer(fixtures::read_by_type_response(&[
                (
                    CHANNEL_DECLARATION,
                    channel_properties,
                    CHANNEL_VALUE,
                    Wire::Long(RAPP_CHANNEL_UUID),
                ),
                (
                    BOOTSTRAP_DECLARATION,
                    PROPERTY_READ,
                    BOOTSTRAP_VALUE,
                    Wire::Long(RAPP_BOOTSTRAP_UUID),
                ),
            ])),
            Step::Sent(att::read_by_type_request(
                range(BOOTSTRAP_DECLARATION + 1, SERVICE_END),
                CHARACTERISTIC_TYPE,
            )),
            Step::Peer(fixtures::error_response(
                OP_READ_BY_TYPE_REQ,
                BOOTSTRAP_VALUE,
                ERROR_ATTRIBUTE_NOT_FOUND,
            )),
        ]
    }

    /// Descriptor discovery finding the CCCD.
    pub(crate) fn cccd_steps() -> Vec<Step> {
        vec![
            Step::Sent(att::find_information_request(range(
                CHANNEL_CCCD,
                CHANNEL_CCCD,
            ))),
            Step::Peer(fixtures::find_information_response(&[(
                CHANNEL_CCCD,
                Wire::Short(CCCD_TYPE),
            )])),
        ]
    }

    /// The CCCD write.
    pub(crate) fn cccd_write() -> Step {
        Step::Sent(att::write_request(
            fixtures::handle(CHANNEL_CCCD),
            &CCCD_INDICATIONS.to_le_bytes(),
        ))
    }

    /// A whole setup the phone accepts.
    pub(crate) fn setup() -> Vec<Step> {
        let mut steps = mtu_steps(PHONE_MTU);
        steps.extend(service_steps());
        steps.extend(characteristic_steps(CHANNEL_PROPERTIES));
        steps.extend(cccd_steps());
        steps.push(cccd_write());
        steps.push(Step::Peer(fixtures::write_response()));
        steps
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::super::att::fixtures::{self, Wire};
    use super::super::att::{
        self, AttDecodeError, AttErrorCode, CCCD_TYPE, ERROR_ATTRIBUTE_NOT_FOUND,
        ERROR_REQUEST_NOT_SUPPORTED, HandleRange, OP_READ_BY_GROUP_TYPE_REQ, OP_WRITE_REQ,
        PRIMARY_SERVICE_TYPE, PROPERTY_EXTENDED, PROPERTY_READ, REQUESTED_ATT_MTU,
    };
    use super::script::{
        self, CHANNEL_CCCD, CHANNEL_PROPERTIES, CHANNEL_VALUE, PHONE_MTU, ScriptedBearer, Step,
    };
    use super::{GattError, GattLink};
    use refineid_rapp::ble_sar::BLE_MINIMUM_ATT_MTU;

    /// A handle outside the RAPP service, such as Service Changed.
    const OTHER_HANDLE: u16 = 0x0003;
    /// How long a test link waits.
    const DEADLINE: Duration = Duration::from_secs(1);

    fn set_up(steps: Vec<Step>) -> Result<GattLink<ScriptedBearer>, GattError> {
        GattLink::set_up(ScriptedBearer::new(steps), Instant::now() + DEADLINE)
    }

    #[test]
    fn a_phone_that_serves_the_profile_is_set_up() {
        let link = set_up(script::setup()).expect("the setup completes");
        assert_eq!(link.mtu().octets(), usize::from(REQUESTED_ATT_MTU));
        assert_eq!(
            link.service().channel_value(),
            fixtures::handle(CHANNEL_VALUE)
        );
        assert_eq!(
            link.service().channel_cccd(),
            fixtures::handle(CHANNEL_CCCD)
        );
    }

    #[test]
    fn an_mtu_below_the_profile_minimum_drops_the_connection() {
        let small = u16::try_from(BLE_MINIMUM_ATT_MTU - 1).expect("fits");
        assert_eq!(
            set_up(script::mtu_steps(small)).err(),
            Some(GattError::MtuTooSmall)
        );
    }

    #[test]
    fn a_phone_without_the_service_is_refused() {
        let mut steps = script::mtu_steps(PHONE_MTU);
        steps.push(Step::Sent(att::read_by_group_type_request(
            HandleRange::all(),
            PRIMARY_SERVICE_TYPE,
        )));
        steps.push(Step::Peer(fixtures::error_response(
            OP_READ_BY_GROUP_TYPE_REQ,
            att::FIRST_HANDLE,
            ERROR_ATTRIBUTE_NOT_FOUND,
        )));
        assert_eq!(set_up(steps).err(), Some(GattError::ServiceMissing));
    }

    fn setup_with_channel_properties(properties: u8) -> Vec<Step> {
        let mut steps = script::mtu_steps(PHONE_MTU);
        steps.extend(script::service_steps());
        steps.extend(script::characteristic_steps(properties));
        steps.extend(script::cccd_steps());
        steps
    }

    #[test]
    fn a_channel_with_other_properties_is_refused() {
        let steps = setup_with_channel_properties(CHANNEL_PROPERTIES | PROPERTY_READ);
        assert_eq!(set_up(steps).err(), Some(GattError::PropertiesRefused));
    }

    #[test]
    fn the_extended_properties_bit_is_accepted() {
        let mut steps = setup_with_channel_properties(CHANNEL_PROPERTIES | PROPERTY_EXTENDED);
        steps.push(script::cccd_write());
        steps.push(Step::Peer(fixtures::write_response()));
        assert!(set_up(steps).is_ok());
    }

    #[test]
    fn a_request_of_the_phones_is_answered_at_once() {
        let probe = att::read_by_group_type_request(HandleRange::all(), CCCD_TYPE);
        let write = att::write_request(fixtures::handle(OTHER_HANDLE), b"x");
        let mut steps = vec![
            Step::Sent(att::exchange_mtu_request()),
            Step::Peer(probe),
            Step::Sent(fixtures::error_response(
                OP_READ_BY_GROUP_TYPE_REQ,
                att::FIRST_HANDLE,
                ERROR_ATTRIBUTE_NOT_FOUND,
            )),
            Step::Peer(write),
            Step::Sent(fixtures::error_response(
                OP_WRITE_REQ,
                att::NO_HANDLE,
                ERROR_REQUEST_NOT_SUPPORTED,
            )),
            Step::Peer(fixtures::exchange_mtu_response(PHONE_MTU)),
        ];
        steps.extend(script::service_steps());
        steps.extend(script::characteristic_steps(CHANNEL_PROPERTIES));
        steps.extend(script::cccd_steps());
        steps.push(script::cccd_write());
        steps.push(Step::Peer(fixtures::write_response()));
        assert!(set_up(steps).is_ok());
    }

    #[test]
    fn a_stray_indication_is_confirmed_and_dropped() {
        let mut steps = vec![
            Step::Sent(att::exchange_mtu_request()),
            Step::Peer(fixtures::indication(OTHER_HANDLE, b"service changed")),
            Step::Sent(att::handle_value_confirmation()),
            Step::Peer(fixtures::exchange_mtu_response(PHONE_MTU)),
        ];
        steps.extend(script::service_steps());
        steps.extend(script::characteristic_steps(CHANNEL_PROPERTIES));
        steps.extend(script::cccd_steps());
        steps.push(script::cccd_write());
        steps.push(Step::Peer(fixtures::write_response()));
        let mut link = set_up(steps).expect("the setup completes");
        assert_eq!(
            link.next_channel_indication(Instant::now()).err(),
            Some(GattError::TimedOut)
        );
    }

    #[test]
    fn an_error_response_to_the_cccd_write_fails_the_setup() {
        let mut steps = setup_with_channel_properties(CHANNEL_PROPERTIES);
        steps.push(script::cccd_write());
        steps.push(Step::Peer(fixtures::error_response(
            OP_WRITE_REQ,
            CHANNEL_CCCD,
            ERROR_REQUEST_NOT_SUPPORTED,
        )));
        assert_eq!(
            set_up(steps).err(),
            Some(GattError::ErrorResponse(AttErrorCode::RequestNotSupported))
        );
    }

    #[test]
    fn a_truncated_response_fails_the_setup() {
        let mut response = fixtures::read_by_group_type_response(&[(
            script::SERVICE_START,
            script::SERVICE_END,
            Wire::Short(CCCD_TYPE),
        )]);
        response.pop();
        let mut steps = script::mtu_steps(PHONE_MTU);
        steps.push(Step::Sent(att::read_by_group_type_request(
            HandleRange::all(),
            PRIMARY_SERVICE_TYPE,
        )));
        steps.push(Step::Peer(response));
        assert_eq!(
            set_up(steps).err(),
            Some(GattError::Malformed(AttDecodeError::Malformed))
        );
    }

    #[test]
    fn a_silent_phone_times_the_setup_out_and_a_closed_one_ends_it() {
        let steps = vec![Step::Sent(att::exchange_mtu_request())];
        assert_eq!(set_up(steps).err(), Some(GattError::TimedOut));
        let steps = vec![Step::Sent(att::exchange_mtu_request()), Step::Close];
        assert_eq!(set_up(steps).err(), Some(GattError::Closed));
    }

    #[test]
    fn a_write_response_out_of_turn_is_unexpected() {
        let steps = vec![
            Step::Sent(att::exchange_mtu_request()),
            Step::Peer(fixtures::write_response()),
        ];
        assert_eq!(set_up(steps).err(), Some(GattError::UnexpectedResponse));
    }
}
