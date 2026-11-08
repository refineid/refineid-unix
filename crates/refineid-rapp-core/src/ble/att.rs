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

//! The Attribute Protocol (ATT) PDUs the requester exchanges with the
//! phone (Bluetooth Core Specification v5.4, Vol 3, Part F, section 3.4),
//! and nothing more.
//!
//! The requester sends the requests of the GATT client procedures it runs
//! (Vol 3, Part G, section 4), confirmations, and the answers it owes the
//! phone's own requests. Every PDU the phone sends crosses one border,
//! [`PeerPdu::decode`], into a typed value. Multi-octet fields are
//! little-endian (Vol 3, Part F, section 3.3).

use core::num::NonZeroU16;

use refineid_rapp::ble_sar::BLE_MINIMUM_ATT_MTU;

/// `ATT_ERROR_RSP` (section 3.4.1.1).
pub const OP_ERROR_RSP: u8 = 0x01;
/// `ATT_EXCHANGE_MTU_REQ` (section 3.4.2.1).
pub const OP_EXCHANGE_MTU_REQ: u8 = 0x02;
/// `ATT_EXCHANGE_MTU_RSP` (section 3.4.2.2).
pub const OP_EXCHANGE_MTU_RSP: u8 = 0x03;
/// `ATT_FIND_INFORMATION_REQ` (section 3.4.3.1).
pub const OP_FIND_INFORMATION_REQ: u8 = 0x04;
/// `ATT_FIND_INFORMATION_RSP` (section 3.4.3.2).
pub const OP_FIND_INFORMATION_RSP: u8 = 0x05;
/// `ATT_FIND_BY_TYPE_VALUE_REQ` (section 3.4.3.3).
pub const OP_FIND_BY_TYPE_VALUE_REQ: u8 = 0x06;
/// `ATT_FIND_BY_TYPE_VALUE_RSP` (section 3.4.3.4).
pub const OP_FIND_BY_TYPE_VALUE_RSP: u8 = 0x07;
/// `ATT_READ_BY_TYPE_REQ` (section 3.4.4.1).
pub const OP_READ_BY_TYPE_REQ: u8 = 0x08;
/// `ATT_READ_BY_TYPE_RSP` (section 3.4.4.2).
pub const OP_READ_BY_TYPE_RSP: u8 = 0x09;
/// `ATT_READ_RSP` (section 3.4.4.4).
pub const OP_READ_RSP: u8 = 0x0B;
/// `ATT_READ_BLOB_RSP` (section 3.4.4.6).
pub const OP_READ_BLOB_RSP: u8 = 0x0D;
/// `ATT_READ_MULTIPLE_RSP` (section 3.4.4.8).
pub const OP_READ_MULTIPLE_RSP: u8 = 0x0F;
/// `ATT_READ_BY_GROUP_TYPE_REQ` (section 3.4.4.9).
pub const OP_READ_BY_GROUP_TYPE_REQ: u8 = 0x10;
/// `ATT_READ_BY_GROUP_TYPE_RSP` (section 3.4.4.10).
pub const OP_READ_BY_GROUP_TYPE_RSP: u8 = 0x11;
/// `ATT_WRITE_REQ` (section 3.4.5.1).
pub const OP_WRITE_REQ: u8 = 0x12;
/// `ATT_WRITE_RSP` (section 3.4.5.2).
pub const OP_WRITE_RSP: u8 = 0x13;
/// `ATT_PREPARE_WRITE_RSP` (section 3.4.6.2).
pub const OP_PREPARE_WRITE_RSP: u8 = 0x17;
/// `ATT_EXECUTE_WRITE_RSP` (section 3.4.6.4).
pub const OP_EXECUTE_WRITE_RSP: u8 = 0x19;
/// `ATT_HANDLE_VALUE_NTF` (section 3.4.7.1).
pub const OP_HANDLE_VALUE_NTF: u8 = 0x1B;
/// `ATT_HANDLE_VALUE_IND` (section 3.4.7.2).
pub const OP_HANDLE_VALUE_IND: u8 = 0x1D;
/// `ATT_HANDLE_VALUE_CFM` (section 3.4.7.3).
pub const OP_HANDLE_VALUE_CFM: u8 = 0x1E;
/// `ATT_READ_MULTIPLE_VARIABLE_RSP` (section 3.4.4.12).
pub const OP_READ_MULTIPLE_VARIABLE_RSP: u8 = 0x21;
/// `ATT_MULTIPLE_HANDLE_VALUE_NTF` (section 3.4.7.4).
pub const OP_MULTIPLE_HANDLE_VALUE_NTF: u8 = 0x23;

/// The Command Flag of the opcode (section 3.3.1): a command takes no
/// response and an unsupported one is ignored.
pub const OPCODE_COMMAND_FLAG: u8 = 0x40;

/// Every response opcode, and the confirmation that answers indications
/// the requester never sends: only the requester's own transaction may
/// receive one (section 3.3.2).
const RESPONSE_OPCODES: [u8; 14] = [
    OP_ERROR_RSP,
    OP_EXCHANGE_MTU_RSP,
    OP_FIND_INFORMATION_RSP,
    OP_FIND_BY_TYPE_VALUE_RSP,
    OP_READ_BY_TYPE_RSP,
    OP_READ_RSP,
    OP_READ_BLOB_RSP,
    OP_READ_MULTIPLE_RSP,
    OP_READ_BY_GROUP_TYPE_RSP,
    OP_WRITE_RSP,
    OP_PREPARE_WRITE_RSP,
    OP_EXECUTE_WRITE_RSP,
    OP_READ_MULTIPLE_VARIABLE_RSP,
    OP_HANDLE_VALUE_CFM,
];

/// The discovery requests, whose first parameter is the starting handle
/// (sections 3.4.3.1, 3.4.3.3, 3.4.4.1, 3.4.4.9).
const DISCOVERY_REQUEST_OPCODES: [u8; 4] = [
    OP_FIND_INFORMATION_REQ,
    OP_FIND_BY_TYPE_VALUE_REQ,
    OP_READ_BY_TYPE_REQ,
    OP_READ_BY_GROUP_TYPE_REQ,
];

/// The error code `Invalid PDU` (section 3.4.1.1).
pub const ERROR_INVALID_PDU: u8 = 0x04;
/// The error code `Invalid Handle` (section 3.4.1.1).
pub const ERROR_INVALID_HANDLE: u8 = 0x01;
/// The error code `Request Not Supported` (section 3.4.1.1).
pub const ERROR_REQUEST_NOT_SUPPORTED: u8 = 0x06;
/// The error code `Attribute Not Found` (section 3.4.1.1).
pub const ERROR_ATTRIBUTE_NOT_FOUND: u8 = 0x0A;

/// The handle an error names when the request named none (section
/// 3.4.1.1).
pub const NO_HANDLE: u16 = 0x0000;
/// The lowest attribute handle; 0x0000 is reserved (section 3.2.2).
pub const FIRST_HANDLE: u16 = 0x0001;
/// The highest attribute handle (section 3.2.2).
pub const LAST_HANDLE: u16 = 0xFFFF;

/// Octets of the opcode.
const OPCODE_SIZE: usize = 1;
/// Octets of one handle or 16-bit field.
const U16_SIZE: usize = 2;
/// Octets of a 16-bit UUID.
const UUID16_SIZE: usize = 2;
/// Octets of a 128-bit UUID.
const UUID128_SIZE: usize = 16;
/// Octets of the ATT header the MTU spends before a value: opcode and
/// handle (sections 3.4.5.1 and 3.4.7.2).
pub const ATT_VALUE_HEADER_SIZE: usize = OPCODE_SIZE + U16_SIZE;
/// The longest attribute value (section 3.2.9).
pub const ATTRIBUTE_VALUE_LIMIT: usize = 512;
/// The ATT MTU the requester asks for and receives with: the longest
/// attribute value and its header (RAPP v26.11.2 section 5.2 item 1
/// asks for at least 515).
#[allow(
    clippy::cast_possible_truncation,
    reason = "515 fits a u16; the compile-time assertion below holds it"
)]
pub const REQUESTED_ATT_MTU: u16 = (ATTRIBUTE_VALUE_LIMIT + ATT_VALUE_HEADER_SIZE) as u16;
const _: () = assert!(REQUESTED_ATT_MTU as usize == ATTRIBUTE_VALUE_LIMIT + ATT_VALUE_HEADER_SIZE);

/// The Error Response length: opcode, request opcode, handle, code.
const ERROR_RSP_SIZE: usize = OPCODE_SIZE + OPCODE_SIZE + U16_SIZE + OPCODE_SIZE;
/// The Exchange MTU Response length: opcode and server Rx MTU.
const EXCHANGE_MTU_RSP_SIZE: usize = OPCODE_SIZE + U16_SIZE;
/// The Read By Group Type entry: handle, end group handle, UUID.
const GROUP_ENTRY_FIXED: usize = U16_SIZE + U16_SIZE;
/// A characteristic declaration entry of a Read By Type Response:
/// declaration handle, properties, value handle, UUID (Vol 3, Part G,
/// section 3.3.1).
const DECLARATION_ENTRY_FIXED: usize = U16_SIZE + OPCODE_SIZE + U16_SIZE;
/// The Find Information Response format of 16-bit UUIDs (section
/// 3.4.3.2).
const FORMAT_UUID16: u8 = 0x01;
/// The Find Information Response format of 128-bit UUIDs.
const FORMAT_UUID128: u8 = 0x02;

/// The GATT primary service declaration type (Vol 3, Part G, section
/// 3.1; Assigned Numbers, section 3.7).
pub const PRIMARY_SERVICE_TYPE: u16 = 0x2800;
/// The GATT characteristic declaration type (Vol 3, Part G, section
/// 3.3.1).
pub const CHARACTERISTIC_TYPE: u16 = 0x2803;
/// The Client Characteristic Configuration descriptor type (Vol 3, Part
/// G, section 3.3.3.3).
pub const CCCD_TYPE: u16 = 0x2902;
/// The CCCD value that turns indications on (Vol 3, Part G, section
/// 3.3.3.3; RAPP v26.11.2 section 5.2 item 2).
pub const CCCD_INDICATIONS: u16 = 0x0002;

/// A 128-bit UUID in its canonical (text) octet order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Uuid128([u8; UUID128_SIZE]);

/// Bits in one hex digit.
const HEX_DIGIT_BITS: u32 = 4;
/// The separator of the canonical text form.
const UUID_SEPARATOR: u8 = b'-';
/// The value of hex digit `a`.
const HEX_TEN: u8 = 10;

impl Uuid128 {
    /// The UUID written `text` in the canonical form
    /// `XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX`.
    ///
    /// # Panics
    /// On text that is not a UUID; only constant initializers call this,
    /// so the build fails instead.
    const fn parse(text: &str) -> Self {
        let bytes = text.as_bytes();
        let mut octets = [0u8; UUID128_SIZE];
        let mut filled = 0;
        let mut index = 0;
        let mut high: Option<u8> = None;
        while index < bytes.len() {
            let byte = bytes[index];
            index += 1;
            if byte == UUID_SEPARATOR {
                continue;
            }
            let digit = match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + HEX_TEN,
                b'A'..=b'F' => byte - b'A' + HEX_TEN,
                _ => panic!("not a UUID"),
            };
            match high {
                None => high = Some(digit),
                Some(upper) => {
                    assert!(filled < UUID128_SIZE, "UUID too long");
                    octets[filled] = (upper << HEX_DIGIT_BITS) | digit;
                    filled += 1;
                    high = None;
                }
            }
        }
        assert!(filled == UUID128_SIZE && high.is_none(), "UUID too short");
        Self(octets)
    }

    /// The UUID from its on-air octets, least significant first (Vol 3,
    /// Part F, section 3.2.1; Core Specification Supplement, Part A,
    /// section 1.1).
    #[must_use]
    pub const fn from_le_bytes(bytes: [u8; UUID128_SIZE]) -> Self {
        let mut octets = [0u8; UUID128_SIZE];
        let mut index = 0;
        while index < UUID128_SIZE {
            octets[index] = bytes[UUID128_SIZE - 1 - index];
            index += 1;
        }
        Self(octets)
    }

    /// The on-air octets, least significant first.
    #[must_use]
    pub const fn to_le_bytes(self) -> [u8; UUID128_SIZE] {
        Self::from_le_bytes(self.0).0
    }
}

/// The RAPP primary service (RAPP v26.11.2 section 5.1).
pub const RAPP_SERVICE_UUID: Uuid128 = Uuid128::parse(refineid_rapp::BLE_SERVICE_UUID);
/// The RAPP Channel Characteristic (RAPP v26.11.2 section 5.1).
pub const RAPP_CHANNEL_UUID: Uuid128 = Uuid128::parse("7E39FD02-A6B5-4D78-9E11-37E28E9545F1");
/// The RAPP Bootstrap Characteristic (RAPP v26.11.2 section 5.1).
pub const RAPP_BOOTSTRAP_UUID: Uuid128 = Uuid128::parse("7E39FD03-A6B5-4D78-9E11-37E28E9545F1");

/// An attribute type as the server sent it: a 16-bit alias of the
/// Bluetooth Base UUID or a full 128-bit UUID (Vol 3, Part B, section
/// 2.5.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(
    variant_size_differences,
    reason = "a UUID is 17 octets at most; boxing it would cost more than it saves"
)]
pub enum AttributeType {
    /// A 16-bit UUID.
    Short(u16),
    /// A 128-bit UUID.
    Long(Uuid128),
}

impl AttributeType {
    /// The type in `bytes`, which hold exactly one 16-bit or 128-bit UUID.
    fn decode(bytes: &[u8]) -> Result<Self, AttDecodeError> {
        if let Ok(short) = <[u8; UUID16_SIZE]>::try_from(bytes) {
            return Ok(Self::Short(u16::from_le_bytes(short)));
        }
        <[u8; UUID128_SIZE]>::try_from(bytes)
            .map(|long| Self::Long(Uuid128::from_le_bytes(long)))
            .map_err(|_| AttDecodeError::Malformed)
    }
}

/// An attribute handle: never the reserved 0x0000 (section 3.2.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct AttHandle(NonZeroU16);

impl AttHandle {
    /// The handle `value`, refused when it is the reserved 0x0000.
    #[must_use]
    pub const fn new(value: u16) -> Option<Self> {
        match NonZeroU16::new(value) {
            Some(handle) => Some(Self(handle)),
            None => None,
        }
    }

    /// The handle as the wire carries it.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0.get()
    }

    /// The handle after this one, if any.
    #[must_use]
    pub const fn next(self) -> Option<Self> {
        match self.0.checked_add(1) {
            Some(next) => Some(Self(next)),
            None => None,
        }
    }

    fn decode(bytes: [u8; U16_SIZE]) -> Result<Self, AttDecodeError> {
        Self::new(u16::from_le_bytes(bytes)).ok_or(AttDecodeError::ReservedHandle)
    }
}

/// A handle range `start..=end` with `start <= end`, as every
/// discovery request carries (section 3.4.3.1: a start above the end is
/// an invalid request).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HandleRange {
    start: AttHandle,
    end: AttHandle,
}

impl HandleRange {
    /// The range `start..=end`, or `None` when it is empty.
    #[must_use]
    pub fn new(start: AttHandle, end: AttHandle) -> Option<Self> {
        (start <= end).then_some(Self { start, end })
    }

    /// The whole handle space.
    #[must_use]
    pub const fn all() -> Self {
        match (AttHandle::new(FIRST_HANDLE), AttHandle::new(LAST_HANDLE)) {
            (Some(start), Some(end)) => Self { start, end },
            _ => unreachable!(),
        }
    }

    /// The first handle.
    #[must_use]
    pub const fn start(self) -> AttHandle {
        self.start
    }

    /// The last handle.
    #[must_use]
    pub const fn end(self) -> AttHandle {
        self.end
    }

    /// Whether `handle` lies inside.
    #[must_use]
    pub fn contains(self, handle: AttHandle) -> bool {
        self.start <= handle && handle <= self.end
    }

    /// The rest of the range after `handle`, or `None` when nothing is
    /// left.
    #[must_use]
    pub fn after(self, handle: AttHandle) -> Option<Self> {
        Self::new(handle.next()?, self.end)
    }
}

/// The ATT MTU of a connection: the smaller of the server's Rx MTU and
/// [`REQUESTED_ATT_MTU`] (section 3.4.2.2), never below the 512 bytes RAPP
/// v26.11.2 section 5.2 item 1 demands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NegotiatedMtu(u16);

impl NegotiatedMtu {
    /// The MTU the exchange settles on, or `None` below the profile
    /// minimum: the connection is then dropped.
    #[must_use]
    pub fn from_exchange(server_rx_mtu: u16) -> Option<Self> {
        let mtu = server_rx_mtu.min(REQUESTED_ATT_MTU);
        (usize::from(mtu) >= BLE_MINIMUM_ATT_MTU).then_some(Self(mtu))
    }

    /// The MTU in octets.
    #[must_use]
    pub fn octets(self) -> usize {
        usize::from(self.0)
    }
}

/// The characteristic properties octet (Vol 3, Part G, section 3.3.1.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CharacteristicProperties(u8);

/// The Read property.
pub const PROPERTY_READ: u8 = 0x02;
/// The Write property.
pub const PROPERTY_WRITE: u8 = 0x08;
/// The Indicate property.
pub const PROPERTY_INDICATE: u8 = 0x20;
/// The Extended Properties property.
pub const PROPERTY_EXTENDED: u8 = 0x80;

impl CharacteristicProperties {
    /// Whether every bit of `required` is set and no bit outside
    /// `required | permitted` is.
    #[must_use]
    pub const fn are(self, required: u8, permitted: u8) -> bool {
        self.0 & required == required && self.0 & !(required | permitted) == 0
    }
}

/// One primary service of a Read By Group Type Response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServiceGroup {
    /// The handles the service spans.
    pub range: HandleRange,
    /// The service UUID.
    pub uuid: AttributeType,
}

/// One characteristic declaration of a Read By Type Response for
/// [`CHARACTERISTIC_TYPE`] (Vol 3, Part G, section 3.3.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CharacteristicDeclaration {
    /// The declaration's own handle.
    pub declaration: AttHandle,
    /// The declared properties.
    pub properties: CharacteristicProperties,
    /// The handle of the characteristic value, above the declaration.
    pub value: AttHandle,
    /// The characteristic UUID.
    pub uuid: AttributeType,
}

/// One descriptor of a Find Information Response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DescriptorEntry {
    /// The descriptor handle.
    pub handle: AttHandle,
    /// The descriptor type.
    pub uuid: AttributeType,
}

/// The error codes the requester acts on (section 3.4.1.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttErrorCode {
    /// `Invalid PDU`.
    InvalidPdu,
    /// `Request Not Supported`.
    RequestNotSupported,
    /// `Attribute Not Found`: a discovery found nothing more.
    AttributeNotFound,
    /// Any other code; its value is never kept.
    Other,
}

impl AttErrorCode {
    const fn from_wire(code: u8) -> Self {
        match code {
            ERROR_INVALID_PDU => Self::InvalidPdu,
            ERROR_REQUEST_NOT_SUPPORTED => Self::RequestNotSupported,
            ERROR_ATTRIBUTE_NOT_FOUND => Self::AttributeNotFound,
            _ => Self::Other,
        }
    }
}

/// The error the requester answers a request of the phone's with: it
/// runs no GATT server (section 3.4.1.1; a request left unanswered stalls
/// the bearer until the 30-second transaction timeout of section 3.3.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// A valid discovery request: `Attribute Not Found` at its starting
    /// handle.
    NothingFound {
        /// The opcode of the request.
        opcode: u8,
        /// The request's starting handle.
        start: u16,
    },
    /// A discovery request whose starting handle is 0x0000 or above its
    /// ending handle: `Invalid Handle` at the starting handle (sections
    /// 3.4.3.1, 3.4.3.3, 3.4.4.1, 3.4.4.9).
    InvalidHandle {
        /// The opcode of the request.
        opcode: u8,
        /// The request's starting handle.
        start: u16,
    },
    /// A discovery request too short to carry both handles, or an MTU
    /// exchange whose parameters are not one Client Rx MTU: `Invalid PDU`.
    InvalidPdu {
        /// The opcode of the request.
        opcode: u8,
    },
    /// Every other request: `Request Not Supported`.
    NotSupported {
        /// The opcode of the request.
        opcode: u8,
    },
}

impl Refusal {
    /// The `ATT_ERROR_RSP` carrying this refusal.
    #[must_use]
    pub fn encode(self) -> Vec<u8> {
        let (opcode, handle, code) = match self {
            Self::NothingFound { opcode, start } => (opcode, start, ERROR_ATTRIBUTE_NOT_FOUND),
            Self::InvalidHandle { opcode, start } => (opcode, start, ERROR_INVALID_HANDLE),
            Self::InvalidPdu { opcode } => (opcode, NO_HANDLE, ERROR_INVALID_PDU),
            Self::NotSupported { opcode } => (opcode, NO_HANDLE, ERROR_REQUEST_NOT_SUPPORTED),
        };
        let mut pdu = Vec::with_capacity(ERROR_RSP_SIZE);
        pdu.push(OP_ERROR_RSP);
        pdu.push(opcode);
        pdu.extend_from_slice(&handle.to_le_bytes());
        pdu.push(code);
        pdu
    }
}

/// One PDU the phone sent, typed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PeerPdu {
    /// `ATT_ERROR_RSP` to the request with `request_opcode`.
    ErrorResponse {
        /// The opcode of the request that failed.
        request_opcode: u8,
        /// Why it failed.
        code: AttErrorCode,
    },
    /// `ATT_EXCHANGE_MTU_RSP`.
    ExchangeMtuResponse {
        /// The server's Rx MTU.
        server_rx_mtu: u16,
    },
    /// `ATT_READ_BY_GROUP_TYPE_RSP`.
    ReadByGroupTypeResponse(Vec<ServiceGroup>),
    /// `ATT_READ_BY_TYPE_RSP`, read as characteristic declarations: the
    /// only type the requester reads by.
    ReadByTypeResponse(Vec<CharacteristicDeclaration>),
    /// `ATT_FIND_INFORMATION_RSP`.
    FindInformationResponse(Vec<DescriptorEntry>),
    /// `ATT_WRITE_RSP`.
    WriteResponse,
    /// A response to no request the requester sends.
    OtherResponse,
    /// `ATT_HANDLE_VALUE_IND`; owed a confirmation.
    Indication {
        /// The indicated attribute.
        handle: AttHandle,
        /// The value: transit to the SAR layer or dropped.
        value: Vec<u8>,
    },
    /// A notification: carries no RAPP frame (RAPP v26.11.2 section 5.2).
    Notification,
    /// `ATT_EXCHANGE_MTU_REQ` from the phone as client, carrying exactly
    /// its Client Rx MTU (section 3.4.2.1).
    ExchangeMtuRequest,
    /// Any other request, owed this refusal at once.
    Request(Refusal),
    /// A command: never answered (section 3.3.1).
    Command,
}

/// A PDU from the phone that does not decode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttDecodeError {
    /// No octets at all.
    Empty,
    /// Longer than the requester's Rx MTU.
    Oversized,
    /// The fields do not fit the length.
    Malformed,
    /// A handle field holds the reserved 0x0000.
    ReservedHandle,
    /// A range whose end lies before its start.
    InvertedRange,
}

/// The `N` octets at `offset`, if present.
fn take<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], AttDecodeError> {
    bytes
        .get(offset..offset + N)
        .and_then(|slice| <[u8; N]>::try_from(slice).ok())
        .ok_or(AttDecodeError::Malformed)
}

impl PeerPdu {
    /// Decodes one PDU the phone sent. The requester's Rx MTU,
    /// [`REQUESTED_ATT_MTU`], bounds every PDU: the bearer's ATT MTU is
    /// never above it (section 3.4.2.2).
    ///
    /// # Errors
    /// [`AttDecodeError`] for a PDU that is empty, oversized or whose
    /// fields the specification refuses.
    pub fn decode(pdu: &[u8]) -> Result<Self, AttDecodeError> {
        let (&opcode, parameters) = pdu.split_first().ok_or(AttDecodeError::Empty)?;
        if pdu.len() > usize::from(REQUESTED_ATT_MTU) {
            return Err(AttDecodeError::Oversized);
        }
        match opcode {
            OP_ERROR_RSP => {
                if pdu.len() != ERROR_RSP_SIZE {
                    return Err(AttDecodeError::Malformed);
                }
                let [request_opcode, _, _, code]: [u8; ERROR_RSP_SIZE - OPCODE_SIZE] =
                    take(parameters, 0)?;
                Ok(Self::ErrorResponse {
                    request_opcode,
                    code: AttErrorCode::from_wire(code),
                })
            }
            OP_EXCHANGE_MTU_RSP => {
                if pdu.len() != EXCHANGE_MTU_RSP_SIZE {
                    return Err(AttDecodeError::Malformed);
                }
                Ok(Self::ExchangeMtuResponse {
                    server_rx_mtu: u16::from_le_bytes(take(parameters, 0)?),
                })
            }
            OP_READ_BY_GROUP_TYPE_RSP => decode_groups(parameters),
            OP_READ_BY_TYPE_RSP => decode_declarations(parameters),
            OP_FIND_INFORMATION_RSP => decode_descriptors(parameters),
            OP_WRITE_RSP => {
                if parameters.is_empty() {
                    Ok(Self::WriteResponse)
                } else {
                    Err(AttDecodeError::Malformed)
                }
            }
            OP_HANDLE_VALUE_IND => Ok(Self::Indication {
                handle: AttHandle::decode(take(parameters, 0)?)?,
                value: parameters[U16_SIZE..].to_vec(),
            }),
            OP_HANDLE_VALUE_NTF | OP_MULTIPLE_HANDLE_VALUE_NTF => Ok(Self::Notification),
            OP_EXCHANGE_MTU_REQ => Ok(if parameters.len() == U16_SIZE {
                Self::ExchangeMtuRequest
            } else {
                Self::Request(Refusal::InvalidPdu { opcode })
            }),
            _ if opcode & OPCODE_COMMAND_FLAG != 0 => Ok(Self::Command),
            _ if RESPONSE_OPCODES.contains(&opcode) => Ok(Self::OtherResponse),
            _ if DISCOVERY_REQUEST_OPCODES.contains(&opcode) => {
                Ok(Self::Request(discovery_refusal(opcode, parameters)))
            }
            _ => Ok(Self::Request(Refusal::NotSupported { opcode })),
        }
    }
}

/// The refusal of a discovery request: its Starting Handle and Ending
/// Handle lead the parameters (sections 3.4.3.1, 3.4.3.3, 3.4.4.1,
/// 3.4.4.9).
fn discovery_refusal(opcode: u8, parameters: &[u8]) -> Refusal {
    match (
        take::<U16_SIZE>(parameters, 0),
        take::<U16_SIZE>(parameters, U16_SIZE),
    ) {
        (Ok(start), Ok(end)) => {
            let (start, end) = (u16::from_le_bytes(start), u16::from_le_bytes(end));
            if start == NO_HANDLE || start > end {
                Refusal::InvalidHandle { opcode, start }
            } else {
                Refusal::NothingFound { opcode, start }
            }
        }
        _ => Refusal::InvalidPdu { opcode },
    }
}

/// The entries of a response list: `[length][entry; n]`, `n >= 1`, every
/// entry `length` octets.
fn entries(parameters: &[u8]) -> Result<core::slice::ChunksExact<'_, u8>, AttDecodeError> {
    let (&length, list) = parameters.split_first().ok_or(AttDecodeError::Malformed)?;
    let length = usize::from(length);
    if length == 0 || list.is_empty() || list.len() % length != 0 {
        return Err(AttDecodeError::Malformed);
    }
    Ok(list.chunks_exact(length))
}

/// A Read By Group Type Response (section 3.4.4.10).
fn decode_groups(parameters: &[u8]) -> Result<PeerPdu, AttDecodeError> {
    entries(parameters)?
        .map(|entry| {
            let start = AttHandle::decode(take(entry, 0)?)?;
            let end = AttHandle::decode(take(entry, U16_SIZE)?)?;
            Ok(ServiceGroup {
                range: HandleRange::new(start, end).ok_or(AttDecodeError::InvertedRange)?,
                uuid: AttributeType::decode(&entry[GROUP_ENTRY_FIXED..])?,
            })
        })
        .collect::<Result<_, _>>()
        .map(PeerPdu::ReadByGroupTypeResponse)
}

/// A Read By Type Response of characteristic declarations (section
/// 3.4.4.2; Vol 3, Part G, section 3.3.1).
fn decode_declarations(parameters: &[u8]) -> Result<PeerPdu, AttDecodeError> {
    entries(parameters)?
        .map(|entry| {
            let declaration = AttHandle::decode(take(entry, 0)?)?;
            let [properties] = take::<OPCODE_SIZE>(entry, U16_SIZE)?;
            let value = AttHandle::decode(take(entry, U16_SIZE + OPCODE_SIZE)?)?;
            if value <= declaration {
                return Err(AttDecodeError::InvertedRange);
            }
            Ok(CharacteristicDeclaration {
                declaration,
                properties: CharacteristicProperties(properties),
                value,
                uuid: AttributeType::decode(&entry[DECLARATION_ENTRY_FIXED..])?,
            })
        })
        .collect::<Result<_, _>>()
        .map(PeerPdu::ReadByTypeResponse)
}

/// A Find Information Response (section 3.4.3.2).
fn decode_descriptors(parameters: &[u8]) -> Result<PeerPdu, AttDecodeError> {
    let (&format, list) = parameters.split_first().ok_or(AttDecodeError::Malformed)?;
    let uuid_size = match format {
        FORMAT_UUID16 => UUID16_SIZE,
        FORMAT_UUID128 => UUID128_SIZE,
        _ => return Err(AttDecodeError::Malformed),
    };
    let length = U16_SIZE + uuid_size;
    if list.is_empty() || list.len() % length != 0 {
        return Err(AttDecodeError::Malformed);
    }
    list.chunks_exact(length)
        .map(|entry| {
            Ok(DescriptorEntry {
                handle: AttHandle::decode(take(entry, 0)?)?,
                uuid: AttributeType::decode(&entry[U16_SIZE..])?,
            })
        })
        .collect::<Result<_, _>>()
        .map(PeerPdu::FindInformationResponse)
}

/// `ATT_EXCHANGE_MTU_REQ` with the requester's Rx MTU.
#[must_use]
pub fn exchange_mtu_request() -> Vec<u8> {
    let mut pdu = vec![OP_EXCHANGE_MTU_REQ];
    pdu.extend_from_slice(&REQUESTED_ATT_MTU.to_le_bytes());
    pdu
}

/// `ATT_EXCHANGE_MTU_RSP` for the phone's own exchange, carrying
/// [`REQUESTED_ATT_MTU`], the value the requester's own request carries:
/// a device that is client and server at once uses the same value for
/// Client Rx MTU and Server Rx MTU (section 3.4.2).
#[must_use]
pub fn exchange_mtu_response() -> Vec<u8> {
    let mut pdu = vec![OP_EXCHANGE_MTU_RSP];
    pdu.extend_from_slice(&REQUESTED_ATT_MTU.to_le_bytes());
    pdu
}

/// A discovery request: opcode, the range, and a 16-bit type.
fn ranged_request(opcode: u8, range: HandleRange, attribute_type: Option<u16>) -> Vec<u8> {
    let mut pdu = vec![opcode];
    pdu.extend_from_slice(&range.start.get().to_le_bytes());
    pdu.extend_from_slice(&range.end.get().to_le_bytes());
    if let Some(attribute_type) = attribute_type {
        pdu.extend_from_slice(&attribute_type.to_le_bytes());
    }
    pdu
}

/// `ATT_READ_BY_GROUP_TYPE_REQ` for `group_type` over `range`.
#[must_use]
pub fn read_by_group_type_request(range: HandleRange, group_type: u16) -> Vec<u8> {
    ranged_request(OP_READ_BY_GROUP_TYPE_REQ, range, Some(group_type))
}

/// `ATT_READ_BY_TYPE_REQ` for `attribute_type` over `range`.
#[must_use]
pub fn read_by_type_request(range: HandleRange, attribute_type: u16) -> Vec<u8> {
    ranged_request(OP_READ_BY_TYPE_REQ, range, Some(attribute_type))
}

/// `ATT_FIND_INFORMATION_REQ` over `range`.
#[must_use]
pub fn find_information_request(range: HandleRange) -> Vec<u8> {
    ranged_request(OP_FIND_INFORMATION_REQ, range, None)
}

/// `ATT_WRITE_REQ` of `value` to `handle`; the caller bounds `value` by
/// the negotiated MTU.
#[must_use]
pub fn write_request(handle: AttHandle, value: &[u8]) -> Vec<u8> {
    let mut pdu = Vec::with_capacity(ATT_VALUE_HEADER_SIZE + value.len());
    pdu.push(OP_WRITE_REQ);
    pdu.extend_from_slice(&handle.get().to_le_bytes());
    pdu.extend_from_slice(value);
    pdu
}

/// `ATT_HANDLE_VALUE_CFM`.
#[must_use]
pub fn handle_value_confirmation() -> Vec<u8> {
    vec![OP_HANDLE_VALUE_CFM]
}

/// The PDUs a phone sends, assembled from the same constants the decoder
/// reads, for the tests of this module tree.
#[cfg(test)]
pub(crate) mod fixtures {
    use super::{
        AttHandle, FORMAT_UUID16, FORMAT_UUID128, OP_ERROR_RSP, OP_EXCHANGE_MTU_RSP,
        OP_FIND_INFORMATION_RSP, OP_HANDLE_VALUE_IND, OP_READ_BY_GROUP_TYPE_RSP,
        OP_READ_BY_TYPE_RSP, OP_WRITE_RSP, OPCODE_SIZE, U16_SIZE, Uuid128,
    };

    /// A UUID as a phone writes it in a PDU.
    #[derive(Clone, Copy, Debug)]
    #[allow(variant_size_differences, reason = "a test fixture")]
    pub(crate) enum Wire {
        Short(u16),
        Long(Uuid128),
    }

    impl Wire {
        fn bytes(self) -> Vec<u8> {
            match self {
                Self::Short(short) => short.to_le_bytes().to_vec(),
                Self::Long(long) => long.to_le_bytes().to_vec(),
            }
        }
    }

    /// A handle for a fixture.
    pub(crate) fn handle(value: u16) -> AttHandle {
        AttHandle::new(value).expect("a fixture handle is never zero")
    }

    fn length_of(entry: &[u8]) -> u8 {
        u8::try_from(entry.len()).expect("a fixture entry fits a length octet")
    }

    pub(crate) fn error_response(request_opcode: u8, handle: u16, code: u8) -> Vec<u8> {
        let mut pdu = vec![OP_ERROR_RSP, request_opcode];
        pdu.extend_from_slice(&handle.to_le_bytes());
        pdu.push(code);
        pdu
    }

    pub(crate) fn exchange_mtu_response(server_rx_mtu: u16) -> Vec<u8> {
        let mut pdu = vec![OP_EXCHANGE_MTU_RSP];
        pdu.extend_from_slice(&server_rx_mtu.to_le_bytes());
        pdu
    }

    pub(crate) fn read_by_group_type_response(groups: &[(u16, u16, Wire)]) -> Vec<u8> {
        let entries: Vec<Vec<u8>> = groups
            .iter()
            .map(|(start, end, uuid)| {
                let mut entry = start.to_le_bytes().to_vec();
                entry.extend_from_slice(&end.to_le_bytes());
                entry.extend_from_slice(&uuid.bytes());
                entry
            })
            .collect();
        listed(OP_READ_BY_GROUP_TYPE_RSP, &entries)
    }

    pub(crate) fn read_by_type_response(declarations: &[(u16, u8, u16, Wire)]) -> Vec<u8> {
        let entries: Vec<Vec<u8>> = declarations
            .iter()
            .map(|(declaration, properties, value, uuid)| {
                let mut entry = declaration.to_le_bytes().to_vec();
                entry.push(*properties);
                entry.extend_from_slice(&value.to_le_bytes());
                entry.extend_from_slice(&uuid.bytes());
                entry
            })
            .collect();
        listed(OP_READ_BY_TYPE_RSP, &entries)
    }

    fn listed(opcode: u8, entries: &[Vec<u8>]) -> Vec<u8> {
        let mut pdu = vec![opcode, length_of(&entries[0])];
        for entry in entries {
            pdu.extend_from_slice(entry);
        }
        pdu
    }

    pub(crate) fn find_information_response(descriptors: &[(u16, Wire)]) -> Vec<u8> {
        let format = match descriptors[0].1 {
            Wire::Short(_) => FORMAT_UUID16,
            Wire::Long(_) => FORMAT_UUID128,
        };
        let mut pdu = vec![OP_FIND_INFORMATION_RSP, format];
        for (handle, uuid) in descriptors {
            pdu.extend_from_slice(&handle.to_le_bytes());
            pdu.extend_from_slice(&uuid.bytes());
        }
        pdu
    }

    pub(crate) fn write_response() -> Vec<u8> {
        vec![OP_WRITE_RSP]
    }

    pub(crate) fn indication(handle: u16, value: &[u8]) -> Vec<u8> {
        let mut pdu = Vec::with_capacity(OPCODE_SIZE + U16_SIZE + value.len());
        pdu.push(OP_HANDLE_VALUE_IND);
        pdu.extend_from_slice(&handle.to_le_bytes());
        pdu.extend_from_slice(value);
        pdu
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "test fixtures are constructed to be infallible"
)]
mod tests {
    use super::fixtures::{self, Wire};
    use super::{
        AttDecodeError, AttErrorCode, AttributeType, CCCD_TYPE, ERROR_ATTRIBUTE_NOT_FOUND,
        ERROR_INVALID_HANDLE, ERROR_INVALID_PDU, ERROR_REQUEST_NOT_SUPPORTED, NO_HANDLE,
        NegotiatedMtu, OP_EXCHANGE_MTU_REQ, OP_FIND_INFORMATION_REQ, OP_HANDLE_VALUE_NTF,
        OP_READ_BY_GROUP_TYPE_REQ, OP_READ_BY_TYPE_REQ, OP_WRITE_REQ, OPCODE_COMMAND_FLAG,
        PROPERTY_EXTENDED, PROPERTY_INDICATE, PROPERTY_READ, PROPERTY_WRITE, PeerPdu,
        RAPP_CHANNEL_UUID, RAPP_SERVICE_UUID, REQUESTED_ATT_MTU, Refusal, Uuid128,
    };
    use refineid_rapp::ble_sar::BLE_MINIMUM_ATT_MTU;

    /// A synthetic service start handle.
    const START: u16 = 0x0010;
    /// A synthetic service end handle.
    const END: u16 = 0x0020;

    #[test]
    fn the_service_uuid_reads_back_from_its_air_order() {
        assert_eq!(
            Uuid128::from_le_bytes(RAPP_SERVICE_UUID.to_le_bytes()),
            RAPP_SERVICE_UUID
        );
        assert_ne!(RAPP_SERVICE_UUID, RAPP_CHANNEL_UUID);
    }

    #[test]
    fn the_mtu_is_the_smaller_and_never_below_the_profile_minimum() {
        let small = u16::try_from(BLE_MINIMUM_ATT_MTU - 1).unwrap();
        assert_eq!(NegotiatedMtu::from_exchange(small), None);
        assert_eq!(
            NegotiatedMtu::from_exchange(u16::MAX).map(NegotiatedMtu::octets),
            Some(usize::from(REQUESTED_ATT_MTU))
        );
    }

    #[test]
    fn a_group_response_decodes_and_a_reversed_range_is_refused() {
        let pdu =
            fixtures::read_by_group_type_response(&[(START, END, Wire::Long(RAPP_SERVICE_UUID))]);
        let PeerPdu::ReadByGroupTypeResponse(groups) = PeerPdu::decode(&pdu).unwrap() else {
            unreachable!("a group response")
        };
        assert_eq!(groups[0].uuid, AttributeType::Long(RAPP_SERVICE_UUID));
        let reversed =
            fixtures::read_by_group_type_response(&[(END, START, Wire::Long(RAPP_SERVICE_UUID))]);
        assert_eq!(
            PeerPdu::decode(&reversed),
            Err(AttDecodeError::InvertedRange)
        );
    }

    #[test]
    fn truncated_and_empty_pdus_are_refused() {
        assert_eq!(PeerPdu::decode(&[]), Err(AttDecodeError::Empty));
        let mut pdu =
            fixtures::read_by_group_type_response(&[(START, END, Wire::Long(RAPP_SERVICE_UUID))]);
        pdu.pop();
        assert_eq!(PeerPdu::decode(&pdu), Err(AttDecodeError::Malformed));
        let mut error = fixtures::error_response(OP_WRITE_REQ, START, ERROR_ATTRIBUTE_NOT_FOUND);
        error.pop();
        assert_eq!(PeerPdu::decode(&error), Err(AttDecodeError::Malformed));
        let indication = fixtures::indication(NO_HANDLE, b"x");
        assert_eq!(
            PeerPdu::decode(&indication),
            Err(AttDecodeError::ReservedHandle)
        );
        let oversized = fixtures::indication(START, &vec![0; usize::from(REQUESTED_ATT_MTU)]);
        assert_eq!(PeerPdu::decode(&oversized), Err(AttDecodeError::Oversized));
    }

    #[test]
    fn peer_requests_are_refused_by_kind_and_commands_ignored() {
        let discovery = super::read_by_group_type_request(super::HandleRange::all(), CCCD_TYPE);
        let Ok(PeerPdu::Request(refusal)) = PeerPdu::decode(&discovery) else {
            unreachable!("a request")
        };
        assert_eq!(
            refusal.encode(),
            fixtures::error_response(
                OP_READ_BY_GROUP_TYPE_REQ,
                super::FIRST_HANDLE,
                ERROR_ATTRIBUTE_NOT_FOUND
            )
        );
        let write = super::write_request(fixtures::handle(START), b"x");
        assert_eq!(
            PeerPdu::decode(&write),
            Ok(PeerPdu::Request(Refusal::NotSupported {
                opcode: OP_WRITE_REQ
            }))
        );
        assert_eq!(
            Refusal::NotSupported {
                opcode: OP_WRITE_REQ
            }
            .encode(),
            fixtures::error_response(OP_WRITE_REQ, NO_HANDLE, ERROR_REQUEST_NOT_SUPPORTED)
        );
        assert_eq!(
            PeerPdu::decode(&[OP_FIND_INFORMATION_REQ]),
            Ok(PeerPdu::Request(Refusal::InvalidPdu {
                opcode: OP_FIND_INFORMATION_REQ
            }))
        );
        assert_eq!(
            PeerPdu::decode(&[OP_WRITE_REQ | OPCODE_COMMAND_FLAG]),
            Ok(PeerPdu::Command)
        );
        assert_eq!(
            PeerPdu::decode(&[OP_HANDLE_VALUE_NTF]),
            Ok(PeerPdu::Notification)
        );
    }

    #[test]
    fn the_phones_mtu_exchange_is_answered_with_our_rx_mtu_or_refused() {
        let mut request = vec![OP_EXCHANGE_MTU_REQ];
        request.extend_from_slice(&REQUESTED_ATT_MTU.to_le_bytes());
        assert_eq!(PeerPdu::decode(&request), Ok(PeerPdu::ExchangeMtuRequest));
        assert_eq!(
            super::exchange_mtu_response(),
            fixtures::exchange_mtu_response(REQUESTED_ATT_MTU)
        );
        for malformed in [
            &request[..request.len() - 1],
            &[request.as_slice(), b"x"].concat(),
        ] {
            let Ok(PeerPdu::Request(refusal)) = PeerPdu::decode(malformed) else {
                unreachable!("a refused request")
            };
            assert_eq!(
                refusal.encode(),
                fixtures::error_response(OP_EXCHANGE_MTU_REQ, NO_HANDLE, ERROR_INVALID_PDU)
            );
        }
    }

    #[test]
    fn discovery_handles_are_validated_before_nothing_is_found() {
        let refusal = |start: u16, end: u16| {
            let mut request = vec![OP_READ_BY_TYPE_REQ];
            request.extend_from_slice(&start.to_le_bytes());
            request.extend_from_slice(&end.to_le_bytes());
            request.extend_from_slice(&CCCD_TYPE.to_le_bytes());
            let Ok(PeerPdu::Request(refusal)) = PeerPdu::decode(&request) else {
                unreachable!("a refused request")
            };
            refusal.encode()
        };
        assert_eq!(
            refusal(START, END),
            fixtures::error_response(OP_READ_BY_TYPE_REQ, START, ERROR_ATTRIBUTE_NOT_FOUND)
        );
        assert_eq!(
            refusal(END, START),
            fixtures::error_response(OP_READ_BY_TYPE_REQ, END, ERROR_INVALID_HANDLE)
        );
        assert_eq!(
            refusal(NO_HANDLE, END),
            fixtures::error_response(OP_READ_BY_TYPE_REQ, NO_HANDLE, ERROR_INVALID_HANDLE)
        );
        let mut short = vec![OP_READ_BY_TYPE_REQ];
        short.extend_from_slice(&START.to_le_bytes());
        let Ok(PeerPdu::Request(refusal)) = PeerPdu::decode(&short) else {
            unreachable!("a refused request")
        };
        assert_eq!(
            refusal.encode(),
            fixtures::error_response(OP_READ_BY_TYPE_REQ, NO_HANDLE, ERROR_INVALID_PDU)
        );
    }

    #[test]
    fn an_error_response_keeps_only_a_known_code() {
        let pdu = fixtures::error_response(OP_WRITE_REQ, START, ERROR_ATTRIBUTE_NOT_FOUND);
        assert_eq!(
            PeerPdu::decode(&pdu),
            Ok(PeerPdu::ErrorResponse {
                request_opcode: OP_WRITE_REQ,
                code: AttErrorCode::AttributeNotFound
            })
        );
    }

    #[test]
    fn properties_require_and_permit() {
        let channel = super::CharacteristicProperties(PROPERTY_WRITE | PROPERTY_INDICATE);
        assert!(channel.are(PROPERTY_WRITE | PROPERTY_INDICATE, PROPERTY_EXTENDED));
        let extended =
            super::CharacteristicProperties(PROPERTY_WRITE | PROPERTY_INDICATE | PROPERTY_EXTENDED);
        assert!(extended.are(PROPERTY_WRITE | PROPERTY_INDICATE, PROPERTY_EXTENDED));
        let readable =
            super::CharacteristicProperties(PROPERTY_WRITE | PROPERTY_INDICATE | PROPERTY_READ);
        assert!(!readable.are(PROPERTY_WRITE | PROPERTY_INDICATE, PROPERTY_EXTENDED));
        assert!(
            !super::CharacteristicProperties(PROPERTY_WRITE)
                .are(PROPERTY_WRITE | PROPERTY_INDICATE, PROPERTY_EXTENDED)
        );
    }
}
