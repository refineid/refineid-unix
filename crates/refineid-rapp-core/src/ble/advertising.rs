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

//! The LE Advertising Report event (Bluetooth Core Specification v5.4,
//! Vol 4, Part E, section 7.7.65.2) and the advertising data it carries
//! (Vol 3, Part C, section 11; Core Specification Supplement, Part A,
//! section 1.1), read for the RAPP service UUID.
//!
//! A phone advertises only the service UUID and at most the generic name
//! `RefineID`, from a rotating private address (RAPP v26.11.8 section
//! 4.1). With active scanning the UUID may come in the scan response
//! instead (observed: iOS puts it in the advertising data, Android too,
//! and neither needs a scan response). An address is never kept beyond
//! the scan that saw it, and its value never reaches a log.

use core::fmt;

use super::att::RAPP_SERVICE_UUID;

/// Octets of a device address (Vol 2, Part B, section 1.3).
pub const BD_ADDR_SIZE: usize = 6;
/// The fewest reports one event carries (section 7.7.65.2).
const MIN_REPORTS: u8 = 0x01;
/// The most reports one event carries.
const MAX_REPORTS: u8 = 0x19;
/// The longest legacy advertising or scan response data (section
/// 7.7.65.2, `Data_Length`).
const ADVERTISING_DATA_LIMIT: usize = 31;

/// `Event_Type` `ADV_IND`: connectable and scannable undirected.
const EVENT_ADV_IND: u8 = 0x00;
/// `Event_Type` `ADV_DIRECT_IND`: connectable directed.
const EVENT_ADV_DIRECT_IND: u8 = 0x01;
/// `Event_Type` `ADV_SCAN_IND`: scannable undirected.
const EVENT_ADV_SCAN_IND: u8 = 0x02;
/// `Event_Type` `ADV_NONCONN_IND`: non-connectable undirected.
const EVENT_ADV_NONCONN_IND: u8 = 0x03;
/// `Event_Type` `SCAN_RSP`.
const EVENT_SCAN_RSP: u8 = 0x04;

/// `Address_Type` Public Device Address.
const ADDRESS_PUBLIC: u8 = 0x00;
/// `Address_Type` Random Device Address.
const ADDRESS_RANDOM: u8 = 0x01;
/// `Address_Type` Public Identity Address, resolved by the controller.
const ADDRESS_PUBLIC_IDENTITY: u8 = 0x02;
/// `Address_Type` Random (static) Identity Address, resolved by the
/// controller.
const ADDRESS_RANDOM_IDENTITY: u8 = 0x03;

/// The weakest RSSI a report carries, in dBm (section 7.7.65.2).
const RSSI_MIN: i8 = -127;
/// The strongest RSSI a report carries, in dBm.
const RSSI_MAX: i8 = 20;

/// AD type Incomplete List of 128-bit Service Class UUIDs (Supplement,
/// Part A, section 1.1; Assigned Numbers, section 2.3).
const AD_INCOMPLETE_UUID128_LIST: u8 = 0x06;
/// AD type Complete List of 128-bit Service Class UUIDs.
const AD_COMPLETE_UUID128_LIST: u8 = 0x07;
/// Octets of one 128-bit UUID in a list.
const UUID128_SIZE: usize = 16;

/// A device address in its on-air octet order, least significant first.
/// Its value is never formatted.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct BdAddr([u8; BD_ADDR_SIZE]);

impl BdAddr {
    /// The on-air octets, for the connect call.
    #[must_use]
    pub const fn octets(self) -> [u8; BD_ADDR_SIZE] {
        self.0
    }
}

impl fmt::Debug for BdAddr {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BdAddr(..)")
    }
}

/// The address type an LE connection names its peer by.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeAddressType {
    /// A public device address, or a public identity address.
    Public,
    /// A random device address (such as a resolvable private address), or
    /// a random static identity address.
    Random,
}

/// What an advertising event allows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdvertisingEvent {
    /// `ADV_IND` or `ADV_DIRECT_IND`: the advertiser accepts a connection.
    Connectable,
    /// `ADV_SCAN_IND` or `ADV_NONCONN_IND`: it does not.
    NotConnectable,
    /// `SCAN_RSP`: the answer to an active scan's request.
    ScanResponse,
}

/// A received signal strength in dBm, within the range of section
/// 7.7.65.2.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Rssi(i8);

impl Rssi {
    /// The RSSI of a report, or `None` when the controller had none
    /// (127) or the value lies outside the range.
    #[must_use]
    pub fn from_report(value: i8) -> Option<Self> {
        (RSSI_MIN..=RSSI_MAX)
            .contains(&value)
            .then_some(Self(value))
    }
}

/// One report of an LE Advertising Report event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdvertisingReport {
    /// The advertiser's address.
    pub address: BdAddr,
    /// How it is named.
    pub address_type: LeAddressType,
    /// The kind of event.
    pub event: AdvertisingEvent,
    /// The signal strength, when the controller measured one.
    pub rssi: Option<Rssi>,
    /// Whether a 128-bit service UUID list names the RAPP service.
    pub carries_rapp_service: bool,
}

/// An LE Advertising Report event the requester refuses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdvertisingError {
    /// The report count is outside 1 to 25.
    ReportCount,
    /// The fields do not fit the length.
    Truncated,
    /// Octets follow the last report.
    TrailingOctets,
    /// An unknown event type.
    EventType,
    /// An unknown address type.
    AddressType,
    /// Advertising data longer than 31 octets.
    DataLength,
    /// An AD structure runs past the data, or a UUID list is not a whole
    /// number of UUIDs.
    AdStructure,
}

/// A cursor over event parameters.
struct Cursor<'a> {
    bytes: &'a [u8],
}

impl<'a> Cursor<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], AdvertisingError> {
        if self.bytes.len() < count {
            return Err(AdvertisingError::Truncated);
        }
        let (taken, rest) = self.bytes.split_at(count);
        self.bytes = rest;
        Ok(taken)
    }

    fn octet(&mut self) -> Result<u8, AdvertisingError> {
        self.take(1).map(|taken| taken[0])
    }
}

/// The reports of one LE Advertising Report event; `parameters` follow
/// the subevent code.
///
/// The reports lie one after another, each `Event_Type`, `Address_Type`,
/// `Address`, `Data_Length`, `Data` and `RSSI`, as FreeBSD's
/// `ng_hci_le_advreport` and `hccontrol` read them; with one report per
/// event, the usual case, every reading of section 7.7.65.2 agrees.
///
/// # Errors
/// [`AdvertisingError`] for an event whose fields the specification
/// refuses.
pub fn decode_reports(parameters: &[u8]) -> Result<Vec<AdvertisingReport>, AdvertisingError> {
    let mut cursor = Cursor { bytes: parameters };
    let count = cursor.octet()?;
    if !(MIN_REPORTS..=MAX_REPORTS).contains(&count) {
        return Err(AdvertisingError::ReportCount);
    }
    let mut reports = Vec::with_capacity(usize::from(count));
    for _ in 0..count {
        let event = match cursor.octet()? {
            EVENT_ADV_IND | EVENT_ADV_DIRECT_IND => AdvertisingEvent::Connectable,
            EVENT_ADV_SCAN_IND | EVENT_ADV_NONCONN_IND => AdvertisingEvent::NotConnectable,
            EVENT_SCAN_RSP => AdvertisingEvent::ScanResponse,
            _ => return Err(AdvertisingError::EventType),
        };
        let address_type = match cursor.octet()? {
            ADDRESS_PUBLIC | ADDRESS_PUBLIC_IDENTITY => LeAddressType::Public,
            ADDRESS_RANDOM | ADDRESS_RANDOM_IDENTITY => LeAddressType::Random,
            _ => return Err(AdvertisingError::AddressType),
        };
        let address = BdAddr(
            <[u8; BD_ADDR_SIZE]>::try_from(cursor.take(BD_ADDR_SIZE)?)
                .map_err(|_| AdvertisingError::Truncated)?,
        );
        let length = usize::from(cursor.octet()?);
        if length > ADVERTISING_DATA_LIMIT {
            return Err(AdvertisingError::DataLength);
        }
        let carries_rapp_service = names_rapp_service(cursor.take(length)?)?;
        let rssi = Rssi::from_report(i8::from_le_bytes([cursor.octet()?]));
        reports.push(AdvertisingReport {
            address,
            address_type,
            event,
            rssi,
            carries_rapp_service,
        });
    }
    if !cursor.bytes.is_empty() {
        return Err(AdvertisingError::TrailingOctets);
    }
    Ok(reports)
}

/// Whether the AD structures in `data` list the RAPP service UUID. Each
/// structure is a length octet and that many octets of AD type and data;
/// a zero length ends the data early (Vol 3, Part C, section 11).
fn names_rapp_service(data: &[u8]) -> Result<bool, AdvertisingError> {
    let wanted = RAPP_SERVICE_UUID.to_le_bytes();
    let mut cursor = Cursor { bytes: data };
    let mut found = false;
    while !cursor.bytes.is_empty() {
        let length = usize::from(cursor.octet()?);
        if length == 0 {
            break;
        }
        let structure = cursor
            .take(length)
            .map_err(|_| AdvertisingError::AdStructure)?;
        let (&ad_type, ad_data) = structure
            .split_first()
            .ok_or(AdvertisingError::AdStructure)?;
        if ad_type == AD_INCOMPLETE_UUID128_LIST || ad_type == AD_COMPLETE_UUID128_LIST {
            if ad_data.len() % UUID128_SIZE != 0 {
                return Err(AdvertisingError::AdStructure);
            }
            found |= ad_data
                .chunks_exact(UUID128_SIZE)
                .any(|uuid| uuid == wanted.as_slice());
        }
    }
    Ok(found)
}

/// A RAPP advertiser seen in one scan: connectable, with the service UUID
/// in its advertising data or scan response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RappAdvertiser {
    address: BdAddr,
    address_type: LeAddressType,
    rssi: Option<Rssi>,
}

impl RappAdvertiser {
    /// The address to connect to.
    #[must_use]
    pub const fn address(&self) -> BdAddr {
        self.address
    }

    /// How the address is named.
    #[must_use]
    pub const fn address_type(&self) -> LeAddressType {
        self.address_type
    }
}

/// What one scan heard from one address.
#[derive(Debug)]
struct Heard {
    address: BdAddr,
    address_type: LeAddressType,
    connectable: bool,
    rapp: bool,
    rssi: Option<Rssi>,
}

/// The advertisers one scan heard, folded by address.
#[derive(Debug, Default)]
pub struct RappAdvertisers {
    heard: Vec<Heard>,
}

/// The most addresses one scan remembers; a crowded room beyond it adds
/// nothing a phone in reach needs.
const HEARD_LIMIT: usize = 256;

impl RappAdvertisers {
    /// Notes one report.
    pub fn note(&mut self, report: &AdvertisingReport) {
        let connectable = report.event == AdvertisingEvent::Connectable;
        if let Some(heard) = self.heard.iter_mut().find(|heard| {
            heard.address == report.address && heard.address_type == report.address_type
        }) {
            heard.connectable |= connectable;
            heard.rapp |= report.carries_rapp_service;
            heard.rssi = heard.rssi.max(report.rssi);
        } else if self.heard.len() < HEARD_LIMIT {
            self.heard.push(Heard {
                address: report.address,
                address_type: report.address_type,
                connectable,
                rapp: report.carries_rapp_service,
                rssi: report.rssi,
            });
        }
    }

    /// The connectable RAPP advertisers, strongest first; one without an
    /// RSSI comes last.
    #[must_use]
    pub fn strongest_first(self) -> Vec<RappAdvertiser> {
        let mut advertisers: Vec<RappAdvertiser> = self
            .heard
            .into_iter()
            .filter(|heard| heard.connectable && heard.rapp)
            .map(|heard| RappAdvertiser {
                address: heard.address,
                address_type: heard.address_type,
                rssi: heard.rssi,
            })
            .collect();
        advertisers.sort_by_key(|advertiser| core::cmp::Reverse(advertiser.rssi));
        advertisers
    }
}

/// The parts of a report an advertiser sends, for the tests of this
/// module tree.
#[cfg(test)]
pub(crate) mod fixtures {
    use super::{
        AD_COMPLETE_UUID128_LIST, ADDRESS_RANDOM, BD_ADDR_SIZE, EVENT_ADV_IND, EVENT_SCAN_RSP,
        RAPP_SERVICE_UUID,
    };
    use crate::ble::att::Uuid128;

    /// AD type Flags (Supplement, Part A, section 1.3).
    pub(crate) const AD_FLAGS: u8 = 0x01;
    /// Flags LE General Discoverable Mode and BR/EDR Not Supported.
    pub(crate) const FLAGS_GENERAL_LE_ONLY: u8 = 0x06;
    /// AD type Complete Local Name (Supplement, Part A, section 1.2).
    pub(crate) const AD_COMPLETE_LOCAL_NAME: u8 = 0x09;
    /// The generic name of RAPP v26.11.8 section 4.1.
    pub(crate) const GENERIC_NAME: &[u8] = b"RefineID";
    pub(crate) const EVENT_CONNECTABLE: u8 = EVENT_ADV_IND;
    pub(crate) const EVENT_SCAN_RESPONSE: u8 = EVENT_SCAN_RSP;
    pub(crate) const ADDRESS_TYPE_RANDOM: u8 = ADDRESS_RANDOM;

    /// The on-air octets of the synthetic address written `text`
    /// (`02:00:00:00:00:01` form).
    pub(crate) fn address(text: &str) -> [u8; BD_ADDR_SIZE] {
        let mut octets = [0u8; BD_ADDR_SIZE];
        for (slot, part) in octets.iter_mut().rev().zip(text.split(':')) {
            *slot = u8::from_str_radix(part, 16).expect("a synthetic address");
        }
        octets
    }

    /// One AD structure.
    pub(crate) fn ad(ad_type: u8, data: &[u8]) -> Vec<u8> {
        let mut structure = vec![u8::try_from(data.len() + 1).expect("fits"), ad_type];
        structure.extend_from_slice(data);
        structure
    }

    /// The advertising data of an iOS phone: flags, the service UUID and
    /// the generic name.
    pub(crate) fn phone_data(uuid: Uuid128) -> Vec<u8> {
        let mut data = ad(AD_FLAGS, &[FLAGS_GENERAL_LE_ONLY]);
        data.extend(ad(AD_COMPLETE_UUID128_LIST, &uuid.to_le_bytes()));
        data.extend(ad(AD_COMPLETE_LOCAL_NAME, GENERIC_NAME));
        data
    }

    /// The RAPP phone's data.
    pub(crate) fn rapp_data() -> Vec<u8> {
        phone_data(RAPP_SERVICE_UUID)
    }

    /// One report.
    pub(crate) fn report(
        event: u8,
        address_type: u8,
        address: [u8; BD_ADDR_SIZE],
        data: &[u8],
        rssi: i8,
    ) -> Vec<u8> {
        let mut bytes = vec![event, address_type];
        bytes.extend_from_slice(&address);
        bytes.push(u8::try_from(data.len()).expect("fits"));
        bytes.extend_from_slice(data);
        bytes.extend_from_slice(&rssi.to_le_bytes());
        bytes
    }

    /// The parameters after the subevent code of an event carrying
    /// `reports`.
    pub(crate) fn event(reports: &[Vec<u8>]) -> Vec<u8> {
        let mut bytes = vec![u8::try_from(reports.len()).expect("fits")];
        for report in reports {
            bytes.extend_from_slice(report);
        }
        bytes
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "test fixtures are constructed to be infallible"
)]
mod tests {
    use super::fixtures::{
        self, ADDRESS_TYPE_RANDOM, EVENT_CONNECTABLE, EVENT_SCAN_RESPONSE, address, report,
    };
    use super::{
        AdvertisingError, EVENT_ADV_NONCONN_IND, LeAddressType, MAX_REPORTS, RappAdvertisers,
        decode_reports,
    };
    use crate::ble::att::RAPP_CHANNEL_UUID;

    const FIRST: &str = "02:00:00:00:00:01";
    const SECOND: &str = "02:00:00:00:00:02";
    const THIRD: &str = "02:00:00:00:00:03";
    /// A weak signal, in dBm.
    const WEAK: i8 = -80;
    /// A strong signal, in dBm.
    const STRONG: i8 = -40;
    /// The value that says no RSSI was measured (section 7.7.65.2).
    const NO_RSSI: i8 = 127;

    #[test]
    fn a_phone_advertising_the_service_is_found() {
        let event = fixtures::event(&[report(
            EVENT_CONNECTABLE,
            ADDRESS_TYPE_RANDOM,
            address(FIRST),
            &fixtures::rapp_data(),
            WEAK,
        )]);
        let reports = decode_reports(&event).unwrap();
        assert!(reports[0].carries_rapp_service);
        assert_eq!(reports[0].address_type, LeAddressType::Random);
        assert_eq!(reports[0].address.octets(), address(FIRST));
    }

    #[test]
    fn another_service_is_not_a_phone() {
        let event = fixtures::event(&[report(
            EVENT_CONNECTABLE,
            ADDRESS_TYPE_RANDOM,
            address(FIRST),
            &fixtures::phone_data(RAPP_CHANNEL_UUID),
            WEAK,
        )]);
        assert!(!decode_reports(&event).unwrap()[0].carries_rapp_service);
    }

    #[test]
    fn malformed_events_are_refused() {
        let good = report(
            EVENT_CONNECTABLE,
            ADDRESS_TYPE_RANDOM,
            address(FIRST),
            &fixtures::rapp_data(),
            WEAK,
        );
        let mut truncated = fixtures::event(core::slice::from_ref(&good));
        truncated.pop();
        assert_eq!(decode_reports(&truncated), Err(AdvertisingError::Truncated));
        let mut trailing = fixtures::event(core::slice::from_ref(&good));
        trailing.extend_from_slice(b"x");
        assert_eq!(
            decode_reports(&trailing),
            Err(AdvertisingError::TrailingOctets)
        );
        assert_eq!(
            decode_reports(&fixtures::event(&[])),
            Err(AdvertisingError::ReportCount)
        );
        let mut crowded = fixtures::event(&[good]);
        crowded[0] = MAX_REPORTS + 1;
        assert_eq!(decode_reports(&crowded), Err(AdvertisingError::ReportCount));
        let mut overlong = fixtures::rapp_data();
        overlong[0] += 1;
        let event = fixtures::event(&[report(
            EVENT_CONNECTABLE,
            ADDRESS_TYPE_RANDOM,
            address(FIRST),
            &overlong[..fixtures::rapp_data().len()],
            WEAK,
        )]);
        assert_eq!(decode_reports(&event), Err(AdvertisingError::AdStructure));
        let ragged = fixtures::ad(super::AD_COMPLETE_UUID128_LIST, b"not sixteen");
        let event = fixtures::event(&[report(
            EVENT_CONNECTABLE,
            ADDRESS_TYPE_RANDOM,
            address(FIRST),
            &ragged,
            WEAK,
        )]);
        assert_eq!(decode_reports(&event), Err(AdvertisingError::AdStructure));
    }

    #[test]
    fn advertisers_come_strongest_first_and_a_scan_response_counts() {
        let mut advertisers = RappAdvertisers::default();
        let reports = decode_reports(&fixtures::event(&[
            report(
                EVENT_CONNECTABLE,
                ADDRESS_TYPE_RANDOM,
                address(FIRST),
                &fixtures::rapp_data(),
                WEAK,
            ),
            report(
                EVENT_CONNECTABLE,
                ADDRESS_TYPE_RANDOM,
                address(SECOND),
                &[],
                NO_RSSI,
            ),
            report(
                EVENT_SCAN_RESPONSE,
                ADDRESS_TYPE_RANDOM,
                address(SECOND),
                &fixtures::rapp_data(),
                STRONG,
            ),
            report(
                EVENT_ADV_NONCONN_IND,
                ADDRESS_TYPE_RANDOM,
                address(THIRD),
                &fixtures::rapp_data(),
                STRONG,
            ),
        ]))
        .unwrap();
        for report in &reports {
            advertisers.note(report);
        }
        let found: Vec<[u8; super::BD_ADDR_SIZE]> = advertisers
            .strongest_first()
            .iter()
            .map(|advertiser| advertiser.address().octets())
            .collect();
        assert_eq!(found, vec![address(SECOND), address(FIRST)]);
    }

    #[test]
    fn an_address_is_never_formatted() {
        let event = fixtures::event(&[report(
            EVENT_CONNECTABLE,
            ADDRESS_TYPE_RANDOM,
            address(FIRST),
            &fixtures::rapp_data(),
            WEAK,
        )]);
        let shown = format!("{:?}", decode_reports(&event).unwrap());
        assert!(!shown.contains(&format!("{:?}", address(FIRST))));
    }
}
