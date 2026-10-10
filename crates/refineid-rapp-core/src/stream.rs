//! The `fi.refineid.stream.v1` transport tier (RAPP transport and discovery
//! hierarchy, sections 3.3 and 4).
//!
//! The custodian (the phone) listens on an ephemeral TCP port and advertises
//! `_refineid-stream._tcp.local.` under a fresh random instance name, with a
//! TXT record naming its mode: `mode=pairing` during a pairing ceremony,
//! `mode=session` while it serves stored pairings. The requester browses by
//! those attributes, dials, and opens every connection with one plaintext
//! routing preamble. The session preamble carries the pair's rendezvous token
//! point to point; nothing derived from the token is ever published or
//! looked up by name. An anomaly closes the connection without touching
//! stored state (specification section 10.1, class 1).

use std::collections::BTreeMap;
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::time::Duration;

use crate::ids::RendezvousToken;
use crate::transport::{FrameTransport, TcpFrameTransport, TransportError};
pub use refineid_rapp::{MAX_STREAM_RENDEZVOUS_FRAME, STREAM_PROFILE, StreamRendezvous};

/// The DNS-SD service type of the stream tier.
pub const STREAM_SERVICE_TYPE: &str = "_refineid-stream._tcp.local";

/// The candidate identifier both peers bind for a stream pairing.
pub const STREAM_CANDIDATE_ID: &str = "stream-1";

/// TXT key naming the discovery mode.
const MODE_KEY: &str = "mode";
/// TXT key naming the record format version.
const VERSION_KEY: &str = "v";
/// The one TXT format version this requester understands.
const SUPPORTED_TXT_VERSION: &str = "1";

/// The custodian discovery modes of hierarchy section 4.3.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiscoveryMode {
    /// An explicit pairing ceremony is open on the custodian.
    Pairing,
    /// The custodian serves sessions for stored pairings.
    Session,
}

impl DiscoveryMode {
    /// The TXT `mode` value.
    #[must_use]
    pub const fn txt_value(self) -> &'static str {
        match self {
            Self::Pairing => "pairing",
            Self::Session => "session",
        }
    }
}

/// One advertised custodian: its instance, endpoints, and TXT attributes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamService {
    /// The advertised instance name (random; carries no identity).
    pub instance: String,
    /// `ip:port` endpoints that answered for this instance.
    pub endpoints: Vec<String>,
    /// The TXT attributes, keys lowercased.
    pub attributes: BTreeMap<String, String>,
}

impl StreamService {
    /// Whether the TXT record names format version 1 and `mode`.
    #[must_use]
    pub fn advertises(&self, mode: DiscoveryMode) -> bool {
        self.attributes.get(VERSION_KEY).map(String::as_str) == Some(SUPPORTED_TXT_VERSION)
            && self.attributes.get(MODE_KEY).map(String::as_str) == Some(mode.txt_value())
    }

    /// The rotating discovery hints the record publishes (hierarchy
    /// section 4.3), or `None` when it publishes no `hints` attribute.
    /// Entries that are not 16 lowercase hex digits are ignored.
    #[must_use]
    pub fn hints(&self) -> Option<Vec<[u8; refineid_rapp::DISCOVERY_HINT_SIZE]>> {
        let value = self.attributes.get(HINTS_KEY)?;
        Some(
            value
                .split(',')
                .take(MAX_PUBLISHED_HINTS)
                .filter_map(decode_hint)
                .collect(),
        )
    }

    /// How this record relates to the pairing whose token is `token` at
    /// `unix_seconds`: a published hint names it within one epoch either
    /// way, the record publishes no hints, or its hints name other pairings.
    #[must_use]
    pub fn hint_match(&self, token: &RendezvousToken, unix_seconds: u64) -> HintMatch {
        let Some(hints) = self.hints() else {
            return HintMatch::Unhinted;
        };
        let epoch = unix_seconds / refineid_rapp::DISCOVERY_HINT_EPOCH_SECONDS;
        let named = [epoch.saturating_sub(1), epoch, epoch.saturating_add(1)]
            .into_iter()
            .map(|candidate| refineid_rapp::discovery_hint(token, candidate))
            .any(|hint| hints.contains(&hint));
        if named {
            HintMatch::Named
        } else {
            HintMatch::Other
        }
    }
}

/// How a session record's hints relate to one stored pairing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HintMatch {
    /// A hint names the pairing; dial this custodian first.
    Named,
    /// The record publishes no hints; it may serve the pairing.
    Unhinted,
    /// Every hint names another pairing; do not dial.
    Other,
}

/// TXT key carrying the rotating discovery hints.
const HINTS_KEY: &str = "hints";
/// Hints a custodian publishes at most (hierarchy section 4.3).
const MAX_PUBLISHED_HINTS: usize = 4;
/// Hex digits in one published hint.
const HINT_HEX_DIGITS: usize = 2 * refineid_rapp::DISCOVERY_HINT_SIZE;

fn decode_hint(text: &str) -> Option<[u8; refineid_rapp::DISCOVERY_HINT_SIZE]> {
    if text.len() != HINT_HEX_DIGITS
        || !text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    let mut hint = [0_u8; refineid_rapp::DISCOVERY_HINT_SIZE];
    for (index, byte) in hint.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[2 * index..2 * index + 2], 16).ok()?;
    }
    Some(hint)
}

/// One accepted, preamble-classified stream connection.
#[derive(Debug)]
pub enum StreamAccept {
    /// The dialing proxy asked for the active pairing offer.
    Pairing(TcpFrameTransport),
    /// The dialing proxy asked for a fresh session with a stored pairing.
    Session {
        /// The pair-specific token from the preamble. The caller looks it
        /// up among non-revoked pairings and closes on no match.
        rendezvous_token: RendezvousToken,
        /// The connection, positioned after the preamble.
        transport: TcpFrameTransport,
    },
}

/// A custodian-side stream listener that classifies each connection by its
/// preamble. The requester never listens; mock custodians and tests do.
#[derive(Debug)]
pub struct StreamListener {
    listener: TcpListener,
    candidate_id: String,
    receive_deadline: Duration,
}

impl StreamListener {
    /// Binds the listener.
    ///
    /// # Errors
    ///
    /// Fails when the address cannot be bound.
    pub fn bind(
        address: &str,
        candidate_id: &str,
        receive_deadline: Duration,
    ) -> Result<Self, StreamError> {
        let listener = TcpListener::bind(address).map_err(|_| StreamError::Bind)?;
        Ok(Self {
            listener,
            candidate_id: candidate_id.to_owned(),
            receive_deadline,
        })
    }

    /// The bound local port, for assembling advertised endpoints.
    ///
    /// # Errors
    ///
    /// Fails when the socket cannot report its address.
    pub fn local_port(&self) -> Result<u16, StreamError> {
        self.listener
            .local_addr()
            .map(|address| address.port())
            .map_err(|_| StreamError::Bind)
    }

    /// Accepts one connection, reads exactly one bounded preamble frame,
    /// and classifies it. A connection whose preamble is invalid is closed
    /// and reported; stored state never changes here.
    ///
    /// # Errors
    ///
    /// Fails on accept failure or an invalid preamble.
    pub fn accept(&self) -> Result<StreamAccept, StreamError> {
        let (socket, _peer) = self.listener.accept().map_err(|_| StreamError::Accept)?;
        self.classify(socket)
    }

    /// Attempts to accept an incoming connection within `timeout`.
    ///
    /// Returns `Ok(None)` if no connection arrives within `timeout`.
    ///
    /// # Errors
    ///
    /// Fails on accept failure or an invalid preamble.
    pub fn accept_timeout(&self, timeout: Duration) -> Result<Option<StreamAccept>, StreamError> {
        self.listener
            .set_nonblocking(true)
            .map_err(|_| StreamError::Accept)?;
        let start = std::time::Instant::now();
        loop {
            match self.listener.accept() {
                Ok((socket, _peer)) => {
                    let _ = self.listener.set_nonblocking(false);
                    let _ = socket.set_nonblocking(false);
                    return self.classify(socket).map(Some);
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    if start.elapsed() >= timeout {
                        let _ = self.listener.set_nonblocking(false);
                        return Ok(None);
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(_) => {
                    let _ = self.listener.set_nonblocking(false);
                    return Err(StreamError::Accept);
                }
            }
        }
    }

    fn classify(&self, socket: TcpStream) -> Result<StreamAccept, StreamError> {
        let mut transport =
            TcpFrameTransport::new(socket, &self.candidate_id, self.receive_deadline)
                .map_err(|_| StreamError::Accept)?;
        let preamble = transport.receive_frame().map_err(StreamError::Preamble)?;
        match StreamRendezvous::decode(&preamble)? {
            StreamRendezvous::Pairing => Ok(StreamAccept::Pairing(transport)),
            StreamRendezvous::Session(rendezvous_token) => Ok(StreamAccept::Session {
                rendezvous_token,
                transport,
            }),
        }
    }
}

/// Dials an advertised custodian and sends the routing preamble, as the
/// requester does for pairing and for every session.
///
/// # Errors
///
/// Fails when no endpoint accepts the connection or the preamble cannot be
/// sent.
pub fn dial(
    endpoints: &[String],
    candidate_id: &str,
    receive_deadline: Duration,
    rendezvous: &StreamRendezvous,
) -> Result<TcpFrameTransport, StreamError> {
    let preamble = rendezvous.encode()?;
    for endpoint in endpoints {
        let Ok(mut addresses) = endpoint.as_str().to_socket_addrs() else {
            continue;
        };
        let Some(address) = addresses.next() else {
            continue;
        };
        let Ok(socket) = TcpStream::connect_timeout(&address, CONNECT_TIMEOUT) else {
            continue;
        };
        let mut transport = TcpFrameTransport::new(socket, candidate_id, receive_deadline)
            .map_err(|_| StreamError::Accept)?;
        transport
            .send_frame(&preamble)
            .map_err(StreamError::Preamble)?;
        return Ok(transport);
    }
    Err(StreamError::Unreachable)
}

/// How long one TCP connect may take before the next endpoint is tried.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

fn parse_dns_name(buf: &[u8], mut offset: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut jumped = false;
    let mut next_offset = 0;
    let mut jumps = 0;

    while offset < buf.len() {
        let len = *buf.get(offset)? as usize;
        if len == 0 {
            if !jumped {
                next_offset = offset + 1;
            }
            break;
        }
        if (len & 0xC0) == 0xC0 {
            if jumps > 10 {
                return None;
            }
            let b2 = *buf.get(offset + 1)? as usize;
            let ptr = ((len & 0x3F) << 8) | b2;
            if !jumped {
                next_offset = offset + 2;
                jumped = true;
            }
            offset = ptr;
            jumps += 1;
            continue;
        }
        offset += 1;
        let end = offset.checked_add(len)?;
        if end > buf.len() {
            return None;
        }
        let label = std::str::from_utf8(buf.get(offset..end)?).ok()?;
        labels.push(label.to_ascii_lowercase());
        offset = end;
    }
    Some((labels.join("."), next_offset))
}

/// DNS resource-record types the browser reads (RFC 1035, RFC 2782).
const RR_TYPE_A: u16 = 1;
const RR_TYPE_PTR: u16 = 12;
const RR_TYPE_TXT: u16 = 16;
const RR_TYPE_SRV: u16 = 33;
/// DNS message header length in bytes.
const DNS_HEADER_BYTES: usize = 12;
/// Fixed bytes after a resource record's name: type, class, TTL, length.
const RR_FIXED_BYTES: usize = 10;
/// SRV rdata bytes before the target name: priority, weight, port.
const SRV_FIXED_BYTES: usize = 6;
/// Largest mDNS response the browser reads.
const MDNS_RESPONSE_BYTES: usize = 4096;
/// The mDNS IPv4 group and port (RFC 6762 section 3).
const MDNS_GROUP: std::net::SocketAddrV4 =
    std::net::SocketAddrV4::new(std::net::Ipv4Addr::new(224, 0, 0, 251), 5353);
/// Poll interval while waiting for answers.
const MDNS_POLL: Duration = Duration::from_millis(250);

/// Records gathered from mDNS answers before they are joined per instance.
#[derive(Debug, Default)]
struct MdnsRecords {
    instances: Vec<String>,
    services: BTreeMap<String, (u16, String, Option<std::net::Ipv4Addr>)>,
    texts: BTreeMap<String, BTreeMap<String, String>>,
    addresses: BTreeMap<String, std::net::Ipv4Addr>,
}

impl MdnsRecords {
    fn into_services(self) -> Vec<StreamService> {
        let mut found = Vec::new();
        for instance in self.instances {
            let Some((port, host, responder)) = self.services.get(&instance) else {
                continue;
            };
            let mut endpoints = Vec::new();
            if let Some(ip) = self.addresses.get(host) {
                endpoints.push(format!("{ip}:{port}"));
            }
            if let Some(ip) = responder
                && !endpoints.contains(&format!("{ip}:{port}"))
            {
                endpoints.push(format!("{ip}:{port}"));
            }
            if endpoints.is_empty() {
                continue;
            }
            let label = instance
                .strip_suffix(&format!(".{STREAM_SERVICE_TYPE}"))
                .unwrap_or(&instance)
                .to_owned();
            found.push(StreamService {
                instance: label,
                endpoints,
                attributes: self.texts.get(&instance).cloned().unwrap_or_default(),
            });
        }
        found
    }
}

/// Parses one mDNS response into `records`; malformed input is ignored.
fn parse_mdns_response(
    data: &[u8],
    responder: Option<std::net::Ipv4Addr>,
    records: &mut MdnsRecords,
) {
    if data.len() < DNS_HEADER_BYTES {
        return;
    }
    let count = |index: usize| usize::from(u16::from_be_bytes([data[index], data[index + 1]]));
    let questions = count(4);
    let resources = count(6) + count(8) + count(10);
    let mut offset = DNS_HEADER_BYTES;
    for _ in 0..questions {
        let Some((_, next)) = parse_dns_name(data, offset) else {
            return;
        };
        offset = next + 4;
    }
    for _ in 0..resources {
        let Some((name, after_name)) = parse_dns_name(data, offset) else {
            return;
        };
        if after_name + RR_FIXED_BYTES > data.len() {
            return;
        }
        let rtype = u16::from_be_bytes([data[after_name], data[after_name + 1]]);
        let length = usize::from(u16::from_be_bytes([
            data[after_name + 8],
            data[after_name + 9],
        ]));
        let start = after_name + RR_FIXED_BYTES;
        let end = start + length;
        if end > data.len() {
            return;
        }
        let rdata = &data[start..end];
        match rtype {
            RR_TYPE_PTR if name == STREAM_SERVICE_TYPE => {
                if let Some((instance, _)) = parse_dns_name(data, start)
                    && !records.instances.contains(&instance)
                {
                    records.instances.push(instance);
                }
            }
            RR_TYPE_SRV if rdata.len() >= SRV_FIXED_BYTES => {
                let port = u16::from_be_bytes([rdata[4], rdata[5]]);
                if let Some((host, _)) = parse_dns_name(data, start + SRV_FIXED_BYTES) {
                    records.services.insert(name, (port, host, responder));
                }
            }
            RR_TYPE_TXT => {
                records.texts.insert(name, parse_txt(rdata));
            }
            RR_TYPE_A if rdata.len() == 4 => {
                records.addresses.insert(
                    name,
                    std::net::Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]),
                );
            }
            _ => {}
        }
        offset = end;
    }
}

/// Reads TXT rdata: length-prefixed `key=value` strings (RFC 6763 section 6).
fn parse_txt(rdata: &[u8]) -> BTreeMap<String, String> {
    let mut attributes = BTreeMap::new();
    let mut offset = 0;
    while offset < rdata.len() {
        let length = usize::from(rdata[offset]);
        let end = offset + 1 + length;
        let Some(entry) = rdata.get(offset + 1..end) else {
            break;
        };
        if let Ok(text) = core::str::from_utf8(entry)
            && let Some((key, value)) = text.split_once('=')
        {
            attributes
                .entry(key.to_ascii_lowercase())
                .or_insert_with(|| value.to_owned());
        }
        offset = end;
    }
    attributes
}

/// Browses `_refineid-stream._tcp.local.` for `timeout` and returns every
/// advertised custodian, with the TXT attributes it published.
///
/// The query asks for unicast answers from an ephemeral port (RFC 6762
/// section 5.4), so it works beside a system mDNS responder.
#[must_use]
pub fn browse_stream_services(timeout: Duration) -> Vec<StreamService> {
    use std::net::UdpSocket;
    use std::time::Instant;

    let Ok(socket) = UdpSocket::bind("0.0.0.0:0") else {
        return Vec::new();
    };
    let _ = socket.set_read_timeout(Some(MDNS_POLL));
    let mut query = vec![0u8; DNS_HEADER_BYTES];
    query[5] = 1;
    for label in STREAM_SERVICE_TYPE.split('.') {
        #[allow(
            clippy::cast_possible_truncation,
            reason = "the service-type labels are fixed and under 64 bytes"
        )]
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0);
    query.extend_from_slice(&RR_TYPE_PTR.to_be_bytes());
    // Class IN with the unicast-response bit.
    query.extend_from_slice(&0x8001u16.to_be_bytes());
    if socket.send_to(&query, MDNS_GROUP).is_err() {
        return Vec::new();
    }

    let start = Instant::now();
    let mut records = MdnsRecords::default();
    let mut buffer = [0u8; MDNS_RESPONSE_BYTES];
    while start.elapsed() < timeout {
        let Ok((read, peer)) = socket.recv_from(&mut buffer) else {
            continue;
        };
        let responder = match peer {
            std::net::SocketAddr::V4(v4) => Some(*v4.ip()),
            std::net::SocketAddr::V6(_) => None,
        };
        parse_mdns_response(&buffer[..read], responder, &mut records);
    }
    records.into_services()
}

/// Browses for custodians advertising `mode`, each with at least one
/// endpoint.
#[must_use]
pub fn browse(mode: DiscoveryMode, timeout: Duration) -> Vec<StreamService> {
    browse_stream_services(timeout)
        .into_iter()
        .filter(|service| service.advertises(mode))
        .collect()
}

/// Rejected stream-profile bytes, parameters, or connection steps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamError {
    /// Structure, domain, type, or token length was not as specified.
    Malformed,
    /// Preamble frame exceeded [`MAX_STREAM_RENDEZVOUS_FRAME`].
    Oversized,
    /// Purpose string is not registered; the connection closes unanswered.
    UnknownPurpose,
    /// The listener address could not be bound or reported.
    Bind,
    /// A connection could not be accepted or wrapped.
    Accept,
    /// The preamble frame could not be moved.
    Preamble(TransportError),
    /// No advertised endpoint accepted the connection.
    Unreachable,
}

impl From<refineid_rapp::StreamError> for StreamError {
    fn from(err: refineid_rapp::StreamError) -> Self {
        match err {
            refineid_rapp::StreamError::Malformed => Self::Malformed,
            refineid_rapp::StreamError::Oversized => Self::Oversized,
            refineid_rapp::StreamError::UnknownPurpose => Self::UnknownPurpose,
        }
    }
}

impl core::fmt::Display for StreamError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Malformed => write!(f, "malformed stream profile data"),
            Self::Oversized => write!(f, "oversized stream rendezvous frame"),
            Self::UnknownPurpose => write!(f, "unknown stream rendezvous purpose"),
            Self::Bind => write!(f, "failed to bind stream listener"),
            Self::Accept => write!(f, "failed to accept stream connection"),
            Self::Preamble(e) => write!(f, "failed to move preamble frame: {e}"),
            Self::Unreachable => write!(f, "stream endpoint unreachable"),
        }
    }
}

impl core::error::Error for StreamError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Preamble(e) => Some(e),
            _ => None,
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "test fixtures are constructed to be infallible"
)]
mod tests {
    use std::collections::BTreeMap;
    use std::time::Duration;

    use super::{
        DiscoveryMode, HintMatch, MdnsRecords, StreamAccept, StreamError, StreamListener,
        StreamRendezvous, StreamService, dial, parse_mdns_response,
    };
    use crate::ids::RendezvousToken;
    use crate::transport::FrameTransport;

    const DEADLINE: Duration = Duration::from_secs(2);
    const CANDIDATE: &str = "stream-test";

    fn token() -> RendezvousToken {
        RendezvousToken::from_array([0x5A; 16])
    }

    fn name(labels: &[&str]) -> Vec<u8> {
        let mut out = Vec::new();
        for label in labels {
            out.push(u8::try_from(label.len()).unwrap());
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
        out
    }

    fn record(owner: &[&str], rtype: u16, rdata: &[u8]) -> Vec<u8> {
        let mut out = name(owner);
        out.extend_from_slice(&rtype.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&120u32.to_be_bytes());
        out.extend_from_slice(&u16::try_from(rdata.len()).unwrap().to_be_bytes());
        out.extend_from_slice(rdata);
        out
    }

    /// A response like a custodian's: PTR, SRV, TXT, and A records.
    fn response(instance: &str, txt: &[&str]) -> Vec<u8> {
        let service = ["_refineid-stream", "_tcp", "local"];
        let full = [instance, "_refineid-stream", "_tcp", "local"];
        let host = ["refineid-b3d90e15", "local"];
        let mut srv = vec![0, 0, 0, 0];
        srv.extend_from_slice(&47110u16.to_be_bytes());
        srv.extend_from_slice(&name(&host));
        let mut txt_rdata = Vec::new();
        for entry in txt {
            txt_rdata.push(u8::try_from(entry.len()).unwrap());
            txt_rdata.extend_from_slice(entry.as_bytes());
        }
        let mut packet = vec![0, 0, 0x84, 0, 0, 0, 0, 4, 0, 0, 0, 0];
        packet.extend(record(&service, super::RR_TYPE_PTR, &name(&full)));
        packet.extend(record(&full, super::RR_TYPE_SRV, &srv));
        packet.extend(record(&full, super::RR_TYPE_TXT, &txt_rdata));
        packet.extend(record(&host, super::RR_TYPE_A, &[192, 0, 2, 10]));
        packet
    }

    #[test]
    fn browse_joins_records_and_reads_the_mode() {
        let mut records = MdnsRecords::default();
        parse_mdns_response(
            &response("refineid-7f2a1c84", &["v=1", "mode=pairing"]),
            None,
            &mut records,
        );
        parse_mdns_response(
            &response("refineid-0b9e44d1", &["v=1", "mode=session"]),
            None,
            &mut records,
        );
        let services = records.into_services();
        assert_eq!(services.len(), 2);
        let pairing: Vec<_> = services
            .iter()
            .filter(|service| service.advertises(DiscoveryMode::Pairing))
            .collect();
        assert_eq!(pairing.len(), 1);
        assert_eq!(pairing[0].instance, "refineid-7f2a1c84");
        assert_eq!(pairing[0].endpoints, ["192.0.2.10:47110"]);
        assert!(services[1].advertises(DiscoveryMode::Session));
    }

    #[test]
    fn a_record_without_version_one_is_not_a_custodian() {
        let mut records = MdnsRecords::default();
        parse_mdns_response(
            &response("refineid-7f2a1c84", &["v=2", "mode=pairing"]),
            None,
            &mut records,
        );
        let services = records.into_services();
        assert!(!services[0].advertises(DiscoveryMode::Pairing));
    }

    #[test]
    fn truncated_responses_are_ignored() {
        let mut records = MdnsRecords::default();
        let packet = response("refineid-7f2a1c84", &["v=1", "mode=pairing"]);
        for cut in 0..packet.len() {
            parse_mdns_response(&packet[..cut], None, &mut records);
        }
    }

    #[test]
    fn preambles_round_trip_and_reject_foreign_purposes() {
        let pairing = StreamRendezvous::Pairing.encode().unwrap();
        assert_eq!(
            StreamRendezvous::decode(&pairing).unwrap(),
            StreamRendezvous::Pairing
        );
        let session = StreamRendezvous::Session(token()).encode().unwrap();
        assert_eq!(
            StreamRendezvous::decode(&session).unwrap(),
            StreamRendezvous::Session(token())
        );
        let oversized = vec![0u8; super::MAX_STREAM_RENDEZVOUS_FRAME + 1];
        assert_eq!(
            StreamRendezvous::decode(&oversized),
            Err(refineid_rapp::StreamError::Oversized)
        );
    }

    #[test]
    fn custodian_listener_classifies_requester_dials() {
        let listener = StreamListener::bind("127.0.0.1:0", CANDIDATE, DEADLINE).unwrap();
        let port = listener.local_port().unwrap();
        let endpoints = vec![format!("127.0.0.1:{port}")];

        let dial_endpoints = endpoints.clone();
        let dialer = std::thread::spawn(move || {
            dial(
                &dial_endpoints,
                CANDIDATE,
                DEADLINE,
                &StreamRendezvous::Pairing,
            )
            .unwrap()
        });
        let accepted = listener.accept().unwrap();
        assert!(matches!(accepted, StreamAccept::Pairing(_)));
        drop(dialer.join().unwrap());

        let dialer = std::thread::spawn(move || {
            let mut transport = dial(
                &endpoints,
                CANDIDATE,
                DEADLINE,
                &StreamRendezvous::Session(RendezvousToken::from_array([0x5A; 16])),
            )
            .unwrap();
            transport.send_frame(&[0x01, 0x02]).unwrap();
        });
        let StreamAccept::Session {
            rendezvous_token,
            mut transport,
        } = listener.accept().unwrap()
        else {
            panic!("expected a session accept");
        };
        assert_eq!(rendezvous_token, token());
        assert_eq!(transport.receive_frame().unwrap(), vec![0x01, 0x02]);
        dialer.join().unwrap();
    }

    #[test]
    fn garbage_preambles_close_without_classification() {
        let listener = StreamListener::bind("127.0.0.1:0", CANDIDATE, DEADLINE).unwrap();
        let port = listener.local_port().unwrap();
        let dialer = std::thread::spawn(move || {
            let socket = std::net::TcpStream::connect(format!("127.0.0.1:{port}")).unwrap();
            let mut transport =
                crate::transport::TcpFrameTransport::new(socket, CANDIDATE, DEADLINE).unwrap();
            transport.send_frame(&[0xFF, 0x00, 0x11]).unwrap();
        });
        assert!(matches!(listener.accept(), Err(StreamError::Malformed)));
        dialer.join().unwrap();
    }

    #[test]
    fn an_unreachable_custodian_is_reported() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        assert!(matches!(
            dial(
                &[format!("127.0.0.1:{port}")],
                CANDIDATE,
                DEADLINE,
                &StreamRendezvous::Pairing
            ),
            Err(StreamError::Unreachable)
        ));
    }

    fn session_service(hints: Option<String>) -> StreamService {
        let mut attributes = BTreeMap::from([
            ("v".to_owned(), "1".to_owned()),
            ("mode".to_owned(), "session".to_owned()),
        ]);
        if let Some(hints) = hints {
            attributes.insert("hints".to_owned(), hints);
        }
        StreamService {
            instance: "refineid-0b9e44d1".to_owned(),
            endpoints: vec!["192.0.2.10:47110".to_owned()],
            attributes,
        }
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn a_hint_names_its_pairing_within_one_epoch_either_way() {
        let token = token();
        let epoch_seconds = refineid_rapp::DISCOVERY_HINT_EPOCH_SECONDS;
        let now = 1_000 * epoch_seconds + 7;
        let previous = refineid_rapp::discovery_hint(&token, 999);
        let other = refineid_rapp::discovery_hint(&RendezvousToken::from_array([0x24; 16]), 1_000);
        let service = session_service(Some(format!("{},{}", hex(&other), hex(&previous))));
        assert_eq!(service.hint_match(&token, now), HintMatch::Named);
        assert_eq!(
            service.hint_match(&token, now + 3 * epoch_seconds),
            HintMatch::Other
        );
        assert_eq!(
            session_service(None).hint_match(&token, now),
            HintMatch::Unhinted
        );
    }

    #[test]
    fn malformed_hint_entries_are_ignored() {
        let token = token();
        let current = refineid_rapp::discovery_hint(&token, 1_000);
        let upper = hex(&current).to_ascii_uppercase();
        let service = session_service(Some(format!("{upper},zz,{}", hex(&current))));
        assert_eq!(service.hints().map(|hints| hints.len()), Some(1));
        let only_bad = session_service(Some(format!("{upper},short")));
        assert_eq!(only_bad.hints().map(|hints| hints.len()), Some(0));
        assert_eq!(
            only_bad.hint_match(&token, 1_000 * refineid_rapp::DISCOVERY_HINT_EPOCH_SECONDS),
            HintMatch::Other
        );
    }
}
