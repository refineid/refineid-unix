//! The `fi.refineid.stream` transport tier (RAPP v26.10.29 section 2.2.2;
//! RAPP transport and discovery hierarchy, sections 3.2 and 4).
//!
//! The custodian (the phone) listens on an ephemeral TCP port and advertises
//! `_refineid-stream._tcp.local.` under a fresh random instance name, with a
//! TXT record naming its mode: `mode=pairing` during a pairing ceremony,
//! `mode=session` while it serves stored pairings, and briefly
//! `mode=withdrawn` when its holder stops serving. The requester browses by
//! those attributes, dials, and opens every connection with one plaintext
//! routing preamble. A session preamble carries a fresh routing value keyed
//! by the pairing's static agreement, so no stable pairing identifier
//! crosses the wire. An anomaly closes the connection without touching
//! stored state (specification section 10.1, class 1).

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::time::Duration;

use refineid_rapp::{
    DiscoveryKey, DiscoveryRecord, InstanceName, PreambleError, SessionRouting, TransportProfile,
    WithdrawalKey, WithdrawnRecord, discovery_epoch, withdrawal_counter,
};

use crate::transport::{FrameTransport, TcpFrameTransport, TransportError};
pub use refineid_rapp::{
    MAX_ROUTING_PREAMBLE_FRAME, RoutingPreamble, STREAM_CANDIDATE_ID, STREAM_PROFILE,
};

/// The DNS-SD service type of the stream tier.
pub const STREAM_SERVICE_TYPE: &str = "_refineid-stream._tcp.local";

/// TXT key naming the discovery mode.
const MODE_KEY: &str = "mode";
/// TXT key naming the record format version.
const VERSION_KEY: &str = "v";
/// The one TXT format version this requester understands.
const SUPPORTED_TXT_VERSION: &str = "1";
/// The `mode` value of a pairing ceremony.
const MODE_PAIRING: &str = "pairing";

/// The custodian discovery modes of hierarchy section 4.3.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiscoveryMode {
    /// An explicit pairing ceremony is open on the custodian.
    Pairing,
    /// The custodian serves sessions for stored pairings.
    Session,
    /// The custodian announced that it stopped serving.
    Withdrawn,
}

/// One advertised custodian: its instance, endpoints, and TXT entries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamService {
    /// The advertised instance portion of the service name (random; carries
    /// no identity).
    pub instance: String,
    /// `ip:port` endpoints that answered for this instance.
    pub endpoints: Vec<String>,
    /// The TXT `key=value` entries as published, in order.
    pub txt: Vec<(String, String)>,
}

impl StreamService {
    fn entries(&self) -> Vec<(&str, &str)> {
        self.txt
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str()))
            .collect()
    }

    /// The value of `key`, compared case-insensitively (RFC 6763 section
    /// 6.4); `None` when it is absent or repeated.
    fn value(&self, key: &str) -> Option<&str> {
        let mut found = self
            .txt
            .iter()
            .filter(|(candidate, _)| candidate.eq_ignore_ascii_case(key));
        let (_, value) = found.next()?;
        found.next().is_none().then_some(value.as_str())
    }

    /// Whether the TXT record is a well-formed record of `mode`.
    #[must_use]
    pub fn advertises(&self, mode: DiscoveryMode) -> bool {
        match mode {
            DiscoveryMode::Pairing => {
                self.value(VERSION_KEY) == Some(SUPPORTED_TXT_VERSION)
                    && self.value(MODE_KEY) == Some(MODE_PAIRING)
            }
            DiscoveryMode::Session => DiscoveryRecord::parse(&self.entries()).is_ok(),
            DiscoveryMode::Withdrawn => WithdrawnRecord::parse(&self.entries()).is_ok(),
        }
    }

    /// How this session record relates to the pairing keyed by `key` at
    /// `unix_seconds`: a published hint names it within one epoch either
    /// way, the record publishes no hints, or its hints name other pairings
    /// or the record is not a well-formed session record.
    #[must_use]
    pub fn hint_match(&self, key: &DiscoveryKey, unix_seconds: u64) -> HintMatch {
        let Ok(record) = DiscoveryRecord::parse(&self.entries()) else {
            return HintMatch::Other;
        };
        if record.hints().is_empty() {
            HintMatch::Unhinted
        } else if key.matches_record(&record, discovery_epoch(unix_seconds)) {
            HintMatch::Named
        } else {
            HintMatch::Other
        }
    }

    /// Whether this is a withdrawn record that announces the pairing keyed
    /// by `key` at `unix_seconds` on this instance.
    #[must_use]
    pub fn withdraws(&self, key: &WithdrawalKey, unix_seconds: u64) -> bool {
        let (Ok(record), Ok(instance)) = (
            WithdrawnRecord::parse(&self.entries()),
            InstanceName::new(&self.instance),
        ) else {
            return false;
        };
        key.matches(&record, &instance, withdrawal_counter(unix_seconds))
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

/// One accepted, preamble-classified stream connection.
#[derive(Debug)]
pub enum StreamAccept {
    /// The dialing proxy asked for the active pairing offer.
    Pairing(TcpFrameTransport),
    /// The dialing proxy asked for a fresh session with a stored pairing.
    Session {
        /// The routing value from the preamble. The caller routes it among
        /// non-revoked pairings and closes on no match.
        routing: SessionRouting,
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
        match RoutingPreamble::decode(TransportProfile::Stream, &preamble)? {
            RoutingPreamble::Pairing => Ok(StreamAccept::Pairing(transport)),
            RoutingPreamble::Session(routing) => Ok(StreamAccept::Session { routing, transport }),
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
    preamble: &RoutingPreamble,
) -> Result<TcpFrameTransport, StreamError> {
    let preamble = preamble.encode(TransportProfile::Stream)?;
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
/// Offset of the question count in the DNS header (RFC 1035 section 4.1.1).
const DNS_QUESTION_COUNT_OFFSET: usize = 4;
/// Questions in one browse query.
const BROWSE_QUESTIONS: u16 = 1;
/// Fixed bytes after a resource record's name: type, class, TTL, length.
const RR_FIXED_BYTES: usize = 10;
/// SRV rdata bytes before the target name: priority, weight, port.
const SRV_FIXED_BYTES: usize = 6;
/// Largest mDNS response the browser reads.
const MDNS_RESPONSE_BYTES: usize = 4096;
/// DNS class IN (RFC 1035 section 3.2.4).
const DNS_CLASS_IN: u16 = 1;
/// The unicast-response bit of an mDNS question's class (RFC 6762 section 5.4).
const DNS_UNICAST_RESPONSE: u16 = 1 << 15;
/// The mDNS port (RFC 6762 section 3).
const MDNS_PORT: u16 = 5353;
/// The mDNS IPv4 group address (RFC 6762 section 3).
const MDNS_GROUP_ADDRESS: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
/// The mDNS IPv4 group and port.
const MDNS_GROUP: SocketAddrV4 = SocketAddrV4::new(MDNS_GROUP_ADDRESS, MDNS_PORT);
/// Read timeout of each browse socket while waiting for answers.
const MDNS_POLL: Duration = Duration::from_millis(125);

/// Records gathered from mDNS answers before they are joined per instance.
#[derive(Debug, Default)]
struct MdnsRecords {
    instances: Vec<String>,
    services: BTreeMap<String, (u16, String, Option<Ipv4Addr>)>,
    texts: BTreeMap<String, Vec<(String, String)>>,
    addresses: BTreeMap<String, Ipv4Addr>,
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
                txt: self.texts.get(&instance).cloned().unwrap_or_default(),
            });
        }
        found
    }
}

/// Parses one mDNS response into `records`; malformed input is ignored.
fn parse_mdns_response(data: &[u8], responder: Option<Ipv4Addr>, records: &mut MdnsRecords) {
    if data.len() < DNS_HEADER_BYTES {
        return;
    }
    let count = |index: usize| usize::from(u16::from_be_bytes([data[index], data[index + 1]]));
    let questions = count(DNS_QUESTION_COUNT_OFFSET);
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
                records
                    .addresses
                    .insert(name, Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]));
            }
            _ => {}
        }
        offset = end;
    }
}

/// Reads TXT rdata: length-prefixed `key=value` strings (RFC 6763 section
/// 6), kept in order and as published. Keys compare case-insensitively
/// where they are read, and a repeated key makes the record malformed
/// there; neither is decided here.
fn parse_txt(rdata: &[u8]) -> Vec<(String, String)> {
    let mut entries = Vec::new();
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
            entries.push((key.to_owned(), value.to_owned()));
        }
        offset = end;
    }
    entries
}

/// Extracts IPv4 addresses of resolved neighbors from `/proc/net/arp` format.
#[must_use]
pub fn parse_arp_table(content: &str) -> Vec<Ipv4Addr> {
    let mut neighbors = Vec::new();
    for line in content.lines().skip(1) {
        let mut fields = line.split_whitespace();
        let Some(ip_str) = fields.next() else {
            continue;
        };
        let Some(_hw_type) = fields.next() else {
            continue;
        };
        let Some(flags_str) = fields.next() else {
            continue;
        };
        let Some(hw_addr) = fields.next() else {
            continue;
        };

        if flags_str == "0x0" || flags_str == "0x00" || hw_addr == "00:00:00:00:00:00" {
            continue;
        }

        if let Ok(ip) = ip_str.parse::<Ipv4Addr>()
            && !ip.is_loopback()
            && !ip.is_multicast()
            && !ip.is_broadcast()
            && !ip.is_unspecified()
            && !ip.is_link_local()
            && !neighbors.contains(&ip)
        {
            neighbors.push(ip);
        }
    }
    neighbors
}

/// Discovers active local IPv4 neighbors on the host's subnet.
///
/// Inspects the Linux kernel ARP table (`/proc/net/arp`). In virtualized
/// environments (such as bridged VMs over Wi-Fi) or Wi-Fi networks with multicast
/// suppression, multicast queries never leave the air interface, but direct unicast
/// queries to active ARP neighbors reach the custodian directly.
#[must_use]
pub fn local_neighbors() -> Vec<Ipv4Addr> {
    if let Ok(content) = std::fs::read_to_string("/proc/net/arp") {
        return parse_arp_table(&content);
    }
    Vec::new()
}

/// Browses `_refineid-stream._tcp.local.` for `timeout` and returns every
/// advertised custodian, with the TXT entries it published.
///
/// The question goes to the mDNS group and, directly, to each of `remembered`
/// as well as active local neighbors discovered from the host's ARP table.
/// A wireless network delivers multicast to a phone unreliably (and bridged
/// VMs on Wi-Fi drop multicast altogether); queries to known or active neighbor
/// addresses are answered whenever the phone is reachable at all.
#[must_use]
pub fn browse_stream_services(timeout: Duration, remembered: &[Ipv4Addr]) -> Vec<StreamService> {
    let mut targets: Vec<Ipv4Addr> = remembered.to_vec();
    for neighbor in local_neighbors() {
        if !targets.contains(&neighbor) {
            targets.push(neighbor);
        }
    }
    let responders: Vec<SocketAddrV4> = targets
        .iter()
        .map(|address| SocketAddrV4::new(*address, MDNS_PORT))
        .collect();
    browse_responders(timeout, &responders)
}

/// The sockets one browse asks on.
///
/// A responder answers a question by multicast unless the question asks
/// for a unicast answer and the record was multicast within a quarter of
/// its TTL (RFC 6762 section 5.4); only a socket bound to the mDNS port and
/// joined to the group hears a multicast answer, and that port is shared
/// with the system responder. A legacy question from an ephemeral port
/// (section 6.7) is answered by unicast, reaches responders asked directly,
/// and still works where the mDNS port cannot be shared.
struct BrowseSockets {
    group: Option<std::net::UdpSocket>,
    legacy: std::net::UdpSocket,
}

impl BrowseSockets {
    fn open() -> Option<Self> {
        let legacy = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
        legacy.set_read_timeout(Some(MDNS_POLL)).ok()?;
        Some(Self {
            group: Self::group_socket(),
            legacy,
        })
    }

    /// Binds the shared mDNS port and joins the group on the default
    /// interface; `None` where the platform refuses either.
    fn group_socket() -> Option<std::net::UdpSocket> {
        use socket2::{Domain, Protocol, SockAddr, Socket, Type};

        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).ok()?;
        socket.set_reuse_address(true).ok()?;
        socket.set_reuse_port(true).ok()?;
        let port = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, MDNS_PORT);
        socket.bind(&SockAddr::from(port)).ok()?;
        socket
            .join_multicast_v4(&MDNS_GROUP_ADDRESS, &Ipv4Addr::UNSPECIFIED)
            .ok()?;
        socket.set_read_timeout(Some(MDNS_POLL)).ok()?;
        Some(socket.into())
    }

    /// Asks the group an ordinary question from the group socket, and the
    /// group and `responders` a legacy one; false when nothing went out.
    fn ask(&self, responders: &[SocketAddrV4]) -> bool {
        let mut asked = self
            .group
            .as_ref()
            .is_some_and(|socket| socket.send_to(&browse_query(false), MDNS_GROUP).is_ok());
        let legacy = browse_query(true);
        for responder in core::iter::once(&MDNS_GROUP).chain(responders) {
            asked |= self.legacy.send_to(&legacy, responder).is_ok();
        }
        asked
    }

    /// Reads one datagram from whichever socket has one within its poll.
    fn receive(&self, buffer: &mut [u8]) -> Option<(usize, std::net::SocketAddr)> {
        if let Some(group) = &self.group
            && let Ok(received) = group.recv_from(buffer)
        {
            return Some(received);
        }
        self.legacy.recv_from(buffer).ok()
    }
}

/// [`browse_stream_services`], asking the mDNS group and `responders`.
fn browse_responders(timeout: Duration, responders: &[SocketAddrV4]) -> Vec<StreamService> {
    use std::time::Instant;

    let Some(sockets) = BrowseSockets::open() else {
        return Vec::new();
    };
    if !sockets.ask(responders) {
        return Vec::new();
    }

    let start = Instant::now();
    let mut records = MdnsRecords::default();
    let mut buffer = [0u8; MDNS_RESPONSE_BYTES];
    while start.elapsed() < timeout {
        let Some((read, peer)) = sockets.receive(&mut buffer) else {
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

/// One PTR question for the stream service type, class IN, with the
/// unicast-response bit when `unicast_response` is set.
fn browse_query(unicast_response: bool) -> Vec<u8> {
    let mut query = vec![0u8; DNS_HEADER_BYTES];
    query[DNS_QUESTION_COUNT_OFFSET..DNS_QUESTION_COUNT_OFFSET + 2]
        .copy_from_slice(&BROWSE_QUESTIONS.to_be_bytes());
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
    let class = if unicast_response {
        DNS_CLASS_IN | DNS_UNICAST_RESPONSE
    } else {
        DNS_CLASS_IN
    };
    query.extend_from_slice(&class.to_be_bytes());
    query
}

/// Browses for custodians advertising `mode`, each with at least one
/// endpoint.
#[must_use]
pub fn browse(mode: DiscoveryMode, timeout: Duration) -> Vec<StreamService> {
    browse_stream_services(timeout, &[])
        .into_iter()
        .filter(|service| service.advertises(mode))
        .collect()
}

/// Rejected stream-profile bytes, parameters, or connection steps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamError {
    /// Structure, domain, type, or routing length was not as specified.
    Malformed,
    /// Preamble frame exceeded [`MAX_ROUTING_PREAMBLE_FRAME`].
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

impl From<PreambleError> for StreamError {
    fn from(err: PreambleError) -> Self {
        match err {
            PreambleError::Malformed => Self::Malformed,
            PreambleError::Oversized => Self::Oversized,
            PreambleError::UnknownPurpose => Self::UnknownPurpose,
        }
    }
}

impl core::fmt::Display for StreamError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Malformed => write!(f, "malformed stream profile data"),
            Self::Oversized => write!(f, "oversized routing preamble frame"),
            Self::UnknownPurpose => write!(f, "unknown routing preamble purpose"),
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
    use std::time::Duration;

    use refineid_rapp::{
        DiscoveryKey, InstanceName, PairId, RoutingKey, TransportProfile, WithdrawalKey,
        WithdrawnRecord, discovery_epoch, withdrawal_counter,
    };

    use super::{
        DiscoveryMode, HintMatch, MdnsRecords, RoutingPreamble, StreamAccept, StreamError,
        StreamListener, StreamService, dial, parse_mdns_response,
    };
    use crate::transport::FrameTransport;

    const DEADLINE: Duration = Duration::from_secs(2);
    const CANDIDATE: &str = "stream-test";
    const INSTANCE: &str = "refineid-0b9e44d1";
    const LOCAL_PRIVATE: [u8; 32] = [0x11; 32];
    const OTHER_PRIVATE: [u8; 32] = [0x33; 32];
    const PAIR_ID: [u8; 16] = [0x22; 16];

    const PEER_PUBLIC: [u8; 32] = [0x44; 32];

    fn discovery_key(local: [u8; 32]) -> DiscoveryKey {
        DiscoveryKey::from_parts(PairId::from_array(PAIR_ID), &local, &PEER_PUBLIC).unwrap()
    }

    fn withdrawal_key(local: [u8; 32]) -> WithdrawalKey {
        WithdrawalKey::from_parts(PairId::from_array(PAIR_ID), &local, &PEER_PUBLIC).unwrap()
    }

    fn routing() -> refineid_rapp::SessionRouting {
        RoutingKey::from_parts(PairId::from_array(PAIR_ID), &LOCAL_PRIVATE, &PEER_PUBLIC)
            .unwrap()
            .route(TransportProfile::Stream, |nonce| {
                nonce.fill(0x5A);
                Ok(())
            })
            .unwrap()
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

    /// A responder on the loopback answers the direct query, as the phone
    /// answers one sent to its own address when multicast never arrives.
    #[test]
    fn a_remembered_responder_is_asked_directly() {
        use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};

        let responder = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = responder.local_addr().unwrap().port();
        let answering = std::thread::spawn(move || {
            let mut query = [0u8; 512];
            let (_, asker) = responder.recv_from(&mut query).unwrap();
            responder
                .send_to(
                    &response("refineid-0b9e44d1", &["v=1", "mode=session"]),
                    asker,
                )
                .unwrap();
        });
        let services = super::browse_responders(
            Duration::from_millis(600),
            &[SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)],
        );
        answering.join().unwrap();
        // The multicast query reaches the real network too; the loopback
        // responder's instance is counted alone.
        assert_eq!(
            services
                .iter()
                .filter(|service| service.instance == INSTANCE)
                .count(),
            1
        );
        let found = services
            .iter()
            .find(|service| service.instance == INSTANCE)
            .expect("the direct answer names the custodian");
        assert!(found.endpoints.contains(&"192.0.2.10:47110".to_owned()));
        assert!(found.advertises(DiscoveryMode::Session));
    }

    /// The question names the stream service type, asks for PTR, and sets
    /// the unicast-response bit only on the legacy form.
    #[test]
    fn browse_questions_differ_only_in_the_unicast_response_bit() {
        let mut question = name(&["_refineid-stream", "_tcp", "local"]);
        question.extend_from_slice(&super::RR_TYPE_PTR.to_be_bytes());
        for (unicast_response, class) in [
            (false, super::DNS_CLASS_IN),
            (true, super::DNS_CLASS_IN | super::DNS_UNICAST_RESPONSE),
        ] {
            let query = super::browse_query(unicast_response);
            let (header, body) = query.split_at(super::DNS_HEADER_BYTES);
            let mut expected_header = [0u8; super::DNS_HEADER_BYTES];
            expected_header[super::DNS_QUESTION_COUNT_OFFSET..super::DNS_QUESTION_COUNT_OFFSET + 2]
                .copy_from_slice(&super::BROWSE_QUESTIONS.to_be_bytes());
            assert_eq!(header, expected_header);
            let mut expected_body = question.clone();
            expected_body.extend_from_slice(&class.to_be_bytes());
            assert_eq!(body, expected_body);
        }
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
        let profile = TransportProfile::Stream;
        let pairing = RoutingPreamble::Pairing.encode(profile).unwrap();
        assert_eq!(
            RoutingPreamble::decode(profile, &pairing).unwrap(),
            RoutingPreamble::Pairing
        );
        let session = RoutingPreamble::Session(routing()).encode(profile).unwrap();
        assert_eq!(
            RoutingPreamble::decode(profile, &session).unwrap(),
            RoutingPreamble::Session(routing())
        );
        assert!(RoutingPreamble::decode(TransportProfile::Ble, &session).is_err());
        let oversized = vec![0u8; super::MAX_ROUTING_PREAMBLE_FRAME + 1];
        assert_eq!(
            RoutingPreamble::decode(profile, &oversized),
            Err(refineid_rapp::PreambleError::Oversized)
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
                &RoutingPreamble::Pairing,
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
                &RoutingPreamble::Session(routing()),
            )
            .unwrap();
            transport.send_frame(&[0x01, 0x02]).unwrap();
        });
        let StreamAccept::Session {
            routing: received,
            mut transport,
        } = listener.accept().unwrap()
        else {
            panic!("expected a session accept");
        };
        assert_eq!(received, routing());
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
                &RoutingPreamble::Pairing
            ),
            Err(StreamError::Unreachable)
        ));
    }

    fn service(txt: &[(&str, String)]) -> StreamService {
        StreamService {
            instance: INSTANCE.to_owned(),
            endpoints: vec!["192.0.2.10:47110".to_owned()],
            txt: txt
                .iter()
                .map(|(key, value)| ((*key).to_owned(), value.clone()))
                .collect(),
        }
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn session_service(hints: Option<String>) -> StreamService {
        let mut txt = vec![("v", "1".to_owned()), ("mode", "session".to_owned())];
        if let Some(hints) = hints {
            txt.push(("hints", hints));
        }
        service(&txt)
    }

    #[test]
    fn a_hint_names_its_pairing_within_one_epoch_either_way() {
        let key = discovery_key(LOCAL_PRIVATE);
        let epoch_seconds = refineid_rapp::DISCOVERY_HINT_EPOCH_SECONDS;
        let now = 1_000 * epoch_seconds + 7;
        let previous = key.hint(discovery_epoch(now) - 1);
        let other = discovery_key(OTHER_PRIVATE).hint(discovery_epoch(now));
        let named = session_service(Some(format!("{},{}", hex(&other), hex(&previous))));
        assert_eq!(named.hint_match(&key, now), HintMatch::Named);
        assert_eq!(
            named.hint_match(&key, now + 3 * epoch_seconds),
            HintMatch::Other
        );
        assert_eq!(
            session_service(None).hint_match(&key, now),
            HintMatch::Unhinted
        );
    }

    #[test]
    fn keys_compare_case_insensitively_and_values_exactly() {
        let key = discovery_key(LOCAL_PRIVATE);
        let now = 1_000 * refineid_rapp::DISCOVERY_HINT_EPOCH_SECONDS;
        let hint = hex(&key.hint(discovery_epoch(now)));
        let mixed = service(&[
            ("V", "1".to_owned()),
            ("Mode", "session".to_owned()),
            ("HINTS", hint.clone()),
        ]);
        assert!(mixed.advertises(DiscoveryMode::Session));
        assert_eq!(mixed.hint_match(&key, now), HintMatch::Named);
        let upper = session_service(Some(hint.to_ascii_uppercase()));
        assert!(!upper.advertises(DiscoveryMode::Session));
        assert_eq!(upper.hint_match(&key, now), HintMatch::Other);
        let repeated = service(&[
            ("v", "1".to_owned()),
            ("mode", "session".to_owned()),
            ("MODE", "session".to_owned()),
        ]);
        assert!(!repeated.advertises(DiscoveryMode::Session));
    }

    #[test]
    fn a_withdrawn_record_names_its_pairing_on_its_instance_only() {
        let key = withdrawal_key(LOCAL_PRIVATE);
        let now = 1_700_000_000;
        let instance = InstanceName::new(INSTANCE).unwrap();
        let candidate = refineid_rapp::AnnouncementCandidate {
            hint: key.hint(&instance, withdrawal_counter(now)),
            last_used_ms: 1,
        };
        let record = WithdrawnRecord::assemble(&[candidate], |bytes| {
            bytes.fill(0x7E);
            Ok(())
        })
        .unwrap();
        let withdrawn = service(&record.txt_entries());
        assert!(withdrawn.advertises(DiscoveryMode::Withdrawn));
        assert!(withdrawn.withdraws(&key, now));
        assert!(!withdrawn.withdraws(&withdrawal_key(OTHER_PRIVATE), now));
        assert!(!withdrawn.withdraws(&key, now + 3 * refineid_rapp::WITHDRAWAL_COUNTER_SECONDS));
        let moved = StreamService {
            instance: "refineid-ffffffff".to_owned(),
            ..withdrawn
        };
        assert!(!moved.withdraws(&key, now));
        assert!(!session_service(None).withdraws(&key, now));
    }

    #[test]
    fn parse_arp_table_extracts_valid_neighbors_and_ignores_incomplete() {
        let sample = "\
IP address       HW type     Flags       HW address            Mask     Device
192.0.2.10       0x1         0x2         02:00:00:00:00:01     *        eth0
192.0.2.20       0x1         0x2         02:00:00:00:00:02     *        eth0
192.0.2.30       0x1         0x2         02:00:00:00:00:03     *        eth0
192.0.2.99       0x1         0x0         00:00:00:00:00:00     *        eth0
127.0.0.1        0x1         0x2         02:00:00:00:00:00     *        lo
224.0.0.251      0x1         0x2         01:00:5e:00:00:fb     *        eth0
192.0.2.1        0x1         0x2         02:00:00:00:00:04     *        eth0
192.0.2.1        0x1         0x2         02:00:00:00:00:04     *        eth0
";
        let parsed = super::parse_arp_table(sample);
        assert_eq!(
            parsed,
            vec![
                std::net::Ipv4Addr::new(192, 0, 2, 10),
                std::net::Ipv4Addr::new(192, 0, 2, 20),
                std::net::Ipv4Addr::new(192, 0, 2, 30),
                std::net::Ipv4Addr::new(192, 0, 2, 1),
            ]
        );
    }
}
