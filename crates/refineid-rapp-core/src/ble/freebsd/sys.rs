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

//! FreeBSD's Bluetooth sockets through libc: the only unsafe code of the
//! BLE transport. Nothing here parses or decides; it opens, binds,
//! connects, filters, sends, polls and receives, with every structure
//! built from the named constants of FreeBSD's headers
//! (`<netgraph/bluetooth/include/ng_btsocket.h>`, `ng_bluetooth.h`,
//! `ng_l2cap.h`, `<sys/socket.h>`).

use std::io;
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
use std::time::Duration;

use libc::{c_int, c_ulong, c_void, socklen_t};

/// `PF_BLUETOOTH` and `AF_BLUETOOTH` (`<sys/socket.h>`).
const PF_BLUETOOTH: c_int = 36;
/// `BLUETOOTH_PROTO_HCI` (`ng_btsocket.h`).
const BLUETOOTH_PROTO_HCI: c_int = 134;
/// `BLUETOOTH_PROTO_L2CAP` (`ng_btsocket.h`).
const BLUETOOTH_PROTO_L2CAP: c_int = 135;
/// `SOL_HCI_RAW` (`ng_btsocket.h`).
const SOL_HCI_RAW: c_int = 0x0802;
/// `SO_HCI_RAW_FILTER` (`ng_btsocket.h`).
const SO_HCI_RAW_FILTER: c_int = 1;
/// `NG_NODESIZ`: the size of `sockaddr_hci.hci_node` (`ng_btsocket.h`).
const NG_NODESIZ: usize = 32;
/// `BDADDR_LE_PUBLIC` (`ng_bluetooth.h`).
const BDADDR_LE_PUBLIC: u8 = 1;
/// `BDADDR_LE_RANDOM` (`ng_bluetooth.h`).
const BDADDR_LE_RANDOM: u8 = 2;
/// `NG_L2CAP_ATT_CID`: the fixed ATT channel of an LE link (`ng_l2cap.h`;
/// Bluetooth Core Specification v5.4, Vol 3, Part A, section 2.1).
const NG_L2CAP_ATT_CID: u16 = 0x0004;
/// The PSM of a fixed-channel connection: none.
const NO_PSM: u16 = 0;
/// The channel a local bind names: any.
const ANY_CID: u16 = 0;
/// `NG_HCI_BDADDR_ANY`: every local controller.
const BDADDR_ANY: [u8; BD_ADDR_SIZE] = [0; BD_ADDR_SIZE];
/// Octets of a device address.
const BD_ADDR_SIZE: usize = 6;

/// Bits in one `bitstr_t` word (`<sys/bitstring.h>`: `unsigned long`).
const BITSTR_BITS: usize = c_ulong::BITS as usize;
/// Bits of `packet_mask` and `event_mask` in
/// `struct ng_btsocket_hci_raw_filter`.
const PACKET_MASK_BITS: usize = 32;
const EVENT_MASK_BITS: usize = 64;
const PACKET_MASK_WORDS: usize = PACKET_MASK_BITS.div_ceil(BITSTR_BITS);
const EVENT_MASK_WORDS: usize = EVENT_MASK_BITS.div_ceil(BITSTR_BITS);

/// `struct sockaddr_hci`.
#[repr(C)]
struct SockaddrHci {
    hci_len: u8,
    hci_family: u8,
    hci_node: [libc::c_char; NG_NODESIZ],
}

/// `struct sockaddr_l2cap`; `psm` and `cid` are little-endian.
#[repr(C)]
struct SockaddrL2cap {
    l2cap_len: u8,
    l2cap_family: u8,
    l2cap_psm: u16,
    l2cap_bdaddr: [u8; BD_ADDR_SIZE],
    l2cap_cid: u16,
    l2cap_bdaddr_type: u8,
    /// The structure's tail padding, which the C layout leaves after
    /// `l2cap_bdaddr_type` to align it to `u16`; always zero, so no
    /// uninitialized octet reaches the kernel.
    tail_padding: u8,
}

/// `struct ng_btsocket_hci_raw_filter`.
#[repr(C)]
struct HciRawFilter {
    packet_mask: [c_ulong; PACKET_MASK_WORDS],
    event_mask: [c_ulong; EVENT_MASK_WORDS],
}

/// The sizes FreeBSD 15 reports for these structures on amd64.
const SOCKADDR_HCI_SIZE: usize = 34;
const SOCKADDR_L2CAP_SIZE: usize = 14;
const _: () = assert!(size_of::<SockaddrHci>() == SOCKADDR_HCI_SIZE);
const _: () = assert!(size_of::<SockaddrL2cap>() == SOCKADDR_L2CAP_SIZE);
/// The offsets of `struct sockaddr_l2cap` the kernel reads.
const L2CAP_PSM_OFFSET: usize = 2;
const L2CAP_BDADDR_OFFSET: usize = 4;
const L2CAP_CID_OFFSET: usize = 10;
const L2CAP_BDADDR_TYPE_OFFSET: usize = 12;
const _: () = assert!(core::mem::offset_of!(SockaddrL2cap, l2cap_psm) == L2CAP_PSM_OFFSET);
const _: () = assert!(core::mem::offset_of!(SockaddrL2cap, l2cap_bdaddr) == L2CAP_BDADDR_OFFSET);
const _: () = assert!(core::mem::offset_of!(SockaddrL2cap, l2cap_cid) == L2CAP_CID_OFFSET);
const _: () =
    assert!(core::mem::offset_of!(SockaddrL2cap, l2cap_bdaddr_type) == L2CAP_BDADDR_TYPE_OFFSET);

#[allow(
    clippy::cast_possible_truncation,
    reason = "the structures are 34 and 14 octets, asserted above"
)]
const fn length_of<T>() -> u8 {
    size_of::<T>() as u8
}

#[allow(
    clippy::cast_possible_truncation,
    reason = "every structure passed is a few dozen octets"
)]
const fn socklen_of<T>() -> socklen_t {
    size_of::<T>() as socklen_t
}

#[allow(
    clippy::cast_possible_truncation,
    reason = "PF_BLUETOOTH is 36, an address family octet"
)]
const AF_BLUETOOTH_OCTET: u8 = PF_BLUETOOTH as u8;

/// A bitstring of `W` words with `bits` set: bit n is bit
/// n % [`BITSTR_BITS`] of word n / [`BITSTR_BITS`] (`<sys/bitstring.h>`,
/// `bit_set`).
fn bitstring<const W: usize>(bits: &[usize]) -> [c_ulong; W] {
    let mut words = [0; W];
    for &bit in bits {
        if let Some(word) = words.get_mut(bit / BITSTR_BITS) {
            *word |= 1 << (bit % BITSTR_BITS);
        }
    }
    words
}

/// One Bluetooth socket.
#[derive(Debug)]
pub(super) struct Socket(OwnedFd);

/// The last OS error as an `io::Error`.
fn last_error() -> io::Error {
    io::Error::last_os_error()
}

/// Fails with the OS error when a call returned -1.
fn check(result: c_int) -> io::Result<c_int> {
    if result < 0 {
        Err(last_error())
    } else {
        Ok(result)
    }
}

#[allow(
    unsafe_code,
    reason = "socket(2) is the only way to open a Bluetooth socket"
)]
fn open(kind: c_int, protocol: c_int) -> io::Result<Socket> {
    // SAFETY: socket(2) takes plain integers and returns a new descriptor
    // or -1; a new descriptor is owned by nothing else.
    let fd = check(unsafe { libc::socket(PF_BLUETOOTH, kind, protocol) })?;
    // SAFETY: `fd` is a freshly opened descriptor this function owns.
    Ok(Socket(unsafe { OwnedFd::from_raw_fd(fd) }))
}

impl Socket {
    #[allow(
        unsafe_code,
        reason = "bind(2) and connect(2) take a raw socket address"
    )]
    fn address<T>(&self, address: &T, call: AddressCall) -> io::Result<()> {
        let pointer = core::ptr::from_ref(address).cast::<libc::sockaddr>();
        let length = socklen_of::<T>();
        let fd = self.0.as_raw_fd();
        // SAFETY: `pointer` addresses a live `T` of `length` octets for the
        // duration of the call, and `fd` is an open socket.
        check(unsafe {
            match call {
                AddressCall::Bind => libc::bind(fd, pointer, length),
                AddressCall::Connect => libc::connect(fd, pointer, length),
            }
        })
        .map(drop)
    }

    #[allow(
        unsafe_code,
        reason = "setsockopt(2) takes the filter as a raw pointer"
    )]
    fn set_filter(&self, filter: &HciRawFilter) -> io::Result<()> {
        // SAFETY: `filter` is a live `HciRawFilter` of the length passed.
        check(unsafe {
            libc::setsockopt(
                self.0.as_raw_fd(),
                SOL_HCI_RAW,
                SO_HCI_RAW_FILTER,
                core::ptr::from_ref(filter).cast::<c_void>(),
                socklen_of::<HciRawFilter>(),
            )
        })
        .map(drop)
    }

    /// Sends one packet.
    #[allow(unsafe_code, reason = "send(2) takes a raw buffer")]
    pub(super) fn send(&self, packet: &[u8]) -> io::Result<()> {
        // SAFETY: `packet` is a live buffer of the length passed.
        let sent = unsafe {
            libc::send(
                self.0.as_raw_fd(),
                packet.as_ptr().cast::<c_void>(),
                packet.len(),
                0,
            )
        };
        match usize::try_from(sent) {
            Ok(count) if count == packet.len() => Ok(()),
            Ok(_) => Err(io::Error::from(io::ErrorKind::WriteZero)),
            Err(_) => Err(last_error()),
        }
    }

    /// Waits up to `timeout` for `events`; whether they came.
    #[allow(unsafe_code, reason = "poll(2) takes a raw descriptor array")]
    fn wait(&self, events: libc::c_short, timeout: Duration) -> io::Result<bool> {
        let mut descriptor = libc::pollfd {
            fd: self.0.as_raw_fd(),
            events,
            revents: 0,
        };
        let millis = c_int::try_from(timeout.as_millis()).unwrap_or(c_int::MAX);
        loop {
            // SAFETY: `descriptor` is one live `pollfd`, and one is passed.
            let ready = unsafe { libc::poll(&raw mut descriptor, 1, millis) };
            match ready {
                0 => return Ok(false),
                count if count > 0 => return Ok(true),
                _ => {
                    let error = last_error();
                    if error.kind() != io::ErrorKind::Interrupted {
                        return Err(error);
                    }
                }
            }
        }
    }

    /// Receives one packet into `buffer` within `timeout`: its length, or
    /// `None` when nothing came. Zero is an orderly close.
    #[allow(unsafe_code, reason = "recv(2) fills a raw buffer")]
    pub(super) fn receive(
        &self,
        buffer: &mut [u8],
        timeout: Duration,
    ) -> io::Result<Option<usize>> {
        if !self.wait(libc::POLLIN, timeout)? {
            return Ok(None);
        }
        // SAFETY: `buffer` is a live, writable buffer of the length passed.
        let received = unsafe {
            libc::recv(
                self.0.as_raw_fd(),
                buffer.as_mut_ptr().cast::<c_void>(),
                buffer.len(),
                0,
            )
        };
        usize::try_from(received)
            .map(Some)
            .map_err(|_| last_error())
    }

    #[allow(unsafe_code, reason = "fcntl(2) sets the descriptor's flags")]
    fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        let fd = self.0.as_raw_fd();
        // SAFETY: F_GETFL takes no argument and `fd` is open.
        let flags = check(unsafe { libc::fcntl(fd, libc::F_GETFL) })?;
        let flags = if nonblocking {
            flags | libc::O_NONBLOCK
        } else {
            flags & !libc::O_NONBLOCK
        };
        // SAFETY: F_SETFL takes an int of flags and `fd` is open.
        check(unsafe { libc::fcntl(fd, libc::F_SETFL, flags) }).map(drop)
    }

    #[allow(unsafe_code, reason = "getsockopt(2) fills a raw int")]
    fn pending_error(&self) -> io::Result<()> {
        let mut error: c_int = 0;
        let mut length = socklen_of::<c_int>();
        // SAFETY: `error` and `length` are live and `length` holds the size
        // of `error`.
        check(unsafe {
            libc::getsockopt(
                self.0.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                (&raw mut error).cast::<c_void>(),
                &raw mut length,
            )
        })?;
        if error == 0 {
            Ok(())
        } else {
            Err(io::Error::from_raw_os_error(error))
        }
    }
}

/// Which address call to make.
#[derive(Clone, Copy, Debug)]
enum AddressCall {
    Bind,
    Connect,
}

/// A raw HCI socket on the controller `node`, receiving the event packets
/// whose codes minus one are `event_bits` (`hccontrol`'s filter).
pub(super) fn open_hci(
    node: &str,
    packet_bits: &[usize],
    event_bits: &[usize],
) -> io::Result<Socket> {
    let socket = open(libc::SOCK_RAW, BLUETOOTH_PROTO_HCI)?;
    let mut address = SockaddrHci {
        hci_len: length_of::<SockaddrHci>(),
        hci_family: AF_BLUETOOTH_OCTET,
        hci_node: [0; NG_NODESIZ],
    };
    if node.len() >= NG_NODESIZ {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }
    for (slot, byte) in address.hci_node.iter_mut().zip(node.bytes()) {
        *slot = libc::c_char::from_ne_bytes([byte]);
    }
    socket.address(&address, AddressCall::Bind)?;
    socket.address(&address, AddressCall::Connect)?;
    socket.set_filter(&HciRawFilter {
        packet_mask: bitstring(packet_bits),
        event_mask: bitstring(event_bits),
    })?;
    Ok(socket)
}

/// An L2CAP socket on the ATT channel of a new LE connection to
/// `address`, connected within `timeout`.
pub(super) fn connect_att(
    address: [u8; BD_ADDR_SIZE],
    random: bool,
    timeout: Duration,
) -> io::Result<Socket> {
    let socket = open(libc::SOCK_SEQPACKET, BLUETOOTH_PROTO_L2CAP)?;
    let local = SockaddrL2cap {
        l2cap_len: length_of::<SockaddrL2cap>(),
        l2cap_family: AF_BLUETOOTH_OCTET,
        l2cap_psm: NO_PSM.to_le(),
        l2cap_bdaddr: BDADDR_ANY,
        l2cap_cid: ANY_CID.to_le(),
        l2cap_bdaddr_type: BDADDR_LE_PUBLIC,
        tail_padding: 0,
    };
    socket.address(&local, AddressCall::Bind)?;
    let peer = SockaddrL2cap {
        l2cap_bdaddr: address,
        l2cap_cid: NG_L2CAP_ATT_CID.to_le(),
        l2cap_bdaddr_type: if random {
            BDADDR_LE_RANDOM
        } else {
            BDADDR_LE_PUBLIC
        },
        ..local
    };
    socket.set_nonblocking(true)?;
    match socket.address(&peer, AddressCall::Connect) {
        Ok(()) => {}
        Err(error) if error.raw_os_error() == Some(libc::EINPROGRESS) => {
            if !socket.wait(libc::POLLOUT, timeout)? {
                return Err(io::Error::from(io::ErrorKind::TimedOut));
            }
            socket.pending_error()?;
        }
        Err(error) => return Err(error),
    }
    socket.set_nonblocking(false)?;
    Ok(socket)
}
