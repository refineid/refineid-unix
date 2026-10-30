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

//! The system log: one syslog datagram per entry, sent to the local log
//! socket.
//!
//! The datagram is the one `syslog(3)` sends, `<PRI>identifier[pid]:
//! message` (RFC 3164 section 4.1), written here rather than through
//! `openlog(3)`, whose identifier is process-wide: the PKCS#11 module
//! runs inside a browser and leaves the browser's own logging as it is.
//! The log daemon stamps the time. Linux reads the socket with journald
//! or a syslog daemon, FreeBSD with syslogd.

use std::os::unix::net::UnixDatagram;

use crate::record::IDENTIFIER;

/// The local log socket.
#[cfg(target_os = "linux")]
const LOG_SOCKET: &str = "/dev/log";
/// The local log socket.
#[cfg(any(target_os = "freebsd", target_os = "netbsd", target_os = "openbsd"))]
const LOG_SOCKET: &str = "/var/run/log";
/// The local log socket.
#[cfg(target_vendor = "apple")]
const LOG_SOCKET: &str = "/var/run/syslog";
/// The local log socket.
#[cfg(not(any(
    target_os = "linux",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_vendor = "apple"
)))]
const LOG_SOCKET: &str = "/dev/log";

/// The user-level facility (RFC 5424 section 6.2.1, `LOG_USER`).
const FACILITY_USER: u8 = 1;
/// The error severity (RFC 5424 section 6.2.1, `LOG_ERR`).
const SEVERITY_ERROR: u8 = 3;
/// The facility's place in the priority value: facility times eight plus
/// severity (RFC 5424 section 6.2.1).
const FACILITY_SHIFT: u8 = 3;
/// The priority value of every entry.
const PRIORITY: u8 = (FACILITY_USER << FACILITY_SHIFT) | SEVERITY_ERROR;

/// The datagram for `line` from process `pid`.
fn datagram(line: &str, pid: u32) -> String {
    format!("<{PRIORITY}>{IDENTIFIER}[{pid}]: {line}")
}

/// Sends `line` to the system log; a log that cannot be reached loses it.
pub(crate) fn write(line: &str) {
    let Ok(socket) = UnixDatagram::unbound() else {
        return;
    };
    let _ = socket.send_to(datagram(line, std::process::id()).as_bytes(), LOG_SOCKET);
}

#[cfg(test)]
mod tests {
    /// A process identifier for the datagram's shape.
    const PID: u32 = 42;

    #[test]
    fn a_datagram_carries_priority_identifier_and_pid() {
        assert_eq!(
            super::datagram("Gui: event: Cause", PID),
            format!(
                "<{}>{}[{PID}]: Gui: event: Cause",
                super::PRIORITY,
                super::IDENTIFIER
            )
        );
    }
}
