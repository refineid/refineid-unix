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

//! Minimal HTTP/1.1 response-head parser for [`crate::simple_https`].

use core::fmt;

use crate::simple_https::SimpleResponse;

/// Separator between the HTTP head and body (RFC 9112 section 2.1).
const HEAD_BODY_SEPARATOR: &[u8] = b"\r\n\r\n";
/// Maximum space-delimited fields split from an HTTP status line
/// (`HTTP-version SP status-code SP [ reason-phrase ]`, RFC 9112 section 4).
const STATUS_LINE_FIELD_LIMIT: usize = 3;
/// Exact digit count of an HTTP status code (`3DIGIT`, RFC 9112 section 4).
const STATUS_CODE_DIGITS: usize = 3;
/// Required leading token prefix of an HTTP/1.x status line (RFC 9112 section 2.3).
const HTTP_VERSION_PREFIX: &str = "HTTP/";
/// Inclusive lower bound of valid three-digit HTTP status codes (RFC 9110 section 15).
const MIN_HTTP_STATUS: u16 = 100;
/// Inclusive upper bound of valid three-digit HTTP status codes (RFC 9110 section 15).
const MAX_HTTP_STATUS: u16 = 599;

/// Why a raw HTTP response failed to parse.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum HttpParseError {
    /// No `CRLF CRLF` head/body separator found.
    NoHeadTerminator,
    /// Head bytes were not UTF-8 (non-UTF-8 `obs-text` in headers or reason phrases is rejected).
    HeadNotUtf8,
    /// Status line missing or its version or status code was invalid.
    MalformedStatusLine,
    /// Extracted response header contained invalid control characters.
    MalformedHeader,
}

impl fmt::Display for HttpParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoHeadTerminator => f.write_str("no end-of-headers marker in HTTP response"),
            Self::HeadNotUtf8 => f.write_str("HTTP head is not UTF-8"),
            Self::MalformedStatusLine => f.write_str("malformed HTTP status line"),
            Self::MalformedHeader => f.write_str("malformed HTTP response header"),
        }
    }
}

impl core::error::Error for HttpParseError {}

/// Split a single framed HTTP/1.1 response into status code, optional
/// `Location` header, and raw body bytes.
///
/// Requires UTF-8 header bytes (failing closed on `obs-text`) and rejects
/// control characters inside `Location`. When multiple `Location` headers are
/// present, the last value wins.
pub(crate) fn parse_response(raw: Vec<u8>) -> Result<SimpleResponse, HttpParseError> {
    let head_end = raw
        .windows(HEAD_BODY_SEPARATOR.len())
        .position(|window| window == HEAD_BODY_SEPARATOR)
        .ok_or(HttpParseError::NoHeadTerminator)?;
    let body_start = head_end.saturating_add(HEAD_BODY_SEPARATOR.len());
    let mut buffer = raw;
    let body = buffer.split_off(body_start);
    buffer.truncate(head_end);
    let head = String::from_utf8(buffer).map_err(|_utf8_error| HttpParseError::HeadNotUtf8)?;

    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or_default();
    let status = parse_status_line(status_line)?;

    let mut location = None;
    for line in lines {
        if let Some((key, value)) = line.split_once(':')
            && key.eq_ignore_ascii_case("location")
        {
            let trimmed = value.trim();
            if trimmed.bytes().any(|byte| byte.is_ascii_control()) {
                return Err(HttpParseError::MalformedHeader);
            }
            location = Some(trimmed.to_owned());
        }
    }

    Ok(SimpleResponse {
        status,
        location,
        body,
    })
}

fn parse_status_line(status_line: &str) -> Result<u16, HttpParseError> {
    let mut parts = status_line.splitn(STATUS_LINE_FIELD_LIMIT, ' ');
    let version = parts.next().ok_or(HttpParseError::MalformedStatusLine)?;
    let Some(digits) = version.strip_prefix(HTTP_VERSION_PREFIX) else {
        return Err(HttpParseError::MalformedStatusLine);
    };
    if !matches!(
        digits.as_bytes(),
        [major, b'.', minor] if major.is_ascii_digit() && minor.is_ascii_digit()
    ) {
        return Err(HttpParseError::MalformedStatusLine);
    }
    let code_text = parts.next().ok_or(HttpParseError::MalformedStatusLine)?;
    if code_text.len() != STATUS_CODE_DIGITS || !code_text.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(HttpParseError::MalformedStatusLine);
    }
    let status = code_text
        .parse::<u16>()
        .map_err(|_parse_error| HttpParseError::MalformedStatusLine)?;
    if !(MIN_HTTP_STATUS..=MAX_HTTP_STATUS).contains(&status) {
        return Err(HttpParseError::MalformedStatusLine);
    }
    Ok(status)
}

#[cfg(test)]
mod tests {
    use super::{HttpParseError, parse_response};

    const HTTP_OK: u16 = 200;
    const HTTP_FOUND: u16 = 302;
    const NON_UTF8_OCTET: u8 = 0xFF;

    #[test]
    fn parses_redirect_location_and_preserves_binary_body() {
        let mut raw = b"HTTP/1.1 302 Found\r\n\
            Content-Type: application/octet-stream\r\n\
            LoCaTiOn:  https://example.com/next \r\n\
            \r\n"
            .to_vec();
        let expected_body = vec![NON_UTF8_OCTET, b'A'];
        raw.extend_from_slice(&expected_body);

        let parsed = parse_response(raw).expect("valid HTTP response");
        assert_eq!(parsed.status, HTTP_FOUND);
        assert_eq!(parsed.location.as_deref(), Some("https://example.com/next"));
        assert_eq!(parsed.body, expected_body);
    }

    #[test]
    fn parses_status_line_without_reason_phrase() {
        let raw = b"HTTP/1.1 200\r\nContent-Length: 2\r\n\r\nOK".to_vec();
        let parsed = parse_response(raw).expect("reason-free status line");
        assert_eq!(parsed.status, HTTP_OK);
        assert_eq!(parsed.location, None);
        assert_eq!(parsed.body, b"OK");
    }

    #[test]
    fn rejects_missing_terminator_non_utf8_head_and_malformed_status_lines() {
        assert_eq!(
            parse_response(b"HTTP/1.1 200 OK\r\n".to_vec()),
            Err(HttpParseError::NoHeadTerminator)
        );

        let mut non_utf8_head = vec![b'H', NON_UTF8_OCTET];
        non_utf8_head.extend_from_slice(b"\r\n\r\n");
        assert_eq!(
            parse_response(non_utf8_head),
            Err(HttpParseError::HeadNotUtf8)
        );

        for bad_head in [
            "\r\n\r\n",
            "GARBAGE\r\n\r\n",
            "NOTHTTP/1.1 200 OK\r\n\r\n",
            "HTTP/ 200 OK\r\n\r\n",
            "HTTP/1.1x 200 OK\r\n\r\n",
            "HTTP/1.1 +20 OK\r\n\r\n",
            "HTTP/1.1 20 OK\r\n\r\n",
            "HTTP/1.1 2000 OK\r\n\r\n",
            "HTTP/1.1 099 Low\r\n\r\n",
            "HTTP/1.1 600 High\r\n\r\n",
        ] {
            assert_eq!(
                parse_response(bad_head.as_bytes().to_vec()),
                Err(HttpParseError::MalformedStatusLine),
                "head: {bad_head:?}"
            );
        }

        assert_eq!(
            parse_response(
                b"HTTP/1.1 302 Found\r\nLocation: https://example.com/\0bad\r\n\r\n".to_vec()
            ),
            Err(HttpParseError::MalformedHeader)
        );
    }
}
