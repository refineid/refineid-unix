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

//! TLS surface for refineid.
//!
//! [`simple_https`] is the address-pinned, server-authenticated HTTPS
//! client used for public-infrastructure fetches (timestamp authorities,
//! EU trusted lists, validator APIs), backed by `rustls` behind the
//! `tls-rustls` feature.
//!
//! [`http`] parses the HTTP/1.1 response status line and `Location`
//! header; [`framing`] reads bounded response bodies.

#[cfg(feature = "tls-rustls")]
pub mod client_auth;
pub mod framing;
pub mod http;
pub mod simple_https;
