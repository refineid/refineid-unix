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
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Error types for the RefineID GUI core and presentation driver layer.

use std::fmt;

/// An error originating from the GUI core controller or presentation driver.
#[derive(Debug)]
pub enum GuiCoreError {
    /// Card communication or reader error.
    Card(String),
    /// Cryptographic or secret validation error.
    Validation(String),
    /// Image decoding or conversion error.
    Image(String),
    /// Signing operation error.
    Signing(String),
    /// RAPP pairing or remote reader error.
    Pairing(String),
    /// Presentation driver initialization or runtime error.
    Driver(String),
    /// IO error.
    Io(std::io::Error),
}

impl fmt::Display for GuiCoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Card(msg) => write!(f, "card error: {msg}"),
            Self::Validation(msg) => write!(f, "validation error: {msg}"),
            Self::Image(msg) => write!(f, "image error: {msg}"),
            Self::Signing(msg) => write!(f, "signing error: {msg}"),
            Self::Pairing(msg) => write!(f, "pairing error: {msg}"),
            Self::Driver(msg) => write!(f, "driver error: {msg}"),
            Self::Io(err) => write!(f, "I/O error: {err}"),
        }
    }
}

impl std::error::Error for GuiCoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<std::io::Error> for GuiCoreError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}
