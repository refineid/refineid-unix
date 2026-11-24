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

//! A synthetic reader backend and card for flow tests.
//!
//! The card answers by instruction byte, not by a fixed script, so a
//! flow test states the card's state (PIN counter, certificate) and
//! not the exact APDU sequence the flow sends.

use refineid_lib_core::apdu::iso7816::{ReadBinary, SelectByAidNoFci};
use refineid_lib_core::apdu::status_word::{PinRetries, StatusWord};
use refineid_lib_core::atr::{Atr, AtrError, MINIMAL_DIRECT_ATR};
use refineid_lib_core::auth::commands::Verify;
use refineid_lib_core::auth::{PinReferenceScheme, PinSlot};
use refineid_lib_core::backend::{ReaderAccessCap, ReaderBackend, ReaderId, ReaderInfo};
use refineid_lib_core::sign::RSA_3072_SIG_BYTES;
use refineid_lib_core::sign::commands::{MseSet, PsoComputeDigitalSignature};
use refineid_lib_core::transport::{CardTransport, CommandApdu, ResponseApdu, TransportOutcome};
use refineid_lib_pcsc::PcscError;

use crate::card_sign::CardReset;

/// Synthetic reader name (AGENTS.md RULE #3).
pub(crate) const SYNTHETIC_READER: &str = "Synthetic Card Reader";

/// Offset of INS in a command APDU (ISO 7816-4 s5.1).
const INS_INDEX: usize = 1;
/// Offset of P1 in a command APDU (ISO 7816-4 s5.1).
const P1_INDEX: usize = 2;
/// Offset of P2 in a command APDU (ISO 7816-4 s5.1).
const P2_INDEX: usize = 3;
/// Length of the CLA INS P1 P2 header (ISO 7816-4 s5.1).
const HEADER_LEN: usize = 4;
/// Length of the counter-only VERIFY: the header and `Lc=00`, no PIN
/// (FINEID S1 v4.2 s3.5.1.1).
const PROBE_LEN: usize = HEADER_LEN + 1;
/// Fill byte of the card's synthetic PSO answers.
const ANSWER_FILL: u8 = b'S';
/// A PIN counter the retry floor serves (five, four or three tries).
pub(crate) const TRIES_SERVED: u8 = 5;
/// A PIN counter the retry floor refuses (two, one or no tries).
pub(crate) const TRIES_BELOW_FLOOR: u8 = 2;
/// The certificate the card holds in every slot: the public DVV root,
/// a real certificate standing in for the card's own.
pub(crate) const CERTIFICATE: &[u8] = include_bytes!("../test-vectors/dvv-gov-root-ca-g3-rsa.der");
/// An alternate certificate standing in for a second card.
pub(crate) const ALT_CERTIFICATE: &[u8] =
    include_bytes!("../test-vectors/dvv-gov-root-ca-g3-ecc.der");

/// Synthetic EF.TokenInfo with serial "CARD-A":
/// 30 0b 02 01 00 04 06 43 41 52 44 2d 41
pub(crate) const TOKEN_INFO_A: &[u8] = &[
    0x30, 0x0b, 0x02, 0x01, 0x00, 0x04, 0x06, b'C', b'A', b'R', b'D', b'-', b'A',
];

/// Synthetic EF.TokenInfo with serial "CARD-B":
/// 30 0b 02 01 00 04 06 43 41 52 44 2d 42
pub(crate) const TOKEN_INFO_B: &[u8] = &[
    0x30, 0x0b, 0x02, 0x01, 0x00, 0x04, 0x06, b'C', b'A', b'R', b'D', b'-', b'B',
];

/// The currently selected file on the card.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SelectedFile {
    Certificate,
    TokenInfo,
}

/// The card state a flow test sets up.
#[derive(Debug, Clone)]
pub(crate) struct SyntheticCard {
    /// What a counter-only VERIFY reports.
    pub(crate) pin_tries: PinRetries,
    /// Credential reference numbering the synthetic card answers to.
    pub(crate) scheme: PinReferenceScheme,
    /// The DER every certificate READ BINARY serves.
    pub(crate) certificate: &'static [u8],
    /// The DER EF.TokenInfo READ BINARY serves.
    pub(crate) token_info: Option<&'static [u8]>,
    /// The currently selected file.
    pub(crate) selected_file: SelectedFile,
    /// Whether to reject PIN verification attempts.
    pub(crate) reject_pin: bool,
    /// Count of credential VERIFY (non-probe) and MSE/PSO APDUs observed.
    pub(crate) credential_or_sign_apdus: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl SyntheticCard {
    /// A card holding [`CERTIFICATE`] whose PIN counter reports `tries`.
    ///
    /// # Errors
    /// `tries` is not a counter value.
    pub(crate) fn with_tries(tries: u8) -> Result<Self, &'static str> {
        Ok(Self {
            pin_tries: PinRetries::from_nibble(tries).ok_or("not a counter value")?,
            scheme: PinReferenceScheme::Citizen,
            certificate: CERTIFICATE,
            token_info: Some(TOKEN_INFO_A),
            selected_file: SelectedFile::Certificate,
            reject_pin: false,
            credential_or_sign_apdus: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        })
    }

    /// An Estonian eID synthetic card answering only Estonian PIN1 probes.
    ///
    /// # Errors
    /// `tries` is not a counter value.
    pub(crate) fn estonian(tries: u8) -> Result<Self, &'static str> {
        Ok(Self {
            pin_tries: PinRetries::from_nibble(tries).ok_or("not a counter value")?,
            scheme: PinReferenceScheme::Estonian,
            certificate: CERTIFICATE,
            token_info: Some(TOKEN_INFO_A),
            selected_file: SelectedFile::Certificate,
            reject_pin: false,
            credential_or_sign_apdus: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        })
    }

    /// A card that rejects full PIN verification attempts with `tries` retries remaining.
    pub(crate) fn with_wrong_pin(tries: u8) -> Result<Self, &'static str> {
        Ok(Self {
            pin_tries: PinRetries::from_nibble(tries).ok_or("not a counter value")?,
            scheme: PinReferenceScheme::Citizen,
            certificate: CERTIFICATE,
            token_info: Some(TOKEN_INFO_A),
            selected_file: SelectedFile::Certificate,
            reject_pin: true,
            credential_or_sign_apdus: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        })
    }

    /// A second distinct card holding [`ALT_CERTIFICATE`] and serial "CARD-B".
    ///
    /// # Errors
    /// `tries` is not a counter value.
    pub(crate) fn card_b(tries: u8) -> Result<Self, &'static str> {
        Ok(Self {
            pin_tries: PinRetries::from_nibble(tries).ok_or("not a counter value")?,
            scheme: PinReferenceScheme::Citizen,
            certificate: ALT_CERTIFICATE,
            token_info: Some(TOKEN_INFO_B),
            selected_file: SelectedFile::Certificate,
            reject_pin: false,
            credential_or_sign_apdus: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        })
    }

    /// Number of credential VERIFY or signing (MSE/PSO) APDUs received.
    pub(crate) fn credential_or_sign_apdu_count(&self) -> usize {
        self.credential_or_sign_apdus
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    fn answer(&mut self, apdu: &[u8]) -> ResponseApdu {
        let ins = apdu.get(INS_INDEX).copied();
        if ins == Some(Verify::INS) {
            let is_probe = apdu.len() == PROBE_LEN;
            if !is_probe {
                self.credential_or_sign_apdus
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
            if self.scheme == PinReferenceScheme::Estonian {
                let p2 = apdu.get(P2_INDEX).copied();
                let allowed = p2 == Some(PinReferenceScheme::Estonian.p2_reference(PinSlot::Pin1))
                    || p2 == Some(PinReferenceScheme::Estonian.puk_reference());
                if !allowed {
                    return respond(Vec::new(), StatusWord::ReferenceDataNotFound);
                }
            }
            return if is_probe || self.reject_pin {
                respond(
                    Vec::new(),
                    StatusWord::PinIncorrect {
                        retries: self.pin_tries,
                    },
                )
            } else {
                respond(Vec::new(), StatusWord::Success)
            };
        }
        if ins == Some(ReadBinary::INS) {
            return self.read_binary(apdu);
        }
        if ins == Some(PsoComputeDigitalSignature::INS) {
            self.credential_or_sign_apdus
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            return respond(vec![ANSWER_FILL; RSA_3072_SIG_BYTES], StatusWord::Success);
        }
        if ins == Some(SelectByAidNoFci::INS) {
            // EF.TokenInfo FID is 0x5032
            if apdu.get(5..7) == Some(&[0x50, 0x32]) {
                self.selected_file = SelectedFile::TokenInfo;
            } else {
                self.selected_file = SelectedFile::Certificate;
            }
            return respond(Vec::new(), StatusWord::Success);
        }
        if ins == Some(MseSet::INS) {
            self.credential_or_sign_apdus
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            return respond(Vec::new(), StatusWord::Success);
        }
        respond(Vec::new(), StatusWord::FileNotFound)
    }

    fn read_binary(&self, apdu: &[u8]) -> ResponseApdu {
        let (Some(&high), Some(&low), Some(&le)) =
            (apdu.get(P1_INDEX), apdu.get(P2_INDEX), apdu.last())
        else {
            return respond(Vec::new(), StatusWord::FileNotFound);
        };
        let data = match self.selected_file {
            SelectedFile::TokenInfo => self.token_info.unwrap_or(&[]),
            SelectedFile::Certificate => self.certificate,
        };
        let offset = usize::from(u16::from_be_bytes([high, low]));
        let end = offset.saturating_add(usize::from(le)).min(data.len());
        let body = data.get(offset..end).map_or_else(Vec::new, <[u8]>::to_vec);
        respond(body, StatusWord::Success)
    }
}

fn respond(body: Vec<u8>, status: StatusWord) -> ResponseApdu {
    let [sw1, sw2] = status.as_u16().to_be_bytes();
    ResponseApdu { body, sw1, sw2 }
}

impl CardTransport for SyntheticCard {
    type Error = String;

    fn transmit_outcome(&mut self, apdu: &CommandApdu) -> Result<TransportOutcome, Self::Error> {
        Ok(TransportOutcome::Response(self.answer(apdu.as_bytes())))
    }

    fn atr(&self) -> Result<Atr, AtrError> {
        Atr::new(MINIMAL_DIRECT_ATR)
    }
}

impl CardReset for SyntheticCard {
    fn reset_card(&mut self) -> Result<(), PcscError> {
        Ok(())
    }
}

/// Readers and the card in them.
pub(crate) struct SyntheticBackend {
    /// What enumeration reports.
    pub(crate) readers: Vec<ReaderInfo>,
    /// The card every session opens.
    pub(crate) card: SyntheticCard,
}

impl SyntheticBackend {
    /// One synthetic reader, with `card` inserted or not.
    pub(crate) fn one_reader(card_present: bool, card: SyntheticCard) -> Self {
        Self {
            readers: vec![ReaderInfo {
                id: ReaderId::new(SYNTHETIC_READER.to_owned()),
                card_present,
            }],
            card,
        }
    }
}

impl ReaderBackend for SyntheticBackend {
    type Transport = SyntheticCard;
    type Error = PcscError;

    fn enumerate(&self) -> Result<Vec<ReaderInfo>, Self::Error> {
        Ok(self.readers.clone())
    }

    fn open_session(
        &self,
        _reader: &ReaderId,
        _access: ReaderAccessCap,
    ) -> Result<Self::Transport, Self::Error> {
        Ok(self.card.clone())
    }
}

/// A thread-safe reader backend allowing card swap and card removal for testing.
#[derive(Clone)]
pub(crate) struct SwappableBackend {
    pub(crate) readers: std::sync::Arc<std::sync::Mutex<Vec<ReaderInfo>>>,
    pub(crate) card: std::sync::Arc<std::sync::Mutex<Option<SyntheticCard>>>,
}

impl SwappableBackend {
    pub(crate) fn new(card: SyntheticCard) -> Self {
        Self {
            readers: std::sync::Arc::new(std::sync::Mutex::new(vec![ReaderInfo {
                id: ReaderId::new(SYNTHETIC_READER.to_owned()),
                card_present: true,
            }])),
            card: std::sync::Arc::new(std::sync::Mutex::new(Some(card))),
        }
    }

    pub(crate) fn swap_card(&self, card: SyntheticCard) {
        if let Ok(mut c) = self.card.lock() {
            *c = Some(card);
        }
        if let Ok(mut r) = self.readers.lock()
            && let Some(reader) = r.first_mut()
        {
            reader.card_present = true;
        }
    }

    pub(crate) fn remove_card(&self) {
        if let Ok(mut c) = self.card.lock() {
            *c = None;
        }
        if let Ok(mut r) = self.readers.lock()
            && let Some(reader) = r.first_mut()
        {
            reader.card_present = false;
        }
    }
}

impl ReaderBackend for SwappableBackend {
    type Transport = SyntheticCard;
    type Error = PcscError;

    fn enumerate(&self) -> Result<Vec<ReaderInfo>, Self::Error> {
        self.readers
            .lock()
            .map(|r| r.clone())
            .map_err(|_| PcscError::Transport("readers lock poisoned".to_owned()))
    }

    fn open_session(
        &self,
        _reader: &ReaderId,
        _access: ReaderAccessCap,
    ) -> Result<Self::Transport, Self::Error> {
        let guard = self
            .card
            .lock()
            .map_err(|_| PcscError::Transport("card lock poisoned".to_owned()))?;
        guard
            .clone()
            .ok_or_else(|| PcscError::Transport("no card in reader".to_owned()))
    }
}
