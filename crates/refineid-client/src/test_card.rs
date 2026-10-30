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

use refineid_lib_core::apdu::iso7816::{ReadBinaryByOffset, SelectByAidNoFci};
use refineid_lib_core::apdu::status_word::{PinRetries, StatusWord};
use refineid_lib_core::atr::{Atr, AtrError, MINIMAL_DIRECT_ATR};
use refineid_lib_core::auth::commands::Verify;
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
/// The certificate the synthetic card holds in every slot.
pub(crate) const CERTIFICATE: &[u8] = include_bytes!("../trust-anchors/dvv-gov-root-ca-g3-rsa.der");

/// The card state a flow test sets up.
#[derive(Debug, Clone)]
pub(crate) struct SyntheticCard {
    /// What a counter-only VERIFY reports.
    pub(crate) pin_tries: PinRetries,
    /// The DER every certificate READ BINARY serves.
    pub(crate) certificate: &'static [u8],
}

impl SyntheticCard {
    /// A card holding [`CERTIFICATE`] whose PIN counter reports `tries`.
    ///
    /// # Errors
    /// `tries` is not a counter value.
    pub(crate) fn with_tries(tries: u8) -> Result<Self, &'static str> {
        Ok(Self {
            pin_tries: PinRetries::from_nibble(tries).ok_or("not a counter value")?,
            certificate: CERTIFICATE,
        })
    }

    fn answer(&self, apdu: &[u8]) -> ResponseApdu {
        let ins = apdu.get(INS_INDEX).copied();
        if ins == Some(Verify::INS) {
            return if apdu.len() == PROBE_LEN {
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
        if ins == Some(ReadBinaryByOffset::INS) {
            return self.read_binary(apdu);
        }
        if ins == Some(PsoComputeDigitalSignature::INS) {
            return respond(vec![ANSWER_FILL; RSA_3072_SIG_BYTES], StatusWord::Success);
        }
        if ins == Some(SelectByAidNoFci::INS) || ins == Some(MseSet::INS) {
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
        let offset = usize::from(u16::from_be_bytes([high, low]));
        let end = offset
            .saturating_add(usize::from(le))
            .min(self.certificate.len());
        let body = self
            .certificate
            .get(offset..end)
            .map_or_else(Vec::new, <[u8]>::to_vec);
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
