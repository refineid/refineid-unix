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

//! Card-side signing and RSA decipher primitives, delegated to `refineid-sign`.
//!
//! Authentication-key signatures and RSA-3072 decipher operations delegate
//! directly to [`refineid_sign::SignOps`] through the internal `CoreReads`
//! transport bridge. Qualified-signature calls (where the caller already
//! verified PIN 2 — and entered `DF.ESIGN` on organizational cards — on the
//! transport) reuse [`refineid_sign::commands`] over `CoreReads`. Only
//! `SHA-512 + ECDSA` constructs its `MSE:SET DST` command locally with
//! `refineid_apdu::CommandApdu::case_3` until `refineid-sign` exposes that
//! algorithm reference.

pub use refineid_sign::commands;
pub use refineid_sign::commands::{
    SHA256_LEN as SHA256_DIGEST_LEN, SHA384_LEN as SHA384_DIGEST_LEN,
    SHA512_LEN as SHA512_DIGEST_LEN,
};
pub use refineid_sign::{
    ECDSA_P256_SIG_BYTES, ECDSA_P384_SIG_BYTES, KEY_REF_AUTH, KEY_REF_SIGN, ORG_QUALIFIED_KEY_REF,
    RSA_3072_MODULUS_BYTES, RSA_3072_SIG_BYTES, RecoveredPlaintext, SignScheme,
};

use refineid_apdu::{ApduClass, CommandHeader, StatusWord};
use refineid_sign::SignOps as _;
use refineid_sign::commands::{
    DecipherAlgRef, ExternalHashValue, MSE_INS, MseSet, PsoComputeDigitalSignature,
    PsoHashExternal, SignatureAlgRef, expected_length_le,
};

use crate::auth::{CoreReadError, CoreReads, PinReferenceScheme};
use crate::crypto::container::{
    Ciphertext, EcdsaP256, EcdsaP384, RsaPkcs1, RsaPkcs1Sha256, Signature,
};
use crate::crypto::digest::{Sha256, Sha384, Sha512};
use crate::transport::{CardTransport, TransportDispatchError};

/// Shortened transport-error alias for sign-path dispatchers.
type TxError<T> = TransportDispatchError<<T as CardTransport>::Error>;

/// MSE:SET P1 selecting computation and decipherment (FINEID S1 v4.2 §3.6.2).
const MSE_P1_SET: u8 = 0x41;
/// MSE:SET P2 for the digital-signature template (FINEID S1 v4.2 §3.6.2).
const MSE_P2_DST: u8 = 0xB6;
/// Control-reference-object tag for the algorithm reference.
const CRDO_ALG_REF: u8 = 0x80;
/// Control-reference-object tag for the key reference.
const CRDO_KEY_REF: u8 = 0x84;
/// Single-byte control-reference-object value length.
const CRDO_VALUE_LEN: u8 = 0x01;
/// Algorithm reference for SHA-512 + ECDSA (high nibble 6 = SHA-512,
/// low nibble 4 = ECDSA; FINEID S1 v4.2 §3.6.3 Table 6).
const ALG_SHA512_ECDSA: u8 = 0x64;
/// ISO 7816-4 status word: conditions of use not satisfied.
const SW_CONDITIONS_NOT_SATISFIED: u16 = 0x6985;
/// ISO 7816-4 status word: incorrect parameters in the command data field.
const SW_INCORRECT_DATA: u16 = 0x6A80;

/// Credential numbering families that support qualified signing in
/// `refineid-lib-core`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum QualifiedSignScheme {
    /// FINEID S1 citizen card ([`KEY_REF_SIGN`]).
    Citizen,
    /// FINEID S4 organizational card ([`ORG_QUALIFIED_KEY_REF`] in `DF.ESIGN`).
    Organizational,
}

/// Refusal when a card family has no supported qualified signing path
/// in `refineid-lib-core`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnsupportedQualifiedScheme(pub PinReferenceScheme);

impl core::fmt::Display for UnsupportedQualifiedScheme {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "qualified signing is not supported under {:?}", self.0)
    }
}

impl core::error::Error for UnsupportedQualifiedScheme {}

impl TryFrom<PinReferenceScheme> for QualifiedSignScheme {
    type Error = UnsupportedQualifiedScheme;

    fn try_from(scheme: PinReferenceScheme) -> Result<Self, Self::Error> {
        match scheme {
            PinReferenceScheme::Citizen => Ok(Self::Citizen),
            PinReferenceScheme::Organizational => Ok(Self::Organizational),
            PinReferenceScheme::Estonian => Err(UnsupportedQualifiedScheme(scheme)),
        }
    }
}

/// Private-key reference, typed at the sign-API boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyRef {
    /// Authentication key, PIN1-gated ([`KEY_REF_AUTH`]).
    Auth,
    /// Authentication key whose reference was discovered from an ISO/IEC
    /// 7816-15 `EF.PrKDF` entry (e.g. Estonian eID).
    DiscoveredAuth(refineid_pkcs15::KeyReference),
    /// Qualified-signature key, PIN2-gated, under a supported
    /// qualified-signing family.
    Sign(QualifiedSignScheme),
}

impl KeyRef {
    /// Build a [`KeyRef::DiscoveredAuth`] from a typed `EF.PrKDF` key
    /// reference resolved by ISO/IEC 7816-15 directory discovery.
    #[must_use]
    pub const fn discovered_auth(reference: refineid_pkcs15::KeyReference) -> Self {
        Self::DiscoveredAuth(reference)
    }

    /// The card-side reference byte for MSE:SET DST/CT.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::Auth => KEY_REF_AUTH,
            Self::DiscoveredAuth(reference) => reference.as_u8(),
            Self::Sign(QualifiedSignScheme::Citizen) => KEY_REF_SIGN,
            Self::Sign(QualifiedSignScheme::Organizational) => ORG_QUALIFIED_KEY_REF,
        }
    }

    /// `true` when the card takes the host digest inside PSO:CDS for
    /// this key instead of a preceding PSO:HASH: the organizational
    /// qualified key.
    #[must_use]
    pub const fn signs_digest_inline(self) -> bool {
        matches!(self, Self::Sign(QualifiedSignScheme::Organizational))
    }
}

/// Sign-path errors.
#[derive(Debug)]
pub enum SignError<TE> {
    /// Transport-layer failure.
    Transport(TE),
    /// Card returned a non-success SW at the labelled stage.
    Sw(&'static str, u16),
    /// Card returned a signature of an unexpected length, or a decipher
    /// ciphertext was not modulus-wide.
    UnexpectedSignatureLength(usize),
    /// Host input cannot be represented by the ISO 7816 APDU length field.
    InputTooLong(usize),
}

impl<TE: core::fmt::Display> core::fmt::Display for SignError<TE> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "sign transport: {e}"),
            Self::Sw(stage, sw) => write!(f, "sign {stage}: card returned SW={sw:#06X}"),
            Self::UnexpectedSignatureLength(n) => {
                write!(f, "sign: card returned unexpected {n}-byte length")
            }
            Self::InputTooLong(n) => write!(
                f,
                "sign: {n}-byte input exceeds the ISO 7816 signing command length"
            ),
        }
    }
}

impl<TE: core::fmt::Debug + core::fmt::Display + 'static> core::error::Error for SignError<TE> {}

/// Map a `refineid-sign` error over [`CoreReads`] into [`SignError`].
fn map_core_sign_error<E>(
    error: refineid_sign::SignError<CoreReadError<E>>,
) -> SignError<TransportDispatchError<E>> {
    match error {
        refineid_sign::SignError::Transport(CoreReadError::Transport(err)) => {
            SignError::Transport(TransportDispatchError::Error(err))
        }
        refineid_sign::SignError::Transport(CoreReadError::CredentialCommand) => {
            SignError::Sw("sign", SW_CONDITIONS_NOT_SATISFIED)
        }
        refineid_sign::SignError::Outcome(outcome) => {
            SignError::Transport(TransportDispatchError::Outcome(outcome))
        }
        refineid_sign::SignError::Status(stage, sw) => SignError::Sw(stage, sw.as_u16()),
        refineid_sign::SignError::Command(_) => SignError::InputTooLong(0),
        refineid_sign::SignError::UnsupportedKey { .. } => {
            SignError::Sw("MSE:Set", StatusWord::ReferenceDataNotFound.as_u16())
        }
        refineid_sign::SignError::UnexpectedSignatureLength { got, .. } => {
            SignError::UnexpectedSignatureLength(got)
        }
    }
}

/// Send one `refineid-apdu` command over [`CoreReads`] (preserving `6Cxx`
/// wrong-`Le` correction) and require `9000`.
fn exchange_core_apdu<T: CardTransport>(
    transport: &mut T,
    apdu: &refineid_apdu::CommandApdu,
    stage: &'static str,
) -> Result<Vec<u8>, SignError<TxError<T>>> {
    let response = refineid_apdu::CardTransport::transmit(&mut CoreReads(transport), apdu)
        .map_err(|err| match err {
            CoreReadError::Transport(inner) => {
                SignError::Transport(TransportDispatchError::Error(inner))
            }
            CoreReadError::CredentialCommand => SignError::Sw(stage, SW_CONDITIONS_NOT_SATISFIED),
        })?
        .into_response()
        .map_err(|outcome| SignError::Transport(TransportDispatchError::Outcome(outcome)))?;
    if !response.is_ok() {
        return Err(SignError::Sw(stage, response.status_word().as_u16()));
    }
    Ok(response.body)
}

/// Drive the `MSE:SET DST` -> (`PSO:HASH` + empty `PSO:CDS` | inline `PSO:CDS`)
/// chain using `refineid_sign::commands`, for keys whose PIN 2 was already
/// verified by the caller.
fn drive_prehashed_chain<T: CardTransport>(
    transport: &mut T,
    alg_ref: SignatureAlgRef,
    key_ref: KeyRef,
    hash: ExternalHashValue,
    inline_digest: bool,
    expected_bytes: usize,
) -> Result<Vec<u8>, SignError<TxError<T>>> {
    let mse = MseSet {
        alg_ref,
        key_ref: key_ref.as_u8(),
    }
    .into_apdu()
    .map_err(|_| SignError::InputTooLong(0))?;
    exchange_core_apdu(transport, &mse, "MSE:Set DST")?;

    let le = expected_length_le(expected_bytes);
    let cds = if inline_digest {
        PsoComputeDigitalSignature
            .into_apdu_with_digest(hash, le)
            .map_err(|_| SignError::InputTooLong(hash.as_bytes().len()))?
    } else {
        let pso_hash = PsoHashExternal { hash }
            .into_apdu()
            .map_err(|_| SignError::InputTooLong(hash.as_bytes().len()))?;
        exchange_core_apdu(transport, &pso_hash, "PSO:HASH")?;
        PsoComputeDigitalSignature.into_apdu(le)
    };
    let sig = exchange_core_apdu(transport, &cds, "PSO:CDS")?;
    if sig.len() != expected_bytes {
        return Err(SignError::UnexpectedSignatureLength(sig.len()));
    }
    Ok(sig)
}

/// Construct a `refineid_sign::SigningKey` for an authentication [`KeyRef`]
/// under `scheme`, or return `None` for qualified [`KeyRef::Sign`].
///
/// Discovered `EF.PrKDF` keys use [`SignScheme::Estonian`] when no explicit
/// organizational inline-digest scheme was requested.
fn core_auth_key<'r, 't, T: CardTransport>(
    reads: &'r mut CoreReads<'t, T>,
    key_ref: KeyRef,
    scheme: SignScheme,
) -> Option<refineid_sign::SigningKey<'r, CoreReads<'t, T>>> {
    match key_ref {
        KeyRef::Auth => Some(reads.authentication_key(scheme)),
        KeyRef::DiscoveredAuth(reference) => {
            let effective = if scheme == SignScheme::Organizational {
                SignScheme::Organizational
            } else {
                SignScheme::Estonian
            };
            Some(reads.authentication_key_with_reference(effective, reference))
        }
        KeyRef::Sign(_) => None,
    }
}

/// FINEID sign / decrypt chain layered as default-impl methods on
/// every [`CardTransport`], delegated to `refineid-sign`.
pub trait SignOps: CardTransport {
    /// SHA-256 + RSA-PKCS1v15 sign chain for any FINEID RSA key.
    ///
    /// # Errors
    /// Transport failure, non-9000 SW, or signature length mismatch.
    fn sign_pre_hashed_sha256_rsa(
        &mut self,
        key_ref: KeyRef,
        hash: Sha256,
    ) -> Result<Signature<RsaPkcs1Sha256>, SignError<TxError<Self>>>
    where
        Self: Sized,
    {
        let mut reads = CoreReads(self);
        if let Some(key) = core_auth_key(&mut reads, key_ref, SignScheme::Citizen) {
            let sig = key
                .sign_prehashed_sha256_rsa(*hash.as_bytes())
                .map_err(map_core_sign_error)?;
            return Ok(Signature::new(sig.into_bytes()));
        }
        let bytes = drive_prehashed_chain(
            self,
            SignatureAlgRef::SHA256_RSA_PKCS1,
            key_ref,
            ExternalHashValue::Sha256(*hash.as_bytes()),
            key_ref.signs_digest_inline(),
            RSA_3072_SIG_BYTES,
        )?;
        Ok(Signature::new(bytes))
    }

    /// [`Self::sign_pre_hashed_sha256_rsa`] in the organizational card's
    /// inline-digest form (no `PSO:HASH`).
    ///
    /// # Errors
    /// As [`Self::sign_pre_hashed_sha256_rsa`].
    fn sign_pre_hashed_sha256_rsa_hash_in_command(
        &mut self,
        key_ref: KeyRef,
        hash: Sha256,
    ) -> Result<Signature<RsaPkcs1Sha256>, SignError<TxError<Self>>>
    where
        Self: Sized,
    {
        let mut reads = CoreReads(self);
        if let Some(key) = core_auth_key(&mut reads, key_ref, SignScheme::Organizational) {
            let sig = key
                .sign_prehashed_sha256_rsa(*hash.as_bytes())
                .map_err(map_core_sign_error)?;
            return Ok(Signature::new(sig.into_bytes()));
        }
        let bytes = drive_prehashed_chain(
            self,
            SignatureAlgRef::SHA256_RSA_PKCS1,
            key_ref,
            ExternalHashValue::Sha256(*hash.as_bytes()),
            true,
            RSA_3072_SIG_BYTES,
        )?;
        Ok(Signature::new(bytes))
    }

    /// Pre-hashed RSA-PKCS#1 v1.5 sign over SHA-256, SHA-384, or SHA-512
    /// against `key_ref`.
    ///
    /// # Errors
    /// Transport failure, non-9000 SW, unsupported weak digest, or signature
    /// length mismatch.
    fn sign_pre_hashed_rsa_pkcs1(
        &mut self,
        key_ref: KeyRef,
        hash: ExternalHashValue,
    ) -> Result<Signature<RsaPkcs1>, SignError<TxError<Self>>>
    where
        Self: Sized,
    {
        let mut reads = CoreReads(self);
        if let Some(key) = core_auth_key(&mut reads, key_ref, SignScheme::Citizen) {
            let bytes = match hash {
                ExternalHashValue::Sha256(digest) => key
                    .sign_prehashed_sha256_rsa(digest)
                    .map_err(map_core_sign_error)?
                    .into_bytes(),
                ExternalHashValue::Sha384(digest) => key
                    .sign_prehashed_sha384_rsa(digest)
                    .map_err(map_core_sign_error)?
                    .into_bytes(),
                ExternalHashValue::Sha512(digest) => key
                    .sign_prehashed_sha512_rsa(digest)
                    .map_err(map_core_sign_error)?
                    .into_bytes(),
                ExternalHashValue::Sha1(_) | ExternalHashValue::Sha224(_) => {
                    return Err(SignError::Sw("MSE:Set DST", SW_INCORRECT_DATA));
                }
            };
            return Ok(Signature::new(bytes));
        }
        let alg_ref = match hash {
            ExternalHashValue::Sha256(_) => SignatureAlgRef::SHA256_RSA_PKCS1,
            ExternalHashValue::Sha384(_) => SignatureAlgRef::SHA384_RSA_PKCS1,
            ExternalHashValue::Sha512(_) => SignatureAlgRef::SHA512_RSA_PKCS1,
            ExternalHashValue::Sha1(_) | ExternalHashValue::Sha224(_) => {
                return Err(SignError::Sw("MSE:Set DST", SW_INCORRECT_DATA));
            }
        };
        let bytes = drive_prehashed_chain(
            self,
            alg_ref,
            key_ref,
            hash,
            key_ref.signs_digest_inline(),
            RSA_3072_SIG_BYTES,
        )?;
        Ok(Signature::new(bytes))
    }

    /// SHA-256 + ECDSA P-384 sign chain returning raw `r || s` (96 bytes).
    ///
    /// # Errors
    /// Transport failure, non-9000 SW, or signature length mismatch.
    fn sign_pre_hashed_sha256_ecdsa_p384(
        &mut self,
        key_ref: KeyRef,
        hash: Sha256,
    ) -> Result<Signature<EcdsaP384>, SignError<TxError<Self>>>
    where
        Self: Sized,
    {
        let mut reads = CoreReads(self);
        if let Some(key) = core_auth_key(&mut reads, key_ref, SignScheme::Citizen) {
            let sig = key
                .sign_prehashed_sha256_ecdsa(*hash.as_bytes())
                .map_err(map_core_sign_error)?;
            return Ok(Signature::new(sig.into_bytes()));
        }
        let bytes = drive_prehashed_chain(
            self,
            SignatureAlgRef::SHA256_ECDSA,
            key_ref,
            ExternalHashValue::Sha256(*hash.as_bytes()),
            key_ref.signs_digest_inline(),
            ECDSA_P384_SIG_BYTES,
        )?;
        Ok(Signature::new(bytes))
    }

    /// SHA-384 + ECDSA P-384 sign chain returning raw `r || s` (96 bytes).
    ///
    /// # Errors
    /// Transport failure, non-9000 SW, or signature length mismatch.
    fn sign_pre_hashed_sha384_ecdsa_p384(
        &mut self,
        key_ref: KeyRef,
        hash: Sha384,
    ) -> Result<Signature<EcdsaP384>, SignError<TxError<Self>>>
    where
        Self: Sized,
    {
        let mut reads = CoreReads(self);
        if let Some(key) = core_auth_key(&mut reads, key_ref, SignScheme::Citizen) {
            let sig = key
                .sign_prehashed_sha384_ecdsa(*hash.as_bytes())
                .map_err(map_core_sign_error)?;
            return Ok(Signature::new(sig.into_bytes()));
        }
        let bytes = drive_prehashed_chain(
            self,
            SignatureAlgRef::SHA384_ECDSA,
            key_ref,
            ExternalHashValue::Sha384(*hash.as_bytes()),
            key_ref.signs_digest_inline(),
            ECDSA_P384_SIG_BYTES,
        )?;
        Ok(Signature::new(bytes))
    }

    /// SHA-512 + ECDSA P-384 sign chain returning raw `r || s` (96 bytes).
    ///
    /// # Errors
    /// Transport failure, non-9000 SW, or signature length mismatch.
    fn sign_pre_hashed_sha512_ecdsa_p384(
        &mut self,
        key_ref: KeyRef,
        hash: Sha512,
    ) -> Result<Signature<EcdsaP384>, SignError<TxError<Self>>>
    where
        Self: Sized,
    {
        let mse_data = [
            CRDO_ALG_REF,
            CRDO_VALUE_LEN,
            ALG_SHA512_ECDSA,
            CRDO_KEY_REF,
            CRDO_VALUE_LEN,
            key_ref.as_u8(),
        ];
        let mse = refineid_apdu::CommandApdu::case_3(
            CommandHeader {
                class: ApduClass::Plain,
                instruction: MSE_INS,
                p1: MSE_P1_SET,
                p2: MSE_P2_DST,
            },
            &mse_data,
        )
        .map_err(|_| SignError::InputTooLong(mse_data.len()))?;
        exchange_core_apdu(self, &mse, "MSE:Set DST")?;

        let ext_hash = ExternalHashValue::Sha512(*hash.as_bytes());
        let le = expected_length_le(ECDSA_P384_SIG_BYTES);
        let cds = if key_ref.signs_digest_inline() {
            PsoComputeDigitalSignature
                .into_apdu_with_digest(ext_hash, le)
                .map_err(|_| SignError::InputTooLong(ext_hash.as_bytes().len()))?
        } else {
            let pso_hash = PsoHashExternal { hash: ext_hash }
                .into_apdu()
                .map_err(|_| SignError::InputTooLong(ext_hash.as_bytes().len()))?;
            exchange_core_apdu(self, &pso_hash, "PSO:HASH")?;
            PsoComputeDigitalSignature.into_apdu(le)
        };
        let sig = exchange_core_apdu(self, &cds, "PSO:CDS")?;
        if sig.len() != ECDSA_P384_SIG_BYTES {
            return Err(SignError::UnexpectedSignatureLength(sig.len()));
        }
        Ok(Signature::new(sig))
    }

    /// SHA-256 + ECDSA P-256 sign chain returning raw `r || s` (64 bytes).
    ///
    /// # Errors
    /// Transport failure, non-9000 SW, or signature length mismatch.
    fn sign_pre_hashed_sha256_ecdsa_p256(
        &mut self,
        key_ref: KeyRef,
        hash: Sha256,
    ) -> Result<Signature<EcdsaP256>, SignError<TxError<Self>>>
    where
        Self: Sized,
    {
        let mut reads = CoreReads(self);
        if let Some(key) = core_auth_key(&mut reads, key_ref, SignScheme::Citizen) {
            let sig = key
                .sign_prehashed_sha256_ecdsa_p256(*hash.as_bytes())
                .map_err(map_core_sign_error)?;
            return Ok(Signature::new(sig.into_bytes()));
        }
        let bytes = drive_prehashed_chain(
            self,
            SignatureAlgRef::SHA256_ECDSA,
            key_ref,
            ExternalHashValue::Sha256(*hash.as_bytes()),
            key_ref.signs_digest_inline(),
            ECDSA_P256_SIG_BYTES,
        )?;
        Ok(Signature::new(bytes))
    }

    /// Auth-slot convenience wrapper for [`SignOps::sign_pre_hashed_sha256_rsa`].
    ///
    /// # Errors
    /// See [`SignOps::sign_pre_hashed_sha256_rsa`].
    fn sign_pre_hashed_sha256_rsa_auth(
        &mut self,
        hash: Sha256,
    ) -> Result<Signature<RsaPkcs1Sha256>, SignError<TxError<Self>>>
    where
        Self: Sized,
    {
        self.sign_pre_hashed_sha256_rsa(KeyRef::Auth, hash)
    }

    /// Qualified-signature-slot convenience wrapper for
    /// [`SignOps::sign_pre_hashed_sha256_rsa`].
    ///
    /// # Errors
    /// See [`SignOps::sign_pre_hashed_sha256_rsa`].
    fn sign_pre_hashed_sha256_rsa_qualified(
        &mut self,
        scheme: QualifiedSignScheme,
        hash: Sha256,
    ) -> Result<Signature<RsaPkcs1Sha256>, SignError<TxError<Self>>>
    where
        Self: Sized,
    {
        self.sign_pre_hashed_sha256_rsa(KeyRef::Sign(scheme), hash)
    }

    /// RSA-PKCS1v1.5 decrypt against the auth key ([`KEY_REF_AUTH`]), delegated
    /// to [`refineid_sign::SignOps::decipher_rsa`].
    ///
    /// # Errors
    /// Transport failure, non-9000 SW, or a ciphertext length other than
    /// [`RSA_3072_SIG_BYTES`].
    fn decrypt_rsa_pkcs1_auth(
        &mut self,
        ciphertext: Ciphertext<RsaPkcs1>,
    ) -> Result<RecoveredPlaintext, SignError<TxError<Self>>>
    where
        Self: Sized,
    {
        let cryptogram = refineid_sign::RsaCryptogram::from_bytes(ciphertext.into_bytes())
            .map_err(|err| SignError::UnexpectedSignatureLength(err.got))?;
        CoreReads(self)
            .decipher_rsa(
                SignScheme::Citizen,
                refineid_sign::KeyRef::Auth,
                DecipherAlgRef::RSA_PKCS1,
                &cryptogram,
            )
            .map_err(map_core_sign_error)
    }
}

impl<T: CardTransport + ?Sized> SignOps for T {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::atr::{Atr, AtrError, MINIMAL_DIRECT_ATR};
    use crate::auth::{PIN_PAD_BYTE, PIN2_STORED_LENGTH, PinOps as _, PinSlot, VERIFY_INS};
    use crate::pkcs15::esign_wire;
    use crate::transport::{CommandApdu, ResponseApdu, TransportOutcome};
    use refineid_sign::commands::PsoDecipher;

    const SW1_SUCCESS: u8 = 0x90;
    const SW2_SUCCESS: u8 = 0x00;
    const SW1_SECURITY: u8 = 0x69;
    const SW2_SECURITY_NOT_SATISFIED: u8 = 0x82;
    const SW_SECURITY_NOT_SATISFIED: u16 = 0x6982;
    const VERIFY_P1_MODE: u8 = 0x00;
    const FILL_BYTE: u8 = 0xAA;
    const SIG_FILL_BYTE: u8 = 0x55;
    const TEST_PIN2_LEN: usize = 6;
    const TEST_PIN2: &[u8; TEST_PIN2_LEN] = b"123456";
    const SHORT_SIG_LEN: usize = 16;

    struct Scripted {
        steps: std::collections::VecDeque<(Vec<u8>, ResponseApdu)>,
    }

    impl Scripted {
        fn new(steps: Vec<(Vec<u8>, ResponseApdu)>) -> Self {
            Self {
                steps: steps.into(),
            }
        }
    }

    impl CardTransport for Scripted {
        type Error = String;

        fn transmit_outcome(
            &mut self,
            apdu: &CommandApdu,
        ) -> Result<TransportOutcome, Self::Error> {
            let Some((expected, response)) = self.steps.pop_front() else {
                return Err("script exhausted".to_owned());
            };
            assert_eq!(apdu.as_bytes(), expected.as_slice(), "APDU mismatch");
            Ok(TransportOutcome::Response(response))
        }

        fn atr(&self) -> Result<Atr, AtrError> {
            Atr::new(MINIMAL_DIRECT_ATR)
        }
    }

    fn ok(body: &[u8]) -> ResponseApdu {
        ResponseApdu {
            body: body.to_vec(),
            sw1: SW1_SUCCESS,
            sw2: SW2_SUCCESS,
        }
    }

    fn sw(sw1: u8, sw2: u8) -> ResponseApdu {
        ResponseApdu {
            body: vec![],
            sw1,
            sw2,
        }
    }

    fn expected_mse_dst(alg_ref: SignatureAlgRef, key_ref: KeyRef) -> Vec<u8> {
        MseSet {
            alg_ref,
            key_ref: key_ref.as_u8(),
        }
        .into_apdu()
        .expect("mse builds")
        .as_bytes()
        .to_vec()
    }

    fn expected_pso_hash(hash: ExternalHashValue) -> Vec<u8> {
        PsoHashExternal { hash }
            .into_apdu()
            .expect("pso hash builds")
            .as_bytes()
            .to_vec()
    }

    fn expected_pso_cds(expected_bytes: usize) -> Vec<u8> {
        PsoComputeDigitalSignature
            .into_apdu(expected_length_le(expected_bytes))
            .as_bytes()
            .to_vec()
    }

    fn expected_pso_cds_inline(hash: ExternalHashValue, expected_bytes: usize) -> Vec<u8> {
        PsoComputeDigitalSignature
            .into_apdu_with_digest(hash, expected_length_le(expected_bytes))
            .expect("inline cds builds")
            .as_bytes()
            .to_vec()
    }

    fn expected_verify_pin2_probe(scheme: PinReferenceScheme) -> Vec<u8> {
        vec![
            ApduClass::Plain.as_byte(),
            VERIFY_INS,
            VERIFY_P1_MODE,
            scheme.reference(PinSlot::Pin2),
        ]
    }

    fn expected_verify_pin2(scheme: PinReferenceScheme) -> Vec<u8> {
        let mut block = TEST_PIN2.to_vec();
        if scheme == PinReferenceScheme::Citizen {
            block.resize(PIN2_STORED_LENGTH, PIN_PAD_BYTE);
        }
        let lc = u8::try_from(block.len()).expect("short-form Lc");
        let mut apdu = vec![
            ApduClass::Plain.as_byte(),
            VERIFY_INS,
            VERIFY_P1_MODE,
            scheme.reference(PinSlot::Pin2),
            lc,
        ];
        apdu.extend_from_slice(&block);
        apdu
    }

    #[test]
    fn estonian_scheme_cannot_become_a_qualified_signing_key() {
        assert_eq!(
            QualifiedSignScheme::try_from(PinReferenceScheme::Estonian),
            Err(UnsupportedQualifiedScheme(PinReferenceScheme::Estonian))
        );
    }

    #[test]
    fn citizen_auth_rsa_and_ecdsa_delegate_to_refineid_sign() {
        let sha256 = Sha256::from_bytes([FILL_BYTE; SHA256_DIGEST_LEN]);
        let rsa_sig = vec![SIG_FILL_BYTE; RSA_3072_SIG_BYTES];
        let mut rsa_tx = Scripted::new(vec![
            (
                expected_mse_dst(SignatureAlgRef::SHA256_RSA_PKCS1, KeyRef::Auth),
                ok(&[]),
            ),
            (
                expected_pso_hash(ExternalHashValue::Sha256(*sha256.as_bytes())),
                ok(&[]),
            ),
            (expected_pso_cds(RSA_3072_SIG_BYTES), ok(&rsa_sig)),
        ]);
        let out = rsa_tx
            .sign_pre_hashed_sha256_rsa_auth(sha256)
            .expect("auth rsa signs");
        assert_eq!(out.as_bytes(), rsa_sig.as_slice());
        assert!(rsa_tx.steps.is_empty());

        let sha384 = Sha384::from_bytes([FILL_BYTE; SHA384_DIGEST_LEN]);
        let ecdsa_sig = vec![SIG_FILL_BYTE; ECDSA_P384_SIG_BYTES];
        let mut ecdsa_tx = Scripted::new(vec![
            (
                expected_mse_dst(SignatureAlgRef::SHA384_ECDSA, KeyRef::Auth),
                ok(&[]),
            ),
            (
                expected_pso_hash(ExternalHashValue::Sha384(*sha384.as_bytes())),
                ok(&[]),
            ),
            (expected_pso_cds(ECDSA_P384_SIG_BYTES), ok(&ecdsa_sig)),
        ]);
        let out_ec = ecdsa_tx
            .sign_pre_hashed_sha384_ecdsa_p384(KeyRef::Auth, sha384)
            .expect("auth ecdsa p384 signs");
        assert_eq!(out_ec.as_bytes(), ecdsa_sig.as_slice());
        assert!(ecdsa_tx.steps.is_empty());
    }

    #[test]
    fn organizational_qualified_signature_runs_inside_esign_inline() {
        let scheme = PinReferenceScheme::Organizational;
        let qualified = QualifiedSignScheme::Organizational;
        let hash = Sha256::from_bytes([FILL_BYTE; SHA256_DIGEST_LEN]);
        let sig = vec![SIG_FILL_BYTE; RSA_3072_SIG_BYTES];
        let mut tx = Scripted::new(vec![
            (esign_wire::select_mf().into_bytes(), ok(&[])),
            (esign_wire::select_esign_by_name().into_bytes(), ok(&[])),
            (expected_verify_pin2_probe(scheme), ok(&[])),
            (expected_verify_pin2(scheme), ok(&[])),
            (
                expected_mse_dst(SignatureAlgRef::SHA256_RSA_PKCS1, KeyRef::Sign(qualified)),
                ok(&[]),
            ),
            (
                expected_pso_cds_inline(
                    ExternalHashValue::Sha256(*hash.as_bytes()),
                    RSA_3072_SIG_BYTES,
                ),
                ok(&sig),
            ),
        ]);
        let pin = crate::pin::PinBytes::try_from(*TEST_PIN2).expect("valid pin");
        assert_eq!(
            tx.verify_pin_with_scheme(PinSlot::Pin2, scheme, pin)
                .expect("verify pin2"),
            crate::auth::VerifyOutcome::Ok
        );
        let out = tx
            .sign_pre_hashed_sha256_rsa_qualified(qualified, hash)
            .expect("qualified org signs");
        assert_eq!(out.as_bytes(), sig.as_slice());
        assert!(tx.steps.is_empty());
    }

    #[test]
    fn sha512_ecdsa_p384_drives_mse_pso_hash_and_cds() {
        let hash = Sha512::from_bytes([FILL_BYTE; SHA512_DIGEST_LEN]);
        let sig = vec![SIG_FILL_BYTE; ECDSA_P384_SIG_BYTES];
        let mse = refineid_apdu::CommandApdu::case_3(
            CommandHeader {
                class: ApduClass::Plain,
                instruction: MSE_INS,
                p1: MSE_P1_SET,
                p2: MSE_P2_DST,
            },
            &[
                CRDO_ALG_REF,
                CRDO_VALUE_LEN,
                ALG_SHA512_ECDSA,
                CRDO_KEY_REF,
                CRDO_VALUE_LEN,
                KEY_REF_AUTH,
            ],
        )
        .expect("mse builds")
        .as_bytes()
        .to_vec();
        let mut tx = Scripted::new(vec![
            (mse, ok(&[])),
            (
                expected_pso_hash(ExternalHashValue::Sha512(*hash.as_bytes())),
                ok(&[]),
            ),
            (expected_pso_cds(ECDSA_P384_SIG_BYTES), ok(&sig)),
        ]);
        let out = tx
            .sign_pre_hashed_sha512_ecdsa_p384(KeyRef::Auth, hash)
            .expect("sha512 ecdsa signs");
        assert_eq!(out.as_bytes(), sig.as_slice());
        assert!(tx.steps.is_empty());
    }

    #[test]
    fn decrypt_rsa_pkcs1_auth_delegates_to_refineid_sign() {
        let ct_bytes = vec![FILL_BYTE; RSA_3072_MODULUS_BYTES];
        let cryptogram = refineid_sign::RsaCryptogram::from_bytes(ct_bytes.clone())
            .expect("modulus-wide cryptogram");
        let mse_ct = commands::MseSetCt {
            alg_ref: DecipherAlgRef::RSA_PKCS1,
            key_ref: KEY_REF_AUTH,
        }
        .into_apdu()
        .expect("mse ct builds")
        .as_bytes()
        .to_vec();
        let chain = PsoDecipher {
            cryptogram: &cryptogram,
        }
        .into_chain()
        .expect("decipher chains");
        let mut steps = vec![(mse_ct, ok(&[]))];
        let (last, leading) = chain.split_last().expect("non-empty chain");
        for chunk in leading {
            steps.push((chunk.as_bytes().to_vec(), ok(&[])));
        }
        steps.push((last.as_bytes().to_vec(), ok(b"recovered-secret")));
        let mut tx = Scripted::new(steps);
        let recovered = tx
            .decrypt_rsa_pkcs1_auth(Ciphertext::new(ct_bytes))
            .expect("decipher succeeds");
        assert_eq!(recovered.as_bytes(), b"recovered-secret");
        assert!(tx.steps.is_empty());
    }

    #[test]
    fn non_success_status_and_wrong_length_surface_as_sign_errors() {
        let hash = Sha256::from_bytes([FILL_BYTE; SHA256_DIGEST_LEN]);
        let mut sw_tx = Scripted::new(vec![(
            expected_mse_dst(SignatureAlgRef::SHA256_RSA_PKCS1, KeyRef::Auth),
            sw(SW1_SECURITY, SW2_SECURITY_NOT_SATISFIED),
        )]);
        assert!(matches!(
            sw_tx.sign_pre_hashed_sha256_rsa_auth(hash),
            Err(SignError::Sw(_, SW_SECURITY_NOT_SATISFIED))
        ));

        let mut short_tx = Scripted::new(vec![
            (
                expected_mse_dst(SignatureAlgRef::SHA256_RSA_PKCS1, KeyRef::Auth),
                ok(&[]),
            ),
            (
                expected_pso_hash(ExternalHashValue::Sha256(*hash.as_bytes())),
                ok(&[]),
            ),
            (
                expected_pso_cds(RSA_3072_SIG_BYTES),
                ok(&[SIG_FILL_BYTE; SHORT_SIG_LEN]),
            ),
        ]);
        assert!(matches!(
            short_tx.sign_pre_hashed_sha256_rsa_auth(hash),
            Err(SignError::UnexpectedSignatureLength(SHORT_SIG_LEN))
        ));
    }
}
