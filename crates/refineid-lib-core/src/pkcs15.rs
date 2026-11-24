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

//! PKCS#15 file-system access on the FINEID card.
//!
//! Re-exports the shared PKCS#15 identifiers, slot taxonomy, directory
//! discovery types, and file-system operations from [`refineid_pkcs15`],
//! bridged over this crate's [`CardTransport`], alongside FINEID-aware
//! reader selection ([`FineidReaderPicker`]) and FCI file-size parsing
//! ([`Fci`]).

#![expect(
    clippy::pub_use,
    reason = "library-facade pattern: re-exports shared PKCS#15 types from refineid-pkcs15 alongside local CardTransport bridge and reader pickers"
)]

use crate::apdu::iso7816::FileId;
use crate::apdu::primitives::{Aid, AidError};
use crate::apdu::status_word::StatusWord;
use crate::transport::{CardTransport, TransportDispatchError};

pub use refineid_pkcs15::fs::MAX_OBJECT_BYTES;
pub use refineid_pkcs15::{
    CertSlot, DF_ESIGN_FID, DiscoveredAuthenticationProfile, EF_AUTH_CERT_ALT_FID,
    EF_AUTH_CERT_FID, EF_ISSUING_CA_ECC_FID, EF_ROOT_CA_FID, EF_SIGN_CERT_ALT_FID,
    EF_SIGN_CERT_FID, EF_TOKEN_INFO_FID, ESIGN_AID, KeyReference, PKCS15_AID, Pkcs15Path,
};

/// Number of FINEID certificate slots probed by [`ALL_CERT_SLOTS`].
pub const ALL_CERT_SLOT_COUNT: usize = 6;

/// All six FINEID certificate slots in directory order, including the
/// on-card issuing intermediate CA (`EF.4336`) read by `card check` and
/// `card export`.
pub const ALL_CERT_SLOTS: [CertSlot; ALL_CERT_SLOT_COUNT] = [
    CertSlot::Authentication,
    CertSlot::Signature,
    CertSlot::AuthenticationAlt,
    CertSlot::RootCa,
    CertSlot::SignatureAlt,
    CertSlot::IssuingCaEcc,
];

/// Convenience alias for [`TransportDispatchError`] specialised to
/// a [`CardTransport`] implementation's own error type.
pub type TxError<T> = TransportDispatchError<<T as CardTransport>::Error>;

/// Error returned from PKCS#15 cert reads and EF.TokenInfo parses.
#[derive(Debug)]
pub enum Pkcs15Error<TE> {
    /// Transport-level failure (PC/SC error, USB I/O, etc.).
    Transport(TE),
    /// Card returned a non-success status word per ISO 7816-4.
    Sw(u16),
    /// `Aid::from_slice` rejected an AID constant outside the ISO 7816-5 length range.
    Aid(AidError),
    /// Cert was empty or the read loop returned no bytes.
    Empty,
    /// Cert exceeded [`MAX_OBJECT_BYTES`].
    TooLarge,
    /// A read-and-parse step received bytes the parser could not decode.
    InvalidData(&'static str),
}

impl<TE: core::fmt::Display> core::fmt::Display for Pkcs15Error<TE> {
    #[inline]
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "PKCS#15 transport: {e}"),
            Self::Sw(sw) => write!(f, "PKCS#15: card returned SW={sw:#06X}"),
            Self::Aid(e) => write!(f, "PKCS#15: AID constant rejected by Aid::from_slice: {e}"),
            Self::Empty => write!(f, "PKCS#15: read returned no bytes"),
            Self::TooLarge => write!(f, "PKCS#15: cert exceeds {MAX_OBJECT_BYTES} bytes"),
            Self::InvalidData(what) => write!(f, "PKCS#15: malformed {what}"),
        }
    }
}

impl<TE: core::fmt::Debug + core::fmt::Display + 'static> core::error::Error for Pkcs15Error<TE> {}

/// PKCS#15 file-system operations layered as default-impl methods on every
/// [`CardTransport`], delegating wire exchanges to [`refineid_pkcs15::Pkcs15Ops`].
pub trait Pkcs15Ops: CardTransport {
    /// SELECT the PKCS#15 application by AID, no FCI returned.
    ///
    /// # Errors
    /// Transport-level failures or a non-success status word from the card.
    #[inline]
    fn select_pkcs15_application(&mut self) -> Result<(), Pkcs15Error<TxError<Self>>>
    where
        Self: Sized,
    {
        refineid_pkcs15::Pkcs15Ops::select_pkcs15_application(&mut crate::auth::CoreReads(self))
            .map_err(map_core_pkcs15_error)
    }

    /// SELECT an EF by 2-byte file ID without response data.
    ///
    /// # Errors
    /// Transport-level failures or a non-success status word.
    #[inline]
    fn select_ef(&mut self, fid: [u8; FileId::LENGTH]) -> Result<(), Pkcs15Error<TxError<Self>>>
    where
        Self: Sized,
    {
        refineid_pkcs15::Pkcs15Ops::select_ef(&mut crate::auth::CoreReads(self), FileId::new(fid))
            .map_err(map_core_pkcs15_error)
    }

    /// SELECT MF (`3F00`).
    ///
    /// # Errors
    /// Transport failure or a non-success status word.
    #[inline]
    fn select_mf(&mut self) -> Result<(), Pkcs15Error<TxError<Self>>>
    where
        Self: Sized,
    {
        refineid_pkcs15::Pkcs15Ops::select_mf(&mut crate::auth::CoreReads(self))
            .map_err(map_core_pkcs15_error)
    }

    /// SELECT a child DF under the current context.
    ///
    /// # Errors
    /// Transport failure or a non-success status word.
    #[inline]
    fn select_child_df(
        &mut self,
        fid: [u8; FileId::LENGTH],
    ) -> Result<(), Pkcs15Error<TxError<Self>>>
    where
        Self: Sized,
    {
        refineid_pkcs15::Pkcs15Ops::select_child_df(
            &mut crate::auth::CoreReads(self),
            FileId::new(fid),
        )
        .map_err(map_core_pkcs15_error)
    }

    /// SELECT DF.ESIGN, the qualified-signature directory beneath the MF, and
    /// return [`StatusWord::Success`] once DF.ESIGN is current or the card's
    /// last refusal status word.
    ///
    /// # Errors
    /// Transport failures.
    #[inline]
    fn select_esign_directory(&mut self) -> Result<StatusWord, TxError<Self>>
    where
        Self: Sized,
    {
        /// Fallback status code for statically unreachable non-status errors
        /// (compile-time guards enforce valid `ESIGN_AID` / `DF_ESIGN_FID`).
        const SW_UNREACHABLE_NON_STATUS: u16 = 0;

        match refineid_pkcs15::Pkcs15Ops::select_esign_directory(&mut crate::auth::CoreReads(self))
        {
            Ok(()) => Ok(StatusWord::Success),
            Err(refineid_pkcs15::Pkcs15Error::Status(sw)) => Ok(sw),
            Err(refineid_pkcs15::Pkcs15Error::Transport(
                crate::auth::CoreReadError::Transport(inner),
            )) => Err(TransportDispatchError::Error(inner)),
            Err(refineid_pkcs15::Pkcs15Error::Outcome(outcome)) => {
                Err(TransportDispatchError::Outcome(outcome))
            }
            Err(
                refineid_pkcs15::Pkcs15Error::Transport(
                    crate::auth::CoreReadError::CredentialCommand,
                )
                | refineid_pkcs15::Pkcs15Error::Aid(_)
                | refineid_pkcs15::Pkcs15Error::Command(_)
                | refineid_pkcs15::Pkcs15Error::Empty
                | refineid_pkcs15::Pkcs15Error::TooLarge
                | refineid_pkcs15::Pkcs15Error::InvalidData(_),
            ) => Ok(StatusWord::Other(SW_UNREACHABLE_NON_STATUS)),
        }
    }

    /// `READ BINARY` against the currently selected EF until EOF / short read / cap.
    ///
    /// # Errors
    /// Transport failures, non-success SW other than EOF, empty result, or cap exceeded.
    #[inline]
    fn read_binary_to_end(
        &mut self,
        expected_size: Option<usize>,
    ) -> Result<Vec<u8>, Pkcs15Error<TxError<Self>>>
    where
        Self: Sized,
    {
        refineid_pkcs15::Pkcs15Ops::read_binary_to_end(
            &mut crate::auth::CoreReads(self),
            expected_size,
        )
        .map_err(map_core_pkcs15_error)
    }

    /// Read exactly one DER object from the currently selected EF.
    ///
    /// # Errors
    /// Transport failure, unexpected status, malformed/truncated DER, empty
    /// response, or declared object above [`MAX_OBJECT_BYTES`].
    #[inline]
    fn read_binary_der_object(
        &mut self,
        what: &'static str,
    ) -> Result<Vec<u8>, Pkcs15Error<TxError<Self>>>
    where
        Self: Sized,
    {
        refineid_pkcs15::Pkcs15Ops::read_binary_der_object(&mut crate::auth::CoreReads(self), what)
            .map_err(map_core_pkcs15_error)
    }

    /// Generic single-cert read routing to the SELECT chain for `slot`.
    ///
    /// # Errors
    /// Any underlying SELECT or READ BINARY failure.
    #[inline]
    fn read_certificate(
        &mut self,
        slot: CertSlot,
    ) -> Result<crate::cert_state::CertDer, Pkcs15Error<TxError<Self>>>
    where
        Self: Sized,
    {
        let cert =
            refineid_pkcs15::Pkcs15Ops::read_certificate(&mut crate::auth::CoreReads(self), slot)
                .map_err(map_core_pkcs15_error)?;
        Ok(crate::cert_state::CertDer::new(cert.as_bytes().to_vec()))
    }

    /// Discover the Estonian eID authentication profile via `refineid-core`'s
    /// ISO/IEC 7816-15 directory discovery (`EF.DIR` -> `EF.ODF` -> `EF.CDF` +
    /// `EF.PrKDF` -> `EF.AOD`).
    ///
    /// Leaves the discovered application AID selected on success.
    ///
    /// # Errors
    /// Transport failures, status errors, or malformed/ambiguous directory files.
    #[inline]
    fn discover_estonian_authentication_profile(
        &mut self,
    ) -> Result<DiscoveredAuthenticationProfile, Pkcs15Error<TxError<Self>>>
    where
        Self: Sized,
    {
        refineid_pkcs15::Pkcs15Ops::discover_estonian_authentication_profile(
            &mut crate::auth::CoreReads(self),
        )
        .map_err(map_core_pkcs15_error)
    }

    /// Select the PKCS#15 application identified by a discovered `refineid-apdu` AID.
    ///
    /// # Errors
    /// Transport or card status failure.
    #[inline]
    fn select_core_application(&mut self, aid: &Aid) -> Result<(), Pkcs15Error<TxError<Self>>>
    where
        Self: Sized,
    {
        refineid_pkcs15::Pkcs15Ops::select_application(&mut crate::auth::CoreReads(self), aid)
            .map_err(map_core_pkcs15_error)
    }

    /// Read and validate a complete DER certificate at an ISO/IEC 7816-15 `Pkcs15Path`.
    ///
    /// # Errors
    /// Selection, read, or DER validation failure.
    #[inline]
    fn read_certificate_at(
        &mut self,
        path: &Pkcs15Path,
    ) -> Result<crate::cert_state::CertDer, Pkcs15Error<TxError<Self>>>
    where
        Self: Sized,
    {
        let cert = refineid_pkcs15::Pkcs15Ops::read_certificate_at(
            &mut crate::auth::CoreReads(self),
            path,
        )
        .map_err(map_core_pkcs15_error)?;
        Ok(crate::cert_state::CertDer::new(cert.as_bytes().to_vec()))
    }

    /// Read the card's authentication certificate and, when resolved through
    /// ISO/IEC 7816-15 directory discovery (Estonian eID), return the
    /// discovered authentication profile as well.
    ///
    /// # Errors
    /// Propagates transport errors immediately; returns the last card/format
    /// error if no authentication certificate slot or discovered profile exists.
    #[inline]
    fn read_authentication_certificate_and_profile(
        &mut self,
    ) -> Result<
        (
            crate::cert_state::CertDer,
            Option<DiscoveredAuthenticationProfile>,
        ),
        Pkcs15Error<TxError<Self>>,
    >
    where
        Self: Sized,
    {
        match self.read_certificate(CertSlot::Authentication) {
            Ok(cert) => return Ok((cert, None)),
            Err(Pkcs15Error::Transport(err)) => return Err(Pkcs15Error::Transport(err)),
            Err(_) => {}
        }
        match self.discover_estonian_authentication_profile() {
            Ok(profile) => {
                let cert = self.read_certificate_at(profile.auth_cert_path())?;
                self.select_core_application(profile.application_aid())?;
                return Ok((cert, Some(profile)));
            }
            Err(Pkcs15Error::Transport(err)) => return Err(Pkcs15Error::Transport(err)),
            Err(_) => {}
        }
        self.read_certificate(CertSlot::AuthenticationAlt)
            .map(|cert| (cert, None))
    }

    /// Read the card's authentication certificate across FINEID and
    /// ISO/IEC 7816-15 directory-discovered cards.
    ///
    /// # Errors
    /// As [`Self::read_authentication_certificate_and_profile`].
    #[inline]
    fn read_authentication_certificate(
        &mut self,
    ) -> Result<crate::cert_state::CertDer, Pkcs15Error<TxError<Self>>>
    where
        Self: Sized,
    {
        self.read_authentication_certificate_and_profile()
            .map(|(cert, _profile)| cert)
    }

    /// Read and parse `EF.TokenInfo` (`5032`).
    ///
    /// # Errors
    /// SELECT / READ BINARY or BER decode failures.
    #[inline]
    fn read_token_info(&mut self) -> Result<TokenInfo, Pkcs15Error<TxError<Self>>>
    where
        Self: Sized,
    {
        refineid_pkcs15::Pkcs15Ops::read_token_info(&mut crate::auth::CoreReads(self))
            .map(TokenInfo::from_core)
            .map_err(map_core_pkcs15_error)
    }
}

impl<T: CardTransport + ?Sized> Pkcs15Ops for T {}

/// Lift a `refineid-core` [`refineid_pkcs15::Pkcs15Error`] through the
/// `CoreReads` bridge into this crate's [`Pkcs15Error`].
fn map_core_pkcs15_error<E>(
    error: refineid_pkcs15::Pkcs15Error<crate::auth::CoreReadError<E>>,
) -> Pkcs15Error<TransportDispatchError<E>> {
    match error {
        refineid_pkcs15::Pkcs15Error::Transport(crate::auth::CoreReadError::Transport(inner)) => {
            Pkcs15Error::Transport(TransportDispatchError::Error(inner))
        }
        refineid_pkcs15::Pkcs15Error::Outcome(outcome) => {
            Pkcs15Error::Transport(TransportDispatchError::Outcome(outcome))
        }
        refineid_pkcs15::Pkcs15Error::Transport(crate::auth::CoreReadError::CredentialCommand) => {
            Pkcs15Error::InvalidData("transport")
        }
        refineid_pkcs15::Pkcs15Error::Status(sw) => Pkcs15Error::Sw(sw.as_u16()),
        refineid_pkcs15::Pkcs15Error::Aid(err) => Pkcs15Error::Aid(err),
        refineid_pkcs15::Pkcs15Error::Command(_) => Pkcs15Error::InvalidData("command"),
        refineid_pkcs15::Pkcs15Error::Empty => Pkcs15Error::Empty,
        refineid_pkcs15::Pkcs15Error::TooLarge => Pkcs15Error::TooLarge,
        refineid_pkcs15::Pkcs15Error::InvalidData(what) => Pkcs15Error::InvalidData(what),
    }
}

/// File Control Information (FCI) bytes returned by a SELECT EF that requested FCI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fci {
    /// Raw FCI / FCP template bytes.
    bytes: Vec<u8>,
}

impl Fci {
    /// Wrap raw FCI bytes from a SELECT response.
    #[must_use]
    #[inline]
    pub const fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Borrow the underlying FCI / FCP bytes.
    #[must_use]
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Parse the file-size data object (`80` or `81`) from a `62` (FCP) or `6F` (FCI) template.
    #[must_use]
    #[inline]
    pub fn parse_file_size(&self) -> Option<usize> {
        use crate::ber::{BerTlvAny, BerTlvIter};

        const TAG_FCP: u16 = 0x62;
        const TAG_FCI: u16 = 0x6F;
        const TAG_FILE_LENGTH_NON_TLV: u16 = 0x80;
        const TAG_FILE_LENGTH_TLV: u16 = 0x81;
        const OCTET_RADIX: usize = 1 << u8::BITS;

        let outer = BerTlvAny::parse(&self.bytes).ok()?;
        if outer.tag() != TAG_FCP && outer.tag() != TAG_FCI {
            return None;
        }
        for child in BerTlvIter::new(outer.value()) {
            let c = child.ok()?;
            if c.tag() == TAG_FILE_LENGTH_NON_TLV || c.tag() == TAG_FILE_LENGTH_TLV {
                let mut v: usize = 0;
                for &b in c.value() {
                    v = v.checked_mul(OCTET_RADIX)?.checked_add(usize::from(b))?;
                }
                return Some(v);
            }
        }
        None
    }
}

/// Subset of PKCS#15 `TokenInfo` surfaced by CLI and GUI card status views.
#[derive(Debug, Clone, Default)]
pub struct TokenInfo {
    /// `EF.TokenInfo.version` per PKCS#15.
    pub version: Option<u32>,
    /// `EF.TokenInfo.serialNumber` as a typed [`crate::identity::TokenSerial`].
    pub serial_number_hex: Option<crate::identity::TokenSerial>,
    /// `EF.TokenInfo.manufacturerID`.
    pub manufacturer_id: Option<String>,
    /// `EF.TokenInfo.label`.
    pub label: Option<String>,
}

impl TokenInfo {
    /// Project a validated [`refineid_pkcs15::TokenInfo`] into this report view.
    #[must_use]
    fn from_core(core_info: refineid_pkcs15::TokenInfo) -> Self {
        Self {
            version: Some(core_info.version()),
            serial_number_hex: core_info.serial_number_hex().cloned(),
            manufacturer_id: core_info.manufacturer_id().map(ToOwned::to_owned),
            label: core_info.label().map(ToOwned::to_owned),
        }
    }

    /// Parse raw `EF.TokenInfo` DER via [`refineid_pkcs15::TokenInfo::parse`].
    ///
    /// # Errors
    /// Returns [`crate::ber::BerError`] if the DER structure does not decode.
    #[cfg(test)]
    pub(crate) fn parse(der: &[u8]) -> Result<Self, crate::ber::BerError> {
        refineid_pkcs15::TokenInfo::parse(der).map(Self::from_core)
    }
}

/// Output of `pick_fineid_reader` -- a reader plus the identity of the card
/// currently inserted in it.
#[derive(Debug, Clone)]
pub struct FineidReaderPick {
    /// PC/SC reader id of the matched reader.
    pub reader_id: crate::backend::ReaderId,
    /// Credential identity captured at pick time.
    pub identity: crate::identity::CredentialIdentity,
}

/// FINEID-aware extension on [`crate::backend::ReaderBackend`].
pub trait FineidReaderPicker: crate::backend::ReaderBackend
where
    Self::Error: core::fmt::Display,
{
    /// Pick a single FINEID card reader matching `filter`.
    ///
    /// # Errors
    /// Any [`crate::backend::ReaderPickError`] variant.
    #[inline]
    fn pick_fineid_reader(
        &self,
        filter: Option<&crate::backend::ReaderFilter>,
    ) -> Result<FineidReaderPick, crate::backend::ReaderPickError>
    where
        Self: Sized,
    {
        pick_fineid_reader(self, filter)
    }

    /// Enumerate every reader holding a FINEID card matching `filter`.
    ///
    /// # Errors
    /// [`crate::backend::ReaderPickError::NoReaders`] when enumeration fails.
    #[inline]
    fn enumerate_fineid_readers(
        &self,
        filter: Option<&crate::backend::ReaderFilter>,
    ) -> Result<Vec<FineidReaderPick>, crate::backend::ReaderPickError>
    where
        Self: Sized,
    {
        enumerate_fineid_readers(self, filter)
    }

    /// Pick a single contactless PACE-capable reader matching `filter`.
    ///
    /// # Errors
    /// Any [`crate::backend::ReaderPickError`] variant.
    #[inline]
    fn pick_contactless_reader(
        &self,
        filter: Option<&crate::backend::ReaderFilter>,
    ) -> Result<crate::backend::ReaderId, crate::backend::ReaderPickError>
    where
        Self: Sized,
    {
        pick_contactless_reader(self, filter)
    }

    /// Enumerate every contactless PACE-capable reader matching `filter`.
    ///
    /// # Errors
    /// [`crate::backend::ReaderPickError::NoReaders`] when enumeration fails.
    #[inline]
    fn enumerate_contactless_readers(
        &self,
        filter: Option<&crate::backend::ReaderFilter>,
    ) -> Result<Vec<crate::backend::ReaderId>, crate::backend::ReaderPickError>
    where
        Self: Sized,
    {
        enumerate_contactless_readers(self, filter)
    }
}

impl<B: crate::backend::ReaderBackend + ?Sized> FineidReaderPicker for B where
    B::Error: core::fmt::Display
{
}

/// FINEID-aware single-reader picker, deterministic for the CLI.
pub(crate) fn pick_fineid_reader<B: crate::backend::ReaderBackend>(
    backend: &B,
    filter: Option<&crate::backend::ReaderFilter>,
) -> Result<FineidReaderPick, crate::backend::ReaderPickError>
where
    B::Error: core::fmt::Display,
{
    use crate::backend::{ReaderInfo, ReaderPickError};

    let readers = backend
        .enumerate()
        .map_err(|_backend_err| ReaderPickError::NoReaders)?;
    if readers.is_empty() {
        return Err(ReaderPickError::NoReaders);
    }
    let present: Vec<ReaderInfo> = readers.into_iter().filter(|r| r.card_present).collect();
    if present.is_empty() {
        return Err(ReaderPickError::NoCardPresent);
    }

    let mut all_names: Vec<String> = Vec::with_capacity(present.len());
    let mut probed: Vec<(ReaderInfo, crate::identity::CredentialIdentity)> =
        Vec::with_capacity(present.len());
    for info in &present {
        all_names.push(info.id.as_str().to_owned());
        if let Some(identity) = probe_fineid_identity(backend, &info.id) {
            probed.push((info.clone(), identity));
        }
    }

    if probed.is_empty() {
        return Err(ReaderPickError::NoFineidCard {
            available: all_names,
        });
    }

    let matched: Vec<&(ReaderInfo, crate::identity::CredentialIdentity)> = filter.map_or_else(
        || probed.iter().collect(),
        |f| {
            let needle = f.as_str();
            probed
                .iter()
                .filter(|(r, _)| r.id.as_str().contains(needle))
                .collect()
        },
    );

    let winner = match (filter, matched.as_slice()) {
        (_, [single]) => *single,
        (Some(f), []) => {
            return Err(ReaderPickError::NoMatchingReader {
                filter: f.as_str().to_owned(),
                available: probed
                    .iter()
                    .map(|(r, _)| r.id.as_str().to_owned())
                    .collect(),
            });
        }
        (Some(f), many) => {
            return Err(ReaderPickError::AmbiguousFilter {
                filter: f.as_str().to_owned(),
                matched: many.iter().map(|(r, _)| r.id.as_str().to_owned()).collect(),
            });
        }
        (None, many) => {
            return Err(ReaderPickError::MultipleReadersNoFilter {
                available: many.iter().map(|(r, _)| r.id.as_str().to_owned()).collect(),
            });
        }
    };

    Ok(FineidReaderPick {
        reader_id: winner.0.id.clone(),
        identity: winner.1.clone(),
    })
}

/// Probe a single reader by opening + SELECT PKCS#15 + `EF.TokenInfo` + auth-cert read.
fn probe_fineid_identity<B: crate::backend::ReaderBackend>(
    backend: &B,
    reader_id: &crate::backend::ReaderId,
) -> Option<crate::identity::CredentialIdentity>
where
    B::Error: core::fmt::Display,
{
    use crate::backend::ReaderAccessCap;
    use crate::identity::{CredentialIdentity, derive_printed_serial, render_token_serial};

    let mut transport = backend
        .open_session(reader_id, ReaderAccessCap::Read)
        .ok()?;
    let token = transport.read_token_info().ok()?;
    let token_full = token.serial_number_hex.map(render_token_serial)?;
    let printed_serial = derive_printed_serial(&token_full);

    let (common_name, surname, given_names, peuin, organization) = transport
        .read_authentication_certificate()
        .ok()
        .and_then(|der| {
            crate::x509::Certificate::from_der(der.as_bytes())
                .ok()
                .map(|cert| {
                    let subject = cert.subject;
                    (
                        subject.common_name(),
                        subject.surname(),
                        subject.given_names(),
                        subject.peuin(),
                        subject.organization_name(),
                    )
                })
        })
        .unwrap_or_default();

    let mut id = CredentialIdentity::new();
    if let Some(cn) = common_name {
        id = id.with_common_name(cn);
    }
    if let Some(s) = surname {
        id = id.with_surname(s);
    }
    if let Some(n) = given_names.first {
        id = id.with_first_name(n);
    }
    if let Some(n) = given_names.second {
        id = id.with_second_name(n);
    }
    id = id.with_additional_names(given_names.additional);
    if let Some(p) = peuin {
        id = id.with_peuin(p);
    }
    if let Some(o) = organization {
        id = id.with_organization(o);
    }
    if let Some(s) = printed_serial {
        id = id.with_printed_serial(s);
    }
    Some(id)
}

/// Probe a single reader for a card that serves `EF.CardAccess` on the plain channel.
fn probe_card_access<B: crate::backend::ReaderBackend>(
    backend: &B,
    reader_id: &crate::backend::ReaderId,
) -> bool
where
    B::Error: core::fmt::Display,
{
    use crate::backend::ReaderAccessCap;
    use crate::card_access::CardAccessOps as _;

    backend
        .open_session(reader_id, ReaderAccessCap::Read)
        .ok()
        .is_some_and(|mut transport| transport.read_card_access().is_ok())
}

/// Every connected reader whose card serves `EF.CardAccess` on the plain channel.
pub(crate) fn enumerate_contactless_readers<B: crate::backend::ReaderBackend>(
    backend: &B,
    filter: Option<&crate::backend::ReaderFilter>,
) -> Result<Vec<crate::backend::ReaderId>, crate::backend::ReaderPickError>
where
    B::Error: core::fmt::Display,
{
    use crate::backend::ReaderPickError;

    let readers = backend
        .enumerate()
        .map_err(|_backend_err| ReaderPickError::NoReaders)?;
    if readers.is_empty() {
        return Err(ReaderPickError::NoReaders);
    }
    Ok(readers
        .into_iter()
        .filter(|r| r.card_present)
        .filter(|r| filter.is_none_or(|f| r.id.as_str().contains(f.as_str())))
        .filter(|r| probe_card_access(backend, &r.id))
        .map(|r| r.id)
        .collect())
}

/// Contactless (PACE-first) single-reader pick for the eMRTD flow.
pub(crate) fn pick_contactless_reader<B: crate::backend::ReaderBackend>(
    backend: &B,
    filter: Option<&crate::backend::ReaderFilter>,
) -> Result<crate::backend::ReaderId, crate::backend::ReaderPickError>
where
    B::Error: core::fmt::Display,
{
    use crate::backend::{ReaderInfo, ReaderPickError};

    let readers = backend
        .enumerate()
        .map_err(|_backend_err| ReaderPickError::NoReaders)?;
    if readers.is_empty() {
        return Err(ReaderPickError::NoReaders);
    }
    let present: Vec<ReaderInfo> = readers.into_iter().filter(|r| r.card_present).collect();
    if present.is_empty() {
        return Err(ReaderPickError::NoCardPresent);
    }

    let mut all_names: Vec<String> = Vec::with_capacity(present.len());
    let mut candidates: Vec<&ReaderInfo> = Vec::with_capacity(present.len());
    for info in &present {
        all_names.push(info.id.as_str().to_owned());
        if probe_card_access(backend, &info.id) {
            candidates.push(info);
        }
    }
    if candidates.is_empty() {
        return Err(ReaderPickError::NoFineidCard {
            available: all_names,
        });
    }

    let matched: Vec<&ReaderInfo> = filter.map_or_else(
        || candidates.clone(),
        |f| {
            let needle = f.as_str();
            candidates
                .iter()
                .copied()
                .filter(|r| r.id.as_str().contains(needle))
                .collect()
        },
    );

    match (filter, matched.as_slice()) {
        (_, [single]) => Ok(single.id.clone()),
        (Some(f), []) => Err(ReaderPickError::NoMatchingReader {
            filter: f.as_str().to_owned(),
            available: candidates
                .iter()
                .map(|r| r.id.as_str().to_owned())
                .collect(),
        }),
        (Some(f), many) => Err(ReaderPickError::AmbiguousFilter {
            filter: f.as_str().to_owned(),
            matched: many.iter().map(|r| r.id.as_str().to_owned()).collect(),
        }),
        (None, many) => Err(ReaderPickError::MultipleReadersNoFilter {
            available: many.iter().map(|r| r.id.as_str().to_owned()).collect(),
        }),
    }
}

/// Enumerate every connected reader whose currently-inserted card responds as FINEID-shape.
pub(crate) fn enumerate_fineid_readers<B: crate::backend::ReaderBackend>(
    backend: &B,
    filter: Option<&crate::backend::ReaderFilter>,
) -> Result<Vec<FineidReaderPick>, crate::backend::ReaderPickError>
where
    B::Error: core::fmt::Display,
{
    use crate::backend::ReaderPickError;

    let readers = backend
        .enumerate()
        .map_err(|_backend_err| ReaderPickError::NoReaders)?;
    let mut out: Vec<FineidReaderPick> = Vec::new();
    for info in readers {
        if !info.card_present {
            continue;
        }
        if let Some(f) = filter
            && !info.id.as_str().contains(f.as_str())
        {
            continue;
        }
        if let Some(identity) = probe_fineid_identity(backend, &info.id) {
            out.push(FineidReaderPick {
                reader_id: info.id,
                identity,
            });
        }
    }
    Ok(out)
}

/// Number of SELECT child-DF variants returned by [`child_df_select_attempts`].
#[cfg(test)]
pub(crate) const CHILD_DF_SELECT_VARIANT_COUNT: usize = 2;

/// Expected SELECT child-DF wire variants for `auth` unit tests.
#[cfg(test)]
pub(crate) fn child_df_select_attempts(
    fid: FileId,
) -> [crate::transport::CommandApdu; CHILD_DF_SELECT_VARIANT_COUNT] {
    use crate::apdu::iso7816::{
        ApduClass, SelectEfNoFci, SelectFile, SelectFileResponseMode, SelectFileTarget,
    };

    const SELECT_P1_CHILD_DF: u8 = 0x01;
    const SELECT_FID_LC: u8 = 2;

    let [high, low] = *fid.as_bytes();
    let child_df = crate::transport::CommandApdu::new(vec![
        SelectEfNoFci::CLA,
        SelectEfNoFci::INS,
        SELECT_P1_CHILD_DF,
        SelectEfNoFci::P2,
        SELECT_FID_LC,
        high,
        low,
    ]);
    let any_by_fid = SelectFile {
        class: ApduClass::Plain,
        target: SelectFileTarget::AnyByFileId(Some(fid)),
        response_mode: SelectFileResponseMode::None,
    }
    .into_apdu()
    .into();
    [child_df, any_by_fid]
}

/// Expected SELECT wire for the DF.ESIGN walk, assembled from the typed
/// command builders, for scripted tests of flows that enter the directory.
#[cfg(test)]
pub(crate) mod esign_wire {
    use super::{DF_ESIGN_FID, ESIGN_AID};
    use crate::apdu::iso7816::{
        ApduClass, FileId, SelectByAidNoFci, SelectFile, SelectFileResponseMode, SelectFileTarget,
    };
    use crate::apdu::primitives::Aid;
    use crate::transport::CommandApdu;

    fn select_any_by_fid(fid: FileId) -> CommandApdu {
        SelectFile {
            class: ApduClass::Plain,
            target: SelectFileTarget::AnyByFileId(Some(fid)),
            response_mode: SelectFileResponseMode::None,
        }
        .into_apdu()
        .into()
    }

    /// SELECT MF, the walk's first command.
    pub fn select_mf() -> CommandApdu {
        select_any_by_fid(FileId::MF)
    }

    /// SELECT DF.ESIGN by its published name.
    pub fn select_esign_by_name() -> CommandApdu {
        let aid = Aid::from_slice(ESIGN_AID).expect("published E.SIGN AID length is valid");
        SelectByAidNoFci { aid }.into_apdu().into()
    }

    /// SELECT DF.ESIGN as any file by its identifier, the walk's last variant.
    pub fn select_esign_any_by_fid() -> CommandApdu {
        select_any_by_fid(DF_ESIGN_FID)
    }
}

#[cfg(test)]
mod tests {
    use super::{EF_AUTH_CERT_FID, Fci, PKCS15_AID, Pkcs15Ops as _, TokenInfo};
    use crate::apdu::iso7816::{
        AbsolutePath, ApduClass, DirectOffset15, FileId, ReadBinary, ReadBinaryOffset,
        SelectByAidNoFci, SelectEfNoFci, SelectFile, SelectFileResponseMode, SelectFileTarget,
    };
    use crate::apdu::primitives::Aid;
    use crate::apdu::status_word::StatusWord;
    use crate::atr::{Atr, AtrError, MINIMAL_DIRECT_ATR};
    use crate::backend::{ReaderAccessCap, ReaderBackend, ReaderId, ReaderInfo, ReaderPickError};
    use crate::transport::{CardTransport, CommandApdu, ResponseApdu, TransportOutcome};

    /// Chunk size requested by `refineid-pkcs15` `READ BINARY` operations.
    const CORE_READ_CHUNK: u8 = 223;
    const READ_OFFSET_START: u16 = 0;

    /// Scripted in-memory transport replaying a canned `(request, response)` trace.
    struct ScriptedTransport {
        script: Vec<(Vec<u8>, ResponseApdu)>,
        cursor: usize,
    }

    impl ScriptedTransport {
        fn new(script: Vec<(Vec<u8>, ResponseApdu)>) -> Self {
            Self { script, cursor: 0 }
        }
    }

    impl CardTransport for ScriptedTransport {
        type Error = String;
        fn transmit_outcome(
            &mut self,
            apdu: &CommandApdu,
        ) -> Result<TransportOutcome, Self::Error> {
            let (expected, response) = self
                .script
                .get(self.cursor)
                .ok_or_else(|| format!("script exhausted at step {}", self.cursor))?;
            if expected != apdu.as_bytes() {
                return Err(format!(
                    "step {}: expected {} got {}",
                    self.cursor,
                    hex::encode(expected),
                    hex::encode(apdu.as_bytes())
                ));
            }
            self.cursor += 1;
            Ok(TransportOutcome::Response(response.clone()))
        }
        fn atr(&self) -> Result<Atr, AtrError> {
            Atr::new(MINIMAL_DIRECT_ATR)
        }
    }

    fn response_with_sw(body: &[u8], status: StatusWord) -> ResponseApdu {
        let [sw1, sw2] = status.as_u16().to_be_bytes();
        ResponseApdu {
            body: body.to_vec(),
            sw1,
            sw2,
        }
    }

    fn ok(body: &[u8]) -> ResponseApdu {
        response_with_sw(body, StatusWord::Success)
    }

    fn select_ef_wire(fid: FileId) -> Vec<u8> {
        SelectEfNoFci { fid }.into_apdu().as_bytes().to_vec()
    }

    fn select_any_wire(fid: FileId) -> Vec<u8> {
        SelectFile {
            class: ApduClass::Plain,
            target: SelectFileTarget::AnyByFileId(Some(fid)),
            response_mode: SelectFileResponseMode::None,
        }
        .into_apdu()
        .as_bytes()
        .to_vec()
    }

    fn select_by_name_wire(fid: FileId) -> Vec<u8> {
        const SELECT_P1_BY_NAME: u8 = 0x04;
        const SELECT_FID_LC: u8 = 2;
        let [hi, lo] = *fid.as_bytes();
        vec![
            SelectEfNoFci::CLA,
            SelectEfNoFci::INS,
            SELECT_P1_BY_NAME,
            SelectEfNoFci::P2,
            SELECT_FID_LC,
            hi,
            lo,
        ]
    }

    fn read_core_chunk_wire() -> Vec<u8> {
        let direct =
            DirectOffset15::try_new(READ_OFFSET_START).expect("start offset fits direct form");
        ReadBinary {
            class: ApduClass::Plain,
            offset: ReadBinaryOffset::Direct(direct),
            le: CORE_READ_CHUNK,
        }
        .into_apdu()
        .as_bytes()
        .to_vec()
    }

    #[test]
    fn parse_fci_file_size_finds_length_dos() {
        const EXPECTED_FCP_SIZE: usize = 0x0680;
        const EXPECTED_CAPTURED_SIZE: usize = 1784;

        let fci = Fci::new(hex::decode("62088002068082020011").expect("FCI fixture hex decodes"));
        assert_eq!(fci.parse_file_size(), Some(EXPECTED_FCP_SIZE));

        let fcp = Fci::new(
            hex::decode("6f18810206f8820101830243318a01058c0303ff009c0303ff00")
                .expect("captured FCP hex decodes"),
        );
        assert_eq!(fcp.parse_file_size(), Some(EXPECTED_CAPTURED_SIZE));

        assert_eq!(
            Fci::new(hex::decode("80020100").expect("bare DO hex decodes")).parse_file_size(),
            None
        );

        // Oversized length DO (nine maximal octets) overflows usize on both 32-bit and 64-bit targets.
        assert_eq!(
            Fci::new(
                hex::decode("620b8009ffffffffffffffffff").expect("oversized FCI fixture decodes")
            )
            .parse_file_size(),
            None
        );
    }

    #[test]
    fn token_info_parse_delegates_to_refineid_pkcs15() {
        const TAG_SEQUENCE: u8 = 0x30;
        const TAG_INTEGER: u8 = 0x02;
        const TAG_OCTET_STRING: u8 = 0x04;
        const TAG_UTF8_STRING: u8 = 0x0C;
        const VERSION_ZERO: u8 = 0;
        const SHORT_TLV_HEADER_LEN: usize = 2;

        fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
            let mut out = Vec::with_capacity(value.len().saturating_add(SHORT_TLV_HEADER_LEN));
            out.push(tag);
            out.push(u8::try_from(value.len()).expect("short DER length"));
            out.extend_from_slice(value);
            out
        }

        let mut body = tlv(TAG_INTEGER, &[VERSION_ZERO]);
        body.extend_from_slice(&tlv(TAG_OCTET_STRING, b"CARD-A"));
        body.extend_from_slice(&tlv(TAG_UTF8_STRING, b"DVV"));
        body.extend_from_slice(&tlv(TAG_UTF8_STRING, b"FINEID"));
        let der = tlv(TAG_SEQUENCE, &body);

        let info = TokenInfo::parse(&der).expect("valid EF.TokenInfo parses");
        assert_eq!(info.version, Some(0));
        assert_eq!(
            info.serial_number_hex.as_ref().map(|s| s.as_str()),
            Some("434152442d41")
        );
        assert_eq!(info.manufacturer_id.as_deref(), Some("DVV"));
        assert_eq!(info.label.as_deref(), Some("FINEID"));
    }

    #[test]
    fn read_authentication_certificate_discovers_estonian_profile_via_iso7816_15() {
        const TAG_ASN1_INTEGER: u8 = 0x02;
        const TAG_ASN1_BIT_STRING: u8 = 0x03;
        const TAG_ASN1_OCTET_STRING: u8 = 0x04;
        const TAG_ASN1_NULL: u8 = 0x05;
        const TAG_ASN1_ENUMERATED: u8 = 0x0A;
        const TAG_ASN1_SEQUENCE: u8 = 0x30;
        const TAG_APP_AID: u8 = 0x4F;
        const TAG_APP_LABEL: u8 = 0x50;
        const TAG_APP_TEMPLATE: u8 = 0x61;
        const TAG_CONTEXT_PRIMITIVE_0: u8 = 0x80;
        const TAG_CONTEXT_CONSTRUCTED_0: u8 = 0xA0;
        const TAG_CONTEXT_CONSTRUCTED_1: u8 = 0xA1;
        const TAG_ODF_CERTIFICATES: u8 = 0xA4;
        const TAG_ODF_AUTH_OBJECTS: u8 = 0xA8;

        const TEST_PRKDF_FID: FileId = FileId::from_u16(0x5035);
        const TEST_AOD_FID: FileId = FileId::from_u16(0x5036);
        const TEST_CDF_FID: FileId = FileId::from_u16(0x5037);
        const TEST_ADF1_FID: FileId = FileId::from_u16(0xADF1);
        const TEST_AUTH_CERT_FID: FileId = FileId::from_u16(0x3411);
        const TEST_OBJECT_ID: [u8; 1] = [0x01];
        const TEST_DISCOVERED_KEY_REF: u8 = 0x81;
        const TEST_PIN1_REF: u8 = 0x01;
        const DER_POSITIVE_INT_PAD: u8 = 0x00;
        const KEY_USAGE_SIGN_UNUSED_BITS: u8 = 5;
        const KEY_USAGE_SIGN_BYTE: u8 = 0x20;
        const PIN_FLAGS_NONE_UNUSED_BITS: u8 = 0;
        const PIN_FLAGS_NONE_BYTE: u8 = 0x00;
        const PIN_TYPE_ASCII_NUMERIC: u8 = 1;
        const PIN_MIN_LENGTH: u8 = 4;
        const PIN_STORED_LENGTH: u8 = 12;
        const PIN_MAX_LENGTH: u8 = 12;
        const SHORT_TLV_HEADER_LEN: usize = 2;

        fn ber_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
            let mut out = Vec::with_capacity(value.len().saturating_add(SHORT_TLV_HEADER_LEN));
            out.push(tag);
            out.push(u8::try_from(value.len()).expect("short DER length"));
            out.extend_from_slice(value);
            out
        }

        let cert = ber_tlv(TAG_ASN1_SEQUENCE, &ber_tlv(TAG_ASN1_NULL, &[]));
        let aid = Aid::from_slice(PKCS15_AID).expect("standard PKCS#15 AID");
        let select_aid = SelectByAidNoFci { aid }.into_apdu().as_bytes().to_vec();
        let select_mf = select_any_wire(FileId::MF);
        let select_auth_cert_path = SelectFile {
            class: ApduClass::Plain,
            target: SelectFileTarget::AbsolutePath(
                AbsolutePath::new(vec![TEST_ADF1_FID, TEST_AUTH_CERT_FID])
                    .expect("valid absolute path under MF"),
            ),
            response_mode: SelectFileResponseMode::None,
        }
        .into_apdu()
        .as_bytes()
        .to_vec();

        let mut dir_entry = ber_tlv(TAG_APP_AID, PKCS15_AID);
        dir_entry.extend_from_slice(&ber_tlv(
            TAG_APP_LABEL,
            refineid_pkcs15::ESTONIAN_EID_APPLICATION_LABEL.as_bytes(),
        ));
        let ef_dir = ber_tlv(TAG_APP_TEMPLATE, &dir_entry);

        let odf_entry = |tag: u8, fid: FileId| {
            ber_tlv(
                tag,
                &ber_tlv(
                    TAG_ASN1_SEQUENCE,
                    &ber_tlv(TAG_ASN1_OCTET_STRING, fid.as_bytes()),
                ),
            )
        };
        let mut ef_odf = odf_entry(TAG_CONTEXT_CONSTRUCTED_0, TEST_PRKDF_FID);
        ef_odf.extend_from_slice(&odf_entry(TAG_ODF_AUTH_OBJECTS, TEST_AOD_FID));
        ef_odf.extend_from_slice(&odf_entry(TAG_ODF_CERTIFICATES, TEST_CDF_FID));

        let mut full_cert_path_bytes = Vec::new();
        full_cert_path_bytes.extend_from_slice(FileId::MF.as_bytes());
        full_cert_path_bytes.extend_from_slice(TEST_ADF1_FID.as_bytes());
        full_cert_path_bytes.extend_from_slice(TEST_AUTH_CERT_FID.as_bytes());
        let mut cdf_body = ber_tlv(TAG_ASN1_SEQUENCE, &[]);
        cdf_body.extend_from_slice(&ber_tlv(
            TAG_ASN1_SEQUENCE,
            &ber_tlv(TAG_ASN1_OCTET_STRING, &TEST_OBJECT_ID),
        ));
        cdf_body.extend_from_slice(&ber_tlv(
            TAG_CONTEXT_CONSTRUCTED_1,
            &ber_tlv(
                TAG_ASN1_SEQUENCE,
                &ber_tlv(
                    TAG_ASN1_SEQUENCE,
                    &ber_tlv(TAG_ASN1_OCTET_STRING, &full_cert_path_bytes),
                ),
            ),
        ));
        let ef_cdf = ber_tlv(TAG_ASN1_SEQUENCE, &cdf_body);

        let mut key_attrs = ber_tlv(TAG_ASN1_OCTET_STRING, &TEST_OBJECT_ID);
        key_attrs.extend_from_slice(&ber_tlv(
            TAG_ASN1_BIT_STRING,
            &[KEY_USAGE_SIGN_UNUSED_BITS, KEY_USAGE_SIGN_BYTE],
        ));
        key_attrs.extend_from_slice(&ber_tlv(
            TAG_ASN1_INTEGER,
            &[DER_POSITIVE_INT_PAD, TEST_DISCOVERED_KEY_REF],
        ));
        let mut prkdf_body = ber_tlv(
            TAG_ASN1_SEQUENCE,
            &ber_tlv(TAG_ASN1_OCTET_STRING, &TEST_OBJECT_ID),
        );
        prkdf_body.extend_from_slice(&ber_tlv(TAG_ASN1_SEQUENCE, &key_attrs));
        prkdf_body.extend_from_slice(&ber_tlv(
            TAG_CONTEXT_CONSTRUCTED_1,
            &ber_tlv(
                TAG_ASN1_SEQUENCE,
                &ber_tlv(TAG_ASN1_SEQUENCE, &ber_tlv(TAG_ASN1_OCTET_STRING, &[])),
            ),
        ));
        let ef_prkdf = ber_tlv(TAG_CONTEXT_CONSTRUCTED_0, &prkdf_body);

        let mut pin_attrs = ber_tlv(
            TAG_ASN1_BIT_STRING,
            &[PIN_FLAGS_NONE_UNUSED_BITS, PIN_FLAGS_NONE_BYTE],
        );
        pin_attrs.extend_from_slice(&ber_tlv(TAG_ASN1_ENUMERATED, &[PIN_TYPE_ASCII_NUMERIC]));
        pin_attrs.extend_from_slice(&ber_tlv(TAG_ASN1_INTEGER, &[PIN_MIN_LENGTH]));
        pin_attrs.extend_from_slice(&ber_tlv(TAG_ASN1_INTEGER, &[PIN_STORED_LENGTH]));
        pin_attrs.extend_from_slice(&ber_tlv(TAG_ASN1_INTEGER, &[PIN_MAX_LENGTH]));
        pin_attrs.extend_from_slice(&ber_tlv(TAG_CONTEXT_PRIMITIVE_0, &[TEST_PIN1_REF]));
        let mut aod_body = ber_tlv(TAG_ASN1_SEQUENCE, &[]);
        aod_body.extend_from_slice(&ber_tlv(
            TAG_ASN1_SEQUENCE,
            &ber_tlv(TAG_ASN1_OCTET_STRING, &TEST_OBJECT_ID),
        ));
        aod_body.extend_from_slice(&ber_tlv(
            TAG_CONTEXT_CONSTRUCTED_1,
            &ber_tlv(TAG_ASN1_SEQUENCE, &pin_attrs),
        ));
        let ef_aod = ber_tlv(TAG_ASN1_SEQUENCE, &aod_body);

        let fnf = response_with_sw(&[], StatusWord::FileNotFound);
        let eof_with = |body: &[u8]| response_with_sw(body, StatusWord::EndOfFile);
        let read_chunk = read_core_chunk_wire();

        let mut tx = ScriptedTransport::new(vec![
            (select_aid.clone(), ok(&[])),
            (select_ef_wire(EF_AUTH_CERT_FID), fnf.clone()),
            (select_any_wire(EF_AUTH_CERT_FID), fnf),
            (select_mf, ok(&[])),
            (select_ef_wire(refineid_pkcs15::EF_DIR_FID), ok(&[])),
            (read_chunk.clone(), eof_with(&ef_dir)),
            (select_aid.clone(), ok(&[])),
            (select_ef_wire(refineid_pkcs15::EF_ODF_FID), ok(&[])),
            (read_chunk.clone(), eof_with(&ef_odf)),
            (select_aid.clone(), ok(&[])),
            (select_ef_wire(TEST_CDF_FID), ok(&[])),
            (read_chunk.clone(), eof_with(&ef_cdf)),
            (select_aid.clone(), ok(&[])),
            (select_ef_wire(TEST_PRKDF_FID), ok(&[])),
            (read_chunk.clone(), eof_with(&ef_prkdf)),
            (select_aid.clone(), ok(&[])),
            (select_ef_wire(TEST_AOD_FID), ok(&[])),
            (read_chunk.clone(), eof_with(&ef_aod)),
            (select_aid.clone(), ok(&[])),
            (select_auth_cert_path, ok(&[])),
            (read_chunk, eof_with(&cert)),
            (select_aid, ok(&[])),
        ]);

        let (der, profile) = tx
            .read_authentication_certificate_and_profile()
            .expect("discovers and reads Estonian auth cert");
        assert_eq!(der.as_bytes(), cert.as_slice());
        let profile = profile.expect("returns discovered profile");
        assert_eq!(
            profile.auth_key_reference().as_u8(),
            TEST_DISCOVERED_KEY_REF
        );
        assert_eq!(profile.pin1().reference(), TEST_PIN1_REF);
    }

    type ReaderScript = Vec<(Vec<u8>, ResponseApdu)>;

    struct ScriptedBackend {
        readers: Vec<(ReaderInfo, ReaderScript)>,
    }

    impl ReaderBackend for ScriptedBackend {
        type Transport = ScriptedTransport;
        type Error = String;

        fn enumerate(&self) -> Result<Vec<ReaderInfo>, Self::Error> {
            Ok(self.readers.iter().map(|(info, _)| info.clone()).collect())
        }

        fn open_session(
            &self,
            reader: &ReaderId,
            _access: ReaderAccessCap,
        ) -> Result<Self::Transport, Self::Error> {
            self.readers
                .iter()
                .find(|(info, _)| info.id == *reader)
                .map(|(_, script)| ScriptedTransport::new(script.clone()))
                .ok_or_else(|| format!("no script for reader {}", reader.as_str()))
        }
    }

    fn present(name: &str) -> ReaderInfo {
        ReaderInfo {
            id: ReaderId::new(name.to_owned()),
            card_present: true,
        }
    }

    fn card_access_script() -> ReaderScript {
        let body = hex::decode(concat!(
            "31283012060a04007f00070202040204020102020110",
            "3012060a04007f00070202040604020102020110",
        ))
        .expect("capture hex decodes");
        let card_access_fid = FileId::new(crate::card_access::EF_CARD_ACCESS_FID);
        vec![
            (select_any_wire(FileId::MF), ok(&[])),
            (select_ef_wire(card_access_fid), ok(&[])),
            (read_core_chunk_wire(), ok(&body)),
        ]
    }

    fn refusing_script() -> ReaderScript {
        let fnf = response_with_sw(&[], StatusWord::FileNotFound);
        vec![
            (select_any_wire(FileId::MF), fnf.clone()),
            (select_by_name_wire(FileId::MF), fnf),
        ]
    }

    #[test]
    fn contactless_pick_selects_the_card_access_server() {
        let backend = ScriptedBackend {
            readers: vec![
                (present("Dual Reader SAM"), refusing_script()),
                (present("Dual Reader PICC"), card_access_script()),
            ],
        };
        let id = super::pick_contactless_reader(&backend, None).expect("picks the PICC reader");
        assert_eq!(id.as_str(), "Dual Reader PICC");
    }

    #[test]
    fn contactless_pick_without_servers_is_no_fineid_card() {
        let backend = ScriptedBackend {
            readers: vec![(present("Dual Reader SAM"), refusing_script())],
        };
        assert!(matches!(
            super::pick_contactless_reader(&backend, None),
            Err(ReaderPickError::NoFineidCard { available }) if available == ["Dual Reader SAM"]
        ));
    }

    #[test]
    fn contactless_pick_ambiguity_follows_the_contact_rules() {
        const TWO_READERS: usize = 2;
        let backend = ScriptedBackend {
            readers: vec![
                (present("Reader A PICC"), card_access_script()),
                (present("Reader B PICC"), card_access_script()),
            ],
        };
        assert!(matches!(
            super::pick_contactless_reader(&backend, None),
            Err(ReaderPickError::MultipleReadersNoFilter { available }) if available.len() == TWO_READERS
        ));
        let filter = crate::backend::ReaderFilter::new("B PICC");
        let id =
            super::pick_contactless_reader(&backend, Some(&filter)).expect("filter disambiguates");
        assert_eq!(id.as_str(), "Reader B PICC");
    }
}
