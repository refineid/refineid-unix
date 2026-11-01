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

//! Document signing with the paired phone's card over RAPP.
//!
//! The phone shows the document names and takes PIN 2 on its own
//! screen; this computer sends digests and receives signatures, and
//! never asks for, holds or sends a PIN. `refineid_doc_sign::remote`
//! builds, checks and finishes the documents; this module carries its
//! two calls over the paired phone's session: `read_certificate` with
//! kind `signature`, then `sign_document` for one document or
//! `batch_sign_documents` for several (RAPP v26.10.29 section 9.3).
//!
//! A card in a reader attached to this computer outranks the phone:
//! [`choose_source`] picks the phone only when no reader holds a card.

use core::fmt;
use std::time::Duration;

use refineid_doc_sign::remote::{
    PhoneDocumentOutcome, PhoneRefusal, PhoneSignOptions, PhoneSigningBatch, RemoteSigner,
    UnvalidatedPhoneCertificate, UnvalidatedPhoneSignature, sign_on_phone,
};
use refineid_doc_sign::service::SignErrorKind;
use refineid_pcsc::ReaderBackend as _;
use refineid_rapp_core::engine::{AdmissionError, OperationOutcome};
use refineid_rapp_core::ids::PairId;
use refineid_rapp_core::message::ResultError;
use refineid_rapp_core::operations::{
    CardKeyProfile, CardOperation, CardOperationResult, CertificateKind, SignatureAlgorithm,
};
use refineid_rapp_core::profiles::ProfileName;
use refineid_rapp_core::remote::{PairSummary, RemoteError, RemoteReader, RemoteSession};
use refineid_remote::{RemoteKeyProfile, RemoteSignatureAlgorithm};

use crate::exit_status::ExitStatus;

/// How long the signer browses for the paired phone and waits for its
/// card, as `phone auth` does.
const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(30);

/// Where a signing runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningSource {
    /// A card in a reader attached to this computer, or no source at
    /// all: the reader path reports what is missing.
    Reader,
    /// The card on the paired phone.
    Phone(PairId),
}

/// The source for a signing: a reader while any reader holds a card,
/// else the paired phone when its pairing is usable and grants
/// document signing, else the reader path.
#[must_use]
pub fn choose_source(card_in_reader: bool, phone: Option<&PairSummary>) -> SigningSource {
    if card_in_reader {
        return SigningSource::Reader;
    }
    match phone {
        Some(phone)
            if phone.usable()
                && phone
                    .granted_profiles
                    .contains(&ProfileName::DocumentSigning) =>
        {
            SigningSource::Phone(phone.pair_id)
        }
        Some(_) | None => SigningSource::Reader,
    }
}

/// Whether any reader attached to this computer holds a card. A reader
/// service that cannot be reached holds none.
#[must_use]
pub fn card_in_a_reader() -> bool {
    refineid_pcsc::PcscBackend
        .enumerate()
        .is_ok_and(|readers| readers.iter().any(|reader| reader.card_present))
}

/// The paired phone, as the pairing store records it.
#[must_use]
pub fn paired_phone() -> Option<PairSummary> {
    RemoteReader::open_local().ok()?.phone()
}

/// The source for a signing on this computer now, by [`choose_source`].
#[must_use]
pub fn current_source() -> SigningSource {
    choose_source(card_in_a_reader(), paired_phone().as_ref())
}

/// One RAPP operation against the paired phone.
pub trait PhoneLink {
    /// Run `operation` and return the phone's result.
    ///
    /// # Errors
    /// [`RemoteError`] when no result arrives.
    fn run(&mut self, operation: &CardOperation) -> Result<CardOperationResult, RemoteError>;
}

/// The paired phone over its session: opened on the first operation,
/// held for the next, closed on drop. The pairing's lock is held with
/// the session, so one program on this computer holds the phone.
#[derive(Debug)]
pub struct PairedPhoneLink {
    /// The pairing store and requester.
    reader: RemoteReader,
    /// The pairing the session serves.
    pair_id: PairId,
    /// The session, once opened.
    session: Option<RemoteSession>,
}

impl PairedPhoneLink {
    /// The link to the phone of `pair_id`.
    ///
    /// # Errors
    /// [`RemoteError::Store`] when the pairing store cannot be opened.
    pub fn open(pair_id: PairId) -> Result<Self, RemoteError> {
        Ok(Self {
            reader: RemoteReader::open_local()?,
            pair_id,
            session: None,
        })
    }
}

impl PhoneLink for PairedPhoneLink {
    fn run(&mut self, operation: &CardOperation) -> Result<CardOperationResult, RemoteError> {
        let session = match &mut self.session {
            Some(session) => session,
            None => self.session.insert(
                self.reader
                    .open_session(Some(self.pair_id), DISCOVERY_TIMEOUT)?,
            ),
        };
        self.reader.execute_on(session, operation)
    }
}

impl Drop for PairedPhoneLink {
    fn drop(&mut self) {
        if let Some(session) = self.session.take() {
            self.reader.close_session(session);
        }
    }
}

/// [`RemoteSigner`] over a [`PhoneLink`], keeping the reader's own
/// account of a refusal for the message.
#[derive(Debug)]
pub struct PhoneSigner<Link> {
    /// The phone.
    link: Link,
    /// Why the last operation ended without a result.
    cause: Option<RemoteError>,
}

impl<Link: PhoneLink> PhoneSigner<Link> {
    /// A signer over `link`.
    pub const fn new(link: Link) -> Self {
        Self { link, cause: None }
    }

    /// Run `operation`; a failure is kept as the cause and answered
    /// as its refusal.
    fn run(&mut self, operation: &CardOperation) -> Result<CardOperationResult, PhoneRefusal> {
        self.link.run(operation).map_err(|error| {
            let refusal = refusal_of(&error);
            self.cause = Some(error);
            refusal
        })
    }
}

impl<Link: PhoneLink> RemoteSigner for PhoneSigner<Link> {
    fn signature_certificate(&mut self) -> Result<UnvalidatedPhoneCertificate, PhoneRefusal> {
        match self.run(&CardOperation::ReadCertificate {
            kind: CertificateKind::Signature,
        })? {
            CardOperationResult::Certificate(der) => Ok(UnvalidatedPhoneCertificate::from_der(der)),
            CardOperationResult::Inspection(_)
            | CardOperationResult::Identity(_)
            | CardOperationResult::Signature(_)
            | CardOperationResult::Signatures(_) => Err(PhoneRefusal::PhoneFailed),
        }
    }

    fn sign(
        &mut self,
        batch: &PhoneSigningBatch,
    ) -> Result<Vec<UnvalidatedPhoneSignature>, PhoneRefusal> {
        let several = batch.documents().len() > 1;
        match (several, self.run(&operation_for(batch))?) {
            (false, CardOperationResult::Signature(signature)) => {
                Ok(vec![UnvalidatedPhoneSignature::from_bytes(signature)])
            }
            (true, CardOperationResult::Signatures(signatures)) => Ok(signatures
                .into_iter()
                .map(UnvalidatedPhoneSignature::from_bytes)
                .collect()),
            (
                _,
                CardOperationResult::Inspection(_)
                | CardOperationResult::Identity(_)
                | CardOperationResult::Certificate(_)
                | CardOperationResult::Signature(_)
                | CardOperationResult::Signatures(_),
            ) => Err(PhoneRefusal::PhoneFailed),
        }
    }
}

/// The RAPP operation that signs `batch`: `sign_document` for one
/// document, `batch_sign_documents` for several, with the batch's key
/// profile, algorithm, names and digests unchanged and in order.
fn operation_for(batch: &PhoneSigningBatch) -> CardOperation {
    let key_profile = key_profile(batch.key_profile());
    let algorithm = algorithm(batch.algorithm());
    match batch.documents() {
        [document] => CardOperation::SignDocument {
            document_name: document.name().as_str().to_owned(),
            key_profile,
            algorithm,
            digest: document.digest().to_vec(),
        },
        documents => CardOperation::BatchSignDocuments {
            document_names: documents
                .iter()
                .map(|document| document.name().as_str().to_owned())
                .collect(),
            key_profile,
            algorithm,
            digests: documents
                .iter()
                .map(|document| document.digest().to_vec())
                .collect(),
        },
    }
}

/// The wire's key profile for the batch's.
const fn key_profile(profile: RemoteKeyProfile) -> CardKeyProfile {
    match profile {
        RemoteKeyProfile::EcdsaP256 => CardKeyProfile::EcdsaP256,
        RemoteKeyProfile::EcdsaP384 => CardKeyProfile::EcdsaP384,
        RemoteKeyProfile::Rsa2048 => CardKeyProfile::Rsa2048,
        RemoteKeyProfile::Rsa3072 => CardKeyProfile::Rsa3072,
    }
}

/// The wire's signature algorithm for the batch's.
const fn algorithm(algorithm: RemoteSignatureAlgorithm) -> SignatureAlgorithm {
    match algorithm {
        RemoteSignatureAlgorithm::EcdsaSha224 => SignatureAlgorithm::EcdsaSha224,
        RemoteSignatureAlgorithm::EcdsaSha256 => SignatureAlgorithm::EcdsaSha256,
        RemoteSignatureAlgorithm::EcdsaSha384 => SignatureAlgorithm::EcdsaSha384,
        RemoteSignatureAlgorithm::EcdsaSha512 => SignatureAlgorithm::EcdsaSha512,
        RemoteSignatureAlgorithm::RsaPkcs1Sha256 => SignatureAlgorithm::RsaPkcs1Sha256,
        RemoteSignatureAlgorithm::RsaPkcs1Sha384 => SignatureAlgorithm::RsaPkcs1Sha384,
        RemoteSignatureAlgorithm::RsaPkcs1Sha512 => SignatureAlgorithm::RsaPkcs1Sha512,
        RemoteSignatureAlgorithm::RsaPssSha256 => SignatureAlgorithm::RsaPssSha256,
    }
}

/// The refusal a reader failure stands for.
#[must_use]
pub fn refusal_of(error: &RemoteError) -> PhoneRefusal {
    match error {
        RemoteError::Outcome(outcome) => match **outcome {
            OperationOutcome::Rejected(result) | OperationOutcome::Cancelled(result) => {
                refusal_of_result(result)
            }
            OperationOutcome::Lost => PhoneRefusal::Unreachable,
            OperationOutcome::Refused | OperationOutcome::Completed(_) => PhoneRefusal::PhoneFailed,
        },
        RemoteError::Admission(AdmissionError::ProfileNotGranted) => PhoneRefusal::NotGranted,
        RemoteError::Admission(_) => PhoneRefusal::PhoneFailed,
        RemoteError::CardAbsent(_) | RemoteError::CardChanged => PhoneRefusal::CardUnavailable,
        RemoteError::Store(_)
        | RemoteError::NotPaired
        | RemoteError::NotFound
        | RemoteError::Withdrawn
        | RemoteError::RevokedByPhone
        | RemoteError::RandomUnavailable
        | RemoteError::Pairing(_)
        | RemoteError::Session(_)
        | RemoteError::Busy => PhoneRefusal::Unreachable,
    }
}

/// The refusal a RAPP section 10.3 error stands for.
const fn refusal_of_result(error: ResultError) -> PhoneRefusal {
    match error {
        ResultError::UserCancelled => PhoneRefusal::Declined,
        ResultError::OperationExpired => PhoneRefusal::Expired,
        ResultError::CardError => PhoneRefusal::CardUnavailable,
        ResultError::RetryFloor => PhoneRefusal::RetryFloor,
        ResultError::Unauthorized => PhoneRefusal::NotGranted,
        ResultError::UnsupportedParameter => PhoneRefusal::Unsupported,
        ResultError::OperationFailed
        | ResultError::Busy
        | ResultError::DuplicateOperation
        | ResultError::InvalidLifetime => PhoneRefusal::PhoneFailed,
    }
}

/// A signing on the phone that wrote nothing, with the reader's account
/// of why the phone gave no answer, when it gave none.
#[derive(Debug)]
pub struct PhoneSignFailure {
    /// What the signing flow refused.
    pub kind: SignErrorKind,
    /// The reader's failure behind a refusal.
    pub cause: Option<Box<RemoteError>>,
}

impl PhoneSignFailure {
    /// The exit status the failure earns: a retry floor is a credential
    /// refusal, as on a local card.
    #[must_use]
    pub const fn exit_status(&self) -> ExitStatus {
        match self.kind {
            SignErrorKind::Phone(PhoneRefusal::RetryFloor) => ExitStatus::CardCredentialRejected,
            _ => ExitStatus::RuntimeFailure,
        }
    }
}

impl fmt::Display for PhoneSignFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            SignErrorKind::Phone(refusal) => match self.cause.as_deref() {
                Some(cause) if reader_tells(cause) => write!(f, "{cause}"),
                Some(RemoteError::Session(_)) => {
                    f.write_str("the connection to the paired phone was lost")
                }
                Some(_) | None => f.write_str(refusal_text(*refusal)),
            },
            SignErrorKind::PhoneCertificate(_) => {
                f.write_str("the certificate on the phone's card cannot be used for signing")
            }
            SignErrorKind::PhoneSignatureCount { .. } => {
                f.write_str(refusal_text(PhoneRefusal::PhoneFailed))
            }
            SignErrorKind::PhoneSignatureInvalid { .. } => f.write_str(
                "the signature from the phone did not match the card's certificate; \
                 nothing was written",
            ),
            kind => write!(f, "{kind}"),
        }
    }
}

/// Whether the reader's own text says best why the phone gave no
/// answer: what to do with the pairing, the phone or its card.
const fn reader_tells(cause: &RemoteError) -> bool {
    matches!(
        cause,
        RemoteError::NotPaired
            | RemoteError::NotFound
            | RemoteError::Withdrawn
            | RemoteError::RevokedByPhone
            | RemoteError::CardAbsent(_)
            | RemoteError::CardChanged
            | RemoteError::Busy
    )
}

/// What the user is told for a refusal.
const fn refusal_text(refusal: PhoneRefusal) -> &'static str {
    match refusal {
        PhoneRefusal::Declined => "the signature request was declined on the paired phone",
        PhoneRefusal::Expired => "the request was not approved on the phone in time",
        PhoneRefusal::CardUnavailable => "the card's answer was lost; nothing was written",
        PhoneRefusal::RetryFloor => "RefineID does not use either of the last two PIN 2 attempts",
        PhoneRefusal::NotGranted | PhoneRefusal::Unsupported => {
            "the phone cannot make this kind of signature"
        }
        PhoneRefusal::PhoneFailed => "the phone did not return a signature; nothing was written",
        PhoneRefusal::Unreachable => "the paired phone did not respond",
    }
}

/// Sign `documents` with the card on the phone of `pair_id`: one
/// certificate read, then every document in one request, so the holder
/// enters PIN 2 once, on the phone.
///
/// # Errors
/// [`PhoneSignFailure`] when nothing was written; once the phone's
/// signatures verified, each document's own outcome is at its position.
pub fn sign(
    pair_id: PairId,
    documents: Vec<PhoneSignOptions>,
) -> Result<Vec<PhoneDocumentOutcome>, PhoneSignFailure> {
    crate::doc_sign_http::install();
    let link = PairedPhoneLink::open(pair_id).map_err(|error| PhoneSignFailure {
        kind: SignErrorKind::Phone(refusal_of(&error)),
        cause: Some(Box::new(error)),
    })?;
    sign_over(link, documents)
}

/// [`sign`] over any link.
fn sign_over<Link: PhoneLink>(
    link: Link,
    documents: Vec<PhoneSignOptions>,
) -> Result<Vec<PhoneDocumentOutcome>, PhoneSignFailure> {
    let mut signer = PhoneSigner::new(link);
    sign_on_phone(&mut signer, documents).map_err(|kind| PhoneSignFailure {
        kind,
        cause: signer.cause.take().map(Box::new),
    })
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use refineid_doc_sign::cades::SigningTime;
    use refineid_doc_sign::document::Format;
    use refineid_doc_sign::pades::SignatureMetadata;
    use refineid_doc_sign::service::{DocumentRequest, SignOutput, SigningDevice};
    use refineid_doc_sign::testkit::{
        CertificateSpec, KEY_USAGE_NON_REPUDIATION, KEY_USAGE_NON_REPUDIATION_UNUSED, TestCurve,
        TestKey, certificate, day, key_usage, minimal_pdf,
    };
    use refineid_rapp_core::remote::CardRequest;
    use refineid_rapp_core::store::PairingState;

    use super::*;
    use crate::test_util::{TempDir, TestResult, check, check_true};

    /// First day of the fixture certificate's validity.
    const NOT_BEFORE: u8 = 1;
    /// Last day of the fixture certificate's validity.
    const NOT_AFTER: u8 = 28;
    /// Serial of the phone's signature certificate.
    const SIGNER_SERIAL: u8 = 7;
    /// The claimed signing time, inside the fixture validity.
    const SIGNING_TIME: SigningTime = SigningTime {
        year: 2026,
        month: 6,
        day: 15,
        hour: 12,
        minute: 0,
        second: 0,
    };
    /// A synthetic pairing.
    const PAIR_ID: [u8; 16] = *b"synthetic-pair-1";

    /// What the scripted phone answers to a signing request.
    #[derive(Debug, Clone)]
    enum Answer {
        /// Signs every digest.
        Sign,
        /// Fails the operation as the reader reports it.
        Fail(RemoteError),
    }

    /// A paired phone whose card holds a P-384 key, answering
    /// `read_certificate` with its certificate and a signing request as
    /// `answer` says. Records every operation it was asked.
    struct ScriptedPhone {
        key: TestKey,
        certificate: Vec<u8>,
        answer: Answer,
        seen: Vec<CardOperation>,
    }

    impl ScriptedPhone {
        fn new(answer: Answer) -> Self {
            let key = TestKey::derive(TestCurve::P384, b"phone-signature");
            let issuer = TestKey::derive(TestCurve::P384, b"phone-signature-issuer");
            let spec = CertificateSpec {
                serial: SIGNER_SERIAL,
                subject: "Test Holder",
                issuer: "Test Signature CA",
                not_before: day(NOT_BEFORE),
                not_after: day(NOT_AFTER),
                extensions: vec![key_usage(
                    KEY_USAGE_NON_REPUDIATION_UNUSED,
                    KEY_USAGE_NON_REPUDIATION,
                )],
            };
            let certificate = certificate(&spec, &key, &issuer);
            Self {
                key,
                certificate,
                answer,
                seen: Vec::new(),
            }
        }
    }

    impl PhoneLink for &mut ScriptedPhone {
        fn run(&mut self, operation: &CardOperation) -> Result<CardOperationResult, RemoteError> {
            self.seen.push(operation.clone());
            match (operation, &self.answer) {
                (CardOperation::ReadCertificate { .. }, _) => {
                    Ok(CardOperationResult::Certificate(self.certificate.clone()))
                }
                (_, Answer::Fail(error)) => Err(error.clone()),
                (CardOperation::SignDocument { digest, .. }, Answer::Sign) => Ok(
                    CardOperationResult::Signature(self.key.sign_digest_raw(digest)),
                ),
                (CardOperation::BatchSignDocuments { digests, .. }, Answer::Sign) => {
                    Ok(CardOperationResult::Signatures(
                        digests
                            .iter()
                            .map(|digest| self.key.sign_digest_raw(digest))
                            .collect(),
                    ))
                }
                (_, Answer::Sign) => Err(RemoteError::Outcome(Box::new(OperationOutcome::Refused))),
            }
        }
    }

    /// A level-B request: no authority is reached.
    fn request(format: Format) -> DocumentRequest {
        DocumentRequest {
            format,
            additional_inputs: Vec::new(),
            signing_time: SIGNING_TIME,
            metadata: SignatureMetadata::default(),
            archive: false,
            long_term: false,
            timestamp_authorities: Vec::new(),
            timestamp_credentials: None,
        }
    }

    /// One PDF named `name` in `dir`.
    fn pdf(dir: &TempDir, name: &str) -> Result<PhoneSignOptions, std::io::Error> {
        Ok(PhoneSignOptions {
            input: dir.write(name, &minimal_pdf())?,
            output: SignOutput::At(dir.path().join(format!("signed-{name}"))),
            document: request(Format::Pades),
        })
    }

    /// Where `documents` are written.
    fn outputs(documents: &[PhoneSignOptions]) -> Vec<PathBuf> {
        documents
            .iter()
            .map(|document| document.output.path(None))
            .collect()
    }

    #[test]
    fn one_document_is_one_sign_document_after_the_certificate() -> TestResult {
        let dir = TempDir::new("phone-one")?;
        let documents = vec![pdf(&dir, "report.pdf")?];
        let written = outputs(&documents);
        let mut phone = ScriptedPhone::new(Answer::Sign);
        let outcomes = sign_over(&mut phone, documents).map_err(|f| f.to_string())?;
        check(&outcomes.len(), &1, "one outcome")?;
        let Some(Ok(report)) = outcomes.first() else {
            return Err("the document was not signed".into());
        };
        check(
            &report.device,
            &SigningDevice::PairedPhone,
            "signed on the phone",
        )?;
        check_true(written.iter().all(|path| path.exists()), "written")?;
        check(&phone.seen.len(), &2, "two operations")?;
        check_true(
            matches!(
                phone.seen.first(),
                Some(CardOperation::ReadCertificate {
                    kind: CertificateKind::Signature
                })
            ),
            "the signature certificate first",
        )?;
        check_true(
            matches!(
                phone.seen.get(1),
                Some(CardOperation::SignDocument {
                    document_name,
                    key_profile: CardKeyProfile::EcdsaP384,
                    algorithm: SignatureAlgorithm::EcdsaSha384,
                    ..
                }) if document_name == "report.pdf"
            ),
            "one sign_document naming the file",
        )
    }

    #[test]
    fn several_documents_are_one_batch() -> TestResult {
        let dir = TempDir::new("phone-batch")?;
        let names = ["first.pdf", "second.pdf", "third.pdf"];
        let documents = names
            .iter()
            .map(|name| pdf(&dir, name))
            .collect::<Result<Vec<_>, _>>()?;
        let written = outputs(&documents);
        let mut phone = ScriptedPhone::new(Answer::Sign);
        let outcomes = sign_over(&mut phone, documents).map_err(|f| f.to_string())?;
        check_true(outcomes.iter().all(Result::is_ok), "every document signed")?;
        check_true(written.iter().all(|path| path.exists()), "all written")?;
        check(&phone.seen.len(), &2, "one certificate read, one batch")?;
        let Some(CardOperation::BatchSignDocuments {
            document_names,
            digests,
            ..
        }) = phone.seen.get(1)
        else {
            return Err("no batch_sign_documents".into());
        };
        check(
            document_names,
            &names.map(str::to_owned).to_vec(),
            "names in order",
        )?;
        check(&digests.len(), &names.len(), "one digest per document")
    }

    #[test]
    fn a_refused_signing_writes_nothing_and_keeps_its_cause() -> TestResult {
        let dir = TempDir::new("phone-refused")?;
        let documents = vec![pdf(&dir, "report.pdf")?];
        let written = outputs(&documents);
        let mut phone = ScriptedPhone::new(Answer::Fail(RemoteError::Outcome(Box::new(
            OperationOutcome::Rejected(ResultError::UserCancelled),
        ))));
        let Err(failure) = sign_over(&mut phone, documents) else {
            return Err("a declined signing succeeded".into());
        };
        check_true(
            matches!(failure.kind, SignErrorKind::Phone(PhoneRefusal::Declined)),
            "declined",
        )?;
        check(
            &failure.to_string(),
            &"the signature request was declined on the paired phone".to_owned(),
            "the phone's wording",
        )?;
        check_true(!written.iter().any(|path| path.exists()), "nothing written")
    }

    #[test]
    fn a_phone_without_its_card_says_so() -> TestResult {
        let dir = TempDir::new("phone-no-card")?;
        let documents = vec![pdf(&dir, "report.pdf")?];
        let mut phone =
            ScriptedPhone::new(Answer::Fail(RemoteError::CardAbsent(CardRequest::ToPhone)));
        let Err(failure) = sign_over(&mut phone, documents) else {
            return Err("signed without a card".into());
        };
        check(
            &failure.to_string(),
            &RemoteError::CardAbsent(CardRequest::ToPhone).to_string(),
            "the reader's own text",
        )
    }

    #[test]
    fn each_phone_error_is_its_refusal() -> TestResult {
        let rejected = |error| RemoteError::Outcome(Box::new(OperationOutcome::Rejected(error)));
        let cancelled = |error| RemoteError::Outcome(Box::new(OperationOutcome::Cancelled(error)));
        for (error, refusal) in [
            (rejected(ResultError::UserCancelled), PhoneRefusal::Declined),
            (
                cancelled(ResultError::UserCancelled),
                PhoneRefusal::Declined,
            ),
            (
                rejected(ResultError::OperationExpired),
                PhoneRefusal::Expired,
            ),
            (
                rejected(ResultError::CardError),
                PhoneRefusal::CardUnavailable,
            ),
            (rejected(ResultError::RetryFloor), PhoneRefusal::RetryFloor),
            (
                rejected(ResultError::Unauthorized),
                PhoneRefusal::NotGranted,
            ),
            (
                rejected(ResultError::UnsupportedParameter),
                PhoneRefusal::Unsupported,
            ),
            (
                rejected(ResultError::OperationFailed),
                PhoneRefusal::PhoneFailed,
            ),
            (rejected(ResultError::Busy), PhoneRefusal::PhoneFailed),
            (
                RemoteError::Outcome(Box::new(OperationOutcome::Lost)),
                PhoneRefusal::Unreachable,
            ),
            (
                RemoteError::Outcome(Box::new(OperationOutcome::Refused)),
                PhoneRefusal::PhoneFailed,
            ),
            (
                RemoteError::Admission(AdmissionError::ProfileNotGranted),
                PhoneRefusal::NotGranted,
            ),
            (
                RemoteError::CardAbsent(CardRequest::InPhoneReader),
                PhoneRefusal::CardUnavailable,
            ),
            (RemoteError::CardChanged, PhoneRefusal::CardUnavailable),
            (RemoteError::NotFound, PhoneRefusal::Unreachable),
            (RemoteError::NotPaired, PhoneRefusal::Unreachable),
            (RemoteError::Withdrawn, PhoneRefusal::Unreachable),
            (RemoteError::RevokedByPhone, PhoneRefusal::Unreachable),
            (RemoteError::Busy, PhoneRefusal::Unreachable),
        ] {
            check(&refusal_of(&error), &refusal, &format!("{error:?}"))?;
        }
        Ok(())
    }

    #[test]
    fn a_retry_floor_is_a_credential_refusal() -> TestResult {
        let floor = PhoneSignFailure {
            kind: SignErrorKind::Phone(PhoneRefusal::RetryFloor),
            cause: None,
        };
        check(
            &floor.exit_status(),
            &ExitStatus::CardCredentialRejected,
            "floor",
        )?;
        let declined = PhoneSignFailure {
            kind: SignErrorKind::Phone(PhoneRefusal::Declined),
            cause: None,
        };
        check(
            &declined.exit_status(),
            &ExitStatus::RuntimeFailure,
            "declined",
        )
    }

    /// A pairing in `state` granting `profiles`.
    fn pairing(state: PairingState, profiles: Vec<ProfileName>) -> PairSummary {
        PairSummary {
            pair_id: PairId::from_array(PAIR_ID),
            peer_display_name: "custodian-1".to_owned(),
            peer_platform: "Synthetic".to_owned(),
            granted_profiles: profiles,
            auth_cert: None,
            state,
        }
    }

    #[test]
    fn a_card_in_a_reader_outranks_the_phone() -> TestResult {
        let phone = pairing(
            PairingState::PairedDisconnected,
            vec![ProfileName::Authentication, ProfileName::DocumentSigning],
        );
        check(
            &choose_source(true, Some(&phone)),
            &SigningSource::Reader,
            "a card in a reader",
        )?;
        check(
            &choose_source(false, Some(&phone)),
            &SigningSource::Phone(phone.pair_id),
            "no card in a reader",
        )?;
        check(
            &choose_source(false, None),
            &SigningSource::Reader,
            "no phone: the reader path says what is missing",
        )
    }

    #[test]
    fn only_a_usable_pairing_granting_signing_signs() -> TestResult {
        let login_only = pairing(
            PairingState::PairedDisconnected,
            vec![ProfileName::Authentication],
        );
        check(
            &choose_source(false, Some(&login_only)),
            &SigningSource::Reader,
            "not granted document signing",
        )?;
        let forgotten = pairing(PairingState::Revoking, vec![ProfileName::DocumentSigning]);
        check(
            &choose_source(false, Some(&forgotten)),
            &SigningSource::Reader,
            "a forgotten pairing",
        )
    }
}
