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

//! `document verify`: judge a signed document file, then ask the
//! network about revocation where the file carried no answer.
//!
//! The verdict itself comes from `refineid_lib_core::document` and the
//! document's own bytes. Only the revocation row may go further: a
//! signer the document says nothing about is looked up over OCSP or
//! CRL, the same walk `document sign` takes when it gathers level-LT
//! evidence, and a network that does not answer leaves the row as it
//! was.

use std::path::{Path, PathBuf};

use refineid_lib_core::document::{
    DocumentFailure, DocumentFile, DocumentReport, Revocation, SignatureReport, TrustAnchors,
};
use refineid_lib_core::x509::DateTime;

use crate::trust_roots::PINNED_ROOT_DER;
use crate::validation_material::{
    ChainStart, MaterialError, NoncePolicy, collect_chains_with_candidates,
};

/// Why a file yielded no report.
#[derive(Debug)]
pub enum DocumentVerifyError {
    /// The file could not be read.
    Read {
        /// The file.
        path: PathBuf,
        /// Underlying `std::io::Error`.
        source: std::io::Error,
    },
    /// The file was read and nothing in it could be judged.
    Failure {
        /// The file.
        path: PathBuf,
        /// What the verifier found instead of signatures.
        failure: DocumentFailure,
    },
}

impl core::fmt::Display for DocumentVerifyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Read { path, source } => write!(f, "{}: {source}", path.display()),
            Self::Failure { path, failure } => write!(f, "{}: {failure}", path.display()),
        }
    }
}

impl core::error::Error for DocumentVerifyError {}

/// Judge the document at `path` as of `now`.
///
/// Every signature is verified from the file alone, anchored on the
/// pinned DVV roots. A signer whose revocation the file does not
/// answer is then asked about over the network; the answer is dated
/// `now`, and no answer leaves the row unavailable.
///
/// # Errors
/// [`DocumentVerifyError`] when the file cannot be read or carries
/// nothing to judge. A negative verdict is not an error.
pub fn verify_file(path: &Path, now: DateTime) -> Result<DocumentReport, DocumentVerifyError> {
    let bytes = std::fs::read(path).map_err(|source| DocumentVerifyError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    let file = DocumentFile::from_file(bytes);
    let anchors: Vec<&[u8]> = PINNED_ROOT_DER.iter().map(|(_, der)| *der).collect();
    let mut report = refineid_lib_core::document::verify(&file, TrustAnchors::new(&anchors), now)
        .map_err(|failure| DocumentVerifyError::Failure {
        path: path.to_path_buf(),
        failure,
    })?;
    for signature in &mut report.signatures {
        if signature.revocation == Revocation::Unavailable {
            signature.revocation = live_revocation(signature, now);
        }
    }
    Ok(report)
}

/// Ask the signer's responders whether the certificate is good now.
///
/// The walk must reach a pinned root and every step must answer; a
/// signer outside that trust, or a responder that does not answer,
/// leaves the revocation unavailable rather than guessed.
fn live_revocation(signature: &SignatureReport, now: DateTime) -> Revocation {
    let anchors: Vec<&[u8]> = PINNED_ROOT_DER.iter().map(|(_, der)| *der).collect();
    let candidates: Vec<&[u8]> = signature
        .issuer_certificate
        .iter()
        .map(|issuer| issuer.as_der())
        .collect();
    let start = ChainStart {
        leaf_der: signature.signer_certificate.as_der(),
        reference_time: now,
        approved_anchor_ders: &anchors,
        nonce_policy: NoncePolicy::AllowMissingEcho,
        include_leaf: false,
        include_anchor: false,
    };
    match collect_chains_with_candidates(&[start], &candidates) {
        Ok(_) => Revocation::Good { checked_at: now },
        Err(MaterialError::Revoked(_)) => Revocation::Revoked,
        Err(_) => Revocation::Unavailable,
    }
}
