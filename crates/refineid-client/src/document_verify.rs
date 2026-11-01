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
//! The verdict comes from `refineid_doc_sign::verification` and the
//! document's own bytes, under the roots core pins. Only the
//! revocation row may go further: a signer on a verified chain the
//! document says nothing about is looked up over OCSP or CRL at `now`,
//! and a network that does not answer leaves the row as it was.

use std::path::{Path, PathBuf};

use refineid_doc_sign::verification::live::live_revocation;
use refineid_doc_sign::verification::{
    DocumentFailure, DocumentFile, DocumentReport, TrustAnchors,
};
use refineid_doc_sign::x509::DateTime;

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
/// roots core pins, at the earliest time a timestamp proves, else at
/// `now`. A signer on a verified chain whose revocation the file does
/// not answer is then asked about over the network; the answer is
/// judged at `now`, and no answer leaves the row unavailable.
///
/// # Errors
/// [`DocumentVerifyError`] when the file cannot be read or carries
/// nothing to judge. A negative verdict is not an error.
pub fn verify_file(path: &Path, now: DateTime) -> Result<DocumentReport, DocumentVerifyError> {
    let failure = |failure| DocumentVerifyError::Failure {
        path: path.to_path_buf(),
        failure,
    };
    let bytes = std::fs::read(path).map_err(|source| DocumentVerifyError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    let file = DocumentFile::from_file(bytes).map_err(failure)?;
    let anchors = TrustAnchors::pinned();
    let report = refineid_doc_sign::verification::verify(&file, &anchors, now).map_err(failure)?;
    crate::doc_sign_http::install();
    Ok(report.with_live_revocation(|signature| live_revocation(signature, &anchors, now)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{TestResult, check_true};

    #[test]
    fn a_file_that_is_no_document_is_a_failure() -> TestResult {
        let dir = std::env::temp_dir().join(format!("refineid-verify-file-{}", std::process::id()));
        std::fs::create_dir_all(&dir)?;
        let file = dir.join("notes.txt");
        std::fs::write(&file, b"synthetic notes")?;
        let outcome = verify_file(&file, refineid_doc_sign::now_date_time());
        let _removed = std::fs::remove_dir_all(&dir);
        check_true(
            matches!(
                outcome,
                Err(DocumentVerifyError::Failure {
                    failure: DocumentFailure::NotASignedDocument,
                    ..
                })
            ),
            "not a signed document",
        )
    }

    #[test]
    fn a_missing_file_is_a_read_error() -> TestResult {
        let missing = std::env::temp_dir().join("refineid-verify-file-missing.pdf");
        check_true(
            matches!(
                verify_file(&missing, refineid_doc_sign::now_date_time()),
                Err(DocumentVerifyError::Read { .. })
            ),
            "read error",
        )
    }
}
