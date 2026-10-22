//! Device-local serialization of a pairing record.
//!
//! A durable [`PairingStore`](crate::store::PairingStore) -- here the
//! owner-only [`FilePairingStore`](crate::file_store::FilePairingStore) --
//! needs the record's bytes. The engine's half of the record, with the pair
//! keys, the grants, the storage confirmation and the time it was forgotten,
//! travels in the engine's own encoding ([`refineid_rapp::encode_pair_record`]);
//! this module frames it with what the workstation keeps beside it, in a
//! versioned, length-framed encoding with no external serde surface.
//!
//! The encoded blob carries the private key, so [`encode_pairing_record`]
//! returns it inside [`Zeroizing`]; callers hand it straight to device-only
//! secret storage and never log it. [`decode_pairing_record`] bounds-checks
//! every field, rejects trailing bytes, and rebuilds the record through the
//! engine's decoder and [`PairingRecord::new`], so a truncated or tampered
//! blob fails closed rather than yielding a half-built record.

use refineid_rapp::{PairRecordCodecError, decode_pair_record, encode_pair_record};
use zeroize::Zeroizing;

use crate::store::{PairingRecord, PeerIntroduction, RecordError};

/// Format tag identifying a `RefineID` pairing-record blob.
pub(crate) const PAIRING_BLOB_MAGIC: &[u8] = b"RAPP-pair-record";

/// The one encoding revision this build reads and writes. Records of earlier
/// revisions belong to earlier protocol versions and are re-paired.
pub(crate) const PAIRING_BLOB_VERSION: u8 = 9;

/// Bytes of a length prefix: a big-endian `u32`.
const LENGTH_PREFIX_BYTES: usize = 4;
/// Bytes of the presence flag of an optional field.
const OPTIONAL_FLAG_BYTES: usize = 1;
/// Bytes of the encoding revision.
const VERSION_BYTES: usize = 1;

/// An absent optional field.
const ABSENT: u8 = 0;
/// A present optional field.
const PRESENT: u8 = 1;

/// Why a stored pairing blob could not be encoded or decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PairingCodecError {
    /// The blob did not begin with the pairing-record format tag.
    BadMagic,
    /// The blob used an encoding revision this build does not understand.
    UnsupportedVersion {
        /// The revision found in the blob.
        found: u8,
    },
    /// The blob ended before a field was fully read.
    Truncated,
    /// Bytes remained after the last field was read.
    TrailingBytes,
    /// An optional field's flag was neither absent nor present.
    InvalidFlag,
    /// A text field was not valid UTF-8.
    InvalidText,
    /// A length does not fit the length prefix.
    Oversized,
    /// The engine's record did not encode or decode.
    Pairing(PairRecordCodecError),
    /// The engine's record is not one this store holds.
    Record(RecordError),
}

impl core::fmt::Display for PairingCodecError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BadMagic => formatter.write_str("blob is not a pairing record"),
            Self::UnsupportedVersion { found } => {
                write!(formatter, "unsupported pairing-record revision {found}")
            }
            Self::Truncated => formatter.write_str("pairing record ended mid-field"),
            Self::TrailingBytes => formatter.write_str("pairing record had trailing bytes"),
            Self::InvalidFlag => formatter.write_str("pairing record had a malformed flag"),
            Self::InvalidText => formatter.write_str("pairing record held invalid text"),
            Self::Oversized => formatter.write_str("pairing record field too long"),
            Self::Pairing(error) => write!(formatter, "pairing keys: {error}"),
            Self::Record(error) => write!(formatter, "pairing record refused: {error:?}"),
        }
    }
}

impl core::error::Error for PairingCodecError {}

/// Serializes a pairing record for device-only secret storage.
///
/// The returned blob contains the pair-specific private key and is therefore
/// wrapped in [`Zeroizing`]: hand it directly to device-only storage
/// and never log it.
///
/// # Errors
/// [`PairingCodecError::Pairing`] when the engine cannot encode its record,
/// and [`PairingCodecError::Oversized`] for a field longer than a length
/// prefix holds.
pub fn encode_pairing_record(
    record: &PairingRecord,
) -> Result<Zeroizing<Vec<u8>>, PairingCodecError> {
    let pairing =
        Zeroizing::new(encode_pair_record(record.pairing()).map_err(PairingCodecError::Pairing)?);
    let peer = record.peer();
    let size = PAIRING_BLOB_MAGIC.len()
        + VERSION_BYTES
        + LENGTH_PREFIX_BYTES
        + pairing.len()
        + LENGTH_PREFIX_BYTES
        + peer.display_name.len()
        + LENGTH_PREFIX_BYTES
        + peer.platform.len()
        + OPTIONAL_FLAG_BYTES
        + record
            .auth_cert()
            .map(|cert| LENGTH_PREFIX_BYTES + cert.len())
            .unwrap_or_default();
    // Sized once, so the key bytes are copied into one buffer and no
    // discarded reallocation keeps them.
    let mut out = Zeroizing::new(Vec::with_capacity(size));
    out.extend_from_slice(PAIRING_BLOB_MAGIC);
    out.push(PAIRING_BLOB_VERSION);
    put_bytes(&mut out, &pairing)?;
    put_bytes(&mut out, peer.display_name.as_bytes())?;
    put_bytes(&mut out, peer.platform.as_bytes())?;
    match record.auth_cert() {
        Some(cert) => {
            out.push(PRESENT);
            put_bytes(&mut out, cert)?;
        }
        None => out.push(ABSENT),
    }
    Ok(out)
}

/// Whether `blob` is a pairing record of an earlier encoding revision,
/// which this build no longer reads: such a record belongs to an earlier
/// protocol version, and its holder re-pairs.
#[must_use]
pub fn is_superseded(blob: &[u8]) -> bool {
    let mut reader = Reader::new(blob);
    reader.take(PAIRING_BLOB_MAGIC.len()) == Ok(PAIRING_BLOB_MAGIC)
        && reader
            .take_u8()
            .is_ok_and(|version| version < PAIRING_BLOB_VERSION)
}

/// Reconstructs a pairing record from a device-only blob.
///
/// # Errors
///
/// Fails when the blob is not a pairing record, uses an unknown revision, ends
/// mid-field, carries trailing bytes, or holds a malformed field or engine
/// record.
pub fn decode_pairing_record(blob: &[u8]) -> Result<PairingRecord, PairingCodecError> {
    let mut reader = Reader::new(blob);
    if reader.take(PAIRING_BLOB_MAGIC.len())? != PAIRING_BLOB_MAGIC {
        return Err(PairingCodecError::BadMagic);
    }
    let version = reader.take_u8()?;
    if version != PAIRING_BLOB_VERSION {
        return Err(PairingCodecError::UnsupportedVersion { found: version });
    }
    let pairing =
        decode_pair_record(reader.take_length_prefixed()?).map_err(PairingCodecError::Pairing)?;
    let peer = PeerIntroduction {
        display_name: reader.take_text()?,
        platform: reader.take_text()?,
    };
    let auth_cert = match reader.take_u8()? {
        ABSENT => None,
        PRESENT => Some(reader.take_length_prefixed()?.to_vec()),
        _ => return Err(PairingCodecError::InvalidFlag),
    };
    reader.finish()?;
    Ok(PairingRecord::new(pairing, peer)
        .map_err(PairingCodecError::Record)?
        .with_auth_cert(auth_cert))
}

/// Appends a length-prefixed byte string.
fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), PairingCodecError> {
    let length = u32::try_from(bytes.len()).map_err(|_| PairingCodecError::Oversized)?;
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

/// A bounds-checked forward cursor over a blob.
struct Reader<'blob> {
    remaining: &'blob [u8],
}

impl<'blob> Reader<'blob> {
    const fn new(blob: &'blob [u8]) -> Self {
        Self { remaining: blob }
    }

    /// Takes exactly `count` bytes or reports truncation.
    const fn take(&mut self, count: usize) -> Result<&'blob [u8], PairingCodecError> {
        let Some((head, tail)) = self.remaining.split_at_checked(count) else {
            return Err(PairingCodecError::Truncated);
        };
        self.remaining = tail;
        Ok(head)
    }

    /// Takes one byte.
    fn take_u8(&mut self) -> Result<u8, PairingCodecError> {
        let [byte] = self.take_array()?;
        Ok(byte)
    }

    /// Takes a fixed-size array.
    fn take_array<const LENGTH: usize>(&mut self) -> Result<[u8; LENGTH], PairingCodecError> {
        self.take(LENGTH)?
            .try_into()
            .map_err(|_| PairingCodecError::Truncated)
    }

    /// Takes a length-prefixed byte string.
    fn take_length_prefixed(&mut self) -> Result<&'blob [u8], PairingCodecError> {
        let length = u32::from_be_bytes(self.take_array()?);
        let length = usize::try_from(length).map_err(|_| PairingCodecError::Truncated)?;
        self.take(length)
    }

    /// Takes a length-prefixed UTF-8 string.
    fn take_text(&mut self) -> Result<String, PairingCodecError> {
        let bytes = self.take_length_prefixed()?;
        core::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|_error| PairingCodecError::InvalidText)
    }

    /// Confirms the blob was consumed exactly.
    const fn finish(&self) -> Result<(), PairingCodecError> {
        if self.remaining.is_empty() {
            Ok(())
        } else {
            Err(PairingCodecError::TrailingBytes)
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "test fixtures are constructed to be infallible"
)]
mod tests {
    use refineid_rapp::ProfileName;

    use super::{
        PAIRING_BLOB_MAGIC, PAIRING_BLOB_VERSION, PairingCodecError, decode_pairing_record,
        encode_pairing_record, is_superseded,
    };
    use crate::ids::PairId;
    use crate::store::fixtures::{pair_record, phone};
    use crate::store::{PairingRecord, PeerIntroduction};

    /// A synthetic pair identifier.
    const PAIR_ID: [u8; refineid_rapp::PAIR_ID_SIZE] = *b"synthetic-pair-7";
    /// When the forgotten fixture's user forgot it.
    const FORGOTTEN_AT_MS: u64 = 1_800_000_000_000;
    /// A synthetic authentication certificate.
    const CERTIFICATE: &[u8] = b"synthetic authentication certificate";
    /// The first encoding revision.
    const FIRST_REVISION: u8 = 1;
    /// A revision past the one this build reads.
    const LATER_REVISION: u8 = PAIRING_BLOB_VERSION + 1;
    /// A byte appended past the record's end.
    const TRAILING: &[u8] = b"!";

    fn sample() -> PairingRecord {
        PairingRecord::new(
            pair_record(
                PairId::from_array(PAIR_ID),
                vec![ProfileName::Authentication, ProfileName::DocumentSigning],
            ),
            PeerIntroduction {
                display_name: "Holder's Phone".into(),
                platform: "iOS".into(),
            },
        )
        .unwrap()
        .with_auth_cert(Some(CERTIFICATE.to_vec()))
    }

    fn assert_same(left: &PairingRecord, right: &PairingRecord) {
        assert_eq!(left.pair_id(), right.pair_id());
        assert_eq!(left.state(), right.state());
        assert_eq!(
            left.pairing().local_static_private(),
            right.pairing().local_static_private()
        );
        assert_eq!(
            left.pairing().remote_static_public(),
            right.pairing().remote_static_public()
        );
        assert_eq!(left.pairing().profiles(), right.pairing().profiles());
        assert_eq!(left.pairing().grants_hash(), right.pairing().grants_hash());
        assert_eq!(
            left.pairing().forgotten_at_ms(),
            right.pairing().forgotten_at_ms()
        );
        assert_eq!(left.peer(), right.peer());
        assert_eq!(left.auth_cert(), right.auth_cert());
    }

    /// `blob` with its revision replaced by `revision`.
    fn at_revision(blob: &[u8], revision: u8) -> Vec<u8> {
        let mut rewritten = PAIRING_BLOB_MAGIC.to_vec();
        rewritten.push(revision);
        rewritten.extend_from_slice(blob.get(rewritten.len()..).unwrap());
        rewritten
    }

    #[test]
    fn the_encoder_sizes_its_buffer_once() {
        let bare = PairingRecord::new(
            pair_record(PairId::from_array(PAIR_ID), vec![ProfileName::CardStatus]),
            phone(),
        )
        .unwrap();
        for record in [sample(), sample().forgotten(FORGOTTEN_AT_MS), bare] {
            let encoded = encode_pairing_record(&record).unwrap();
            assert_eq!(encoded.capacity(), encoded.len());
        }
    }

    #[test]
    fn round_trips_every_field() {
        let record = sample();
        let decoded = decode_pairing_record(&encode_pairing_record(&record).unwrap()).unwrap();
        assert_same(&record, &decoded);
    }

    #[test]
    fn round_trips_a_forgotten_record_with_its_key_and_time() {
        let record = sample().forgotten(FORGOTTEN_AT_MS);
        let decoded = decode_pairing_record(&encode_pairing_record(&record).unwrap()).unwrap();
        assert_same(&record, &decoded);
    }

    #[test]
    fn rejects_a_foreign_blob() {
        assert!(matches!(
            decode_pairing_record(b"not a pairing record at all"),
            Err(PairingCodecError::BadMagic)
        ));
    }

    #[test]
    fn rejects_a_truncated_blob() {
        let blob = encode_pairing_record(&sample()).unwrap();
        let cut = blob
            .get(..blob.len().saturating_sub(TRAILING.len()))
            .unwrap();
        assert!(matches!(
            decode_pairing_record(cut),
            Err(PairingCodecError::Truncated)
        ));
    }

    #[test]
    fn rejects_trailing_bytes() {
        let mut blob = encode_pairing_record(&sample()).unwrap().to_vec();
        blob.extend_from_slice(TRAILING);
        assert!(matches!(
            decode_pairing_record(&blob),
            Err(PairingCodecError::TrailingBytes)
        ));
    }

    #[test]
    fn rejects_a_later_revision_and_sweeps_only_earlier_ones() {
        let blob = encode_pairing_record(&sample()).unwrap();
        let later = at_revision(&blob, LATER_REVISION);
        assert!(matches!(
            decode_pairing_record(&later),
            Err(PairingCodecError::UnsupportedVersion { found }) if found == LATER_REVISION
        ));
        assert!(!is_superseded(&later));
        assert!(!is_superseded(&blob));
        for earlier in FIRST_REVISION..PAIRING_BLOB_VERSION {
            let earlier_blob = at_revision(&blob, earlier);
            assert!(matches!(
                decode_pairing_record(&earlier_blob),
                Err(PairingCodecError::UnsupportedVersion { found }) if found == earlier
            ));
            assert!(is_superseded(&earlier_blob));
        }
    }
}
