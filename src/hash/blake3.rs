//! Blake3 transcript hashing interface declarations.
//!
//! The actual hashing logic lives in host environments.  This module documents how the
//! STARK stack expects the transcript hasher to behave, including domain separation,
//! message framing and finalisation semantics.

use super::config::Blake3Parameters;

/// Interface describing transcript hashing for the STARK protocol.
///
/// * Every message absorbed into the transcript must be length-prefixed with a
///   32-bit little-endian unsigned integer describing the number of bytes being
///   absorbed.
/// * All transcripts are initialised with the domain tag defined by
///   [`crate::hash::config::BLAKE3_COMMITMENT_DOMAIN_TAG`] to ensure separation from
///   arithmetic hashes.
/// * Implementations must expose the parameter descriptor so verifiers can confirm that
///   both parties run the same versioned hash function ([`crate::hash::config::BLAKE3_PARAMETERS_V1_ID`]).
///
/// The trait intentionally does not prescribe an implementation; it simply formalises
/// the contract that a BLAKE3-based transcript hasher must uphold when used as part of
/// the STARK proving system.
pub trait TranscriptHasher {
    /// Digest type returned after finalisation (typically 32 bytes for BLAKE3).
    type Digest;

    /// Returns the static parameter descriptor declaring version and domain tag.
    fn parameters(&self) -> Blake3Parameters;

    /// Resets the hasher to its initial domain-separated state.
    fn reset(&mut self);

    /// Absorbs a length-prefixed message into the transcript.
    fn absorb_length_prefixed(&mut self, message: &[u8]);

    /// Finalises the transcript and returns the digest.
    fn finalize(self) -> Self::Digest;
}
