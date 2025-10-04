//! Transcript-driven randomness interfaces.
//!
//! This module defines abstract traits used by the prover and verifier to
//! communicate with transcript implementations. The concrete cryptographic
//! machinery lives outside of this crate; consumers are expected to implement
//! the traits using their preferred hash functions while adhering to the
//! canonical serialization rules described in [`crate::proof::transcript`].

use crate::proof::transcript::{
    ChallengeDeriver, ChallengeStream, SectionDescriptor, TranscriptLayout,
};
use crate::StarkResult;

/// Hook trait for absorbing transcript sections and deriving deterministic salts.
pub trait TranscriptHook {
    /// Type returned once the transcript has been fully absorbed.
    type Builder: ChallengeDeriver;

    /// Returns the layout the hook is expecting.
    fn layout(&self) -> &TranscriptLayout;

    /// Absorbs a transcript section and returns the derived `section_salt_i` value.
    ///
    /// Implementations must maintain a deterministic chain as specified by the
    /// STARK transcript design:
    ///
    /// ```text
    /// section_salt_0 = H("RPP-STARK-V1")
    /// section_salt_i = H(section_salt_{i-1} || len(payload)_LE || payload)
    /// ```
    ///
    /// where `H` denotes the hash primitive selected by the implementer and
    /// `len(payload)_LE` is a four-byte little-endian length prefix.
    fn absorb_section(
        &mut self,
        descriptor: SectionDescriptor,
        payload: &[u8],
    ) -> StarkResult<[u8; 32]>;

    /// Finalizes the transcript and yields a challenge derivation builder.
    fn finalize(self) -> StarkResult<Self::Builder>;
}

/// Utility trait allowing implementers to expose a ready-to-use challenge stream.
pub trait ChallengeStreamExt: ChallengeStream {
    /// Draws `output` bytes using the provided label, forwarding to the underlying stream.
    fn draw_bytes(&mut self, label: &'static str, output: &mut [u8]) -> StarkResult<()> {
        self.draw_challenge(crate::proof::transcript::ChallengeLabel(label), output)
    }
}

impl<T> ChallengeStreamExt for T where T: ChallengeStream {}
