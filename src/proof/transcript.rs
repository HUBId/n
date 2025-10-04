//! Transcript layout description and challenge derivation interfaces.
//!
//! The STARK transcript is broken into canonical sections that are serialized
//! with little-endian length prefixes. Each section is appended as
//! `len: u32` (little endian) followed by the raw payload bytes. The
//! transcript begins with the static domain tag `RPP-STARK-V1` which is also
//! length-prefixed to make the framing self-describing.
//!
//! The canonical section order is:
//! 1. [`TranscriptSectionKind::DomainTag`] – always the static domain tag.
//! 2. [`TranscriptSectionKind::PublicInputs`] – public witness data.
//! 3. [`TranscriptSectionKind::CommitmentRoots`] – Merkle roots and FRI commitments.
//! 4. [`TranscriptSectionKind::ParameterDigest`] – prover/verifier parameter digest.
//! 5. [`TranscriptSectionKind::BlockContext`] – ambient block metadata.
//!
//! Downstream consumers obtain deterministic challenge streams by finalizing
//! the transcript and deriving [`ChallengeStream`] instances. Implementations
//! are expected to respect the canonical section ordering and serialization to
//! ensure interoperability with third-party provers and verifiers.
//!
//! ## VRF hooks and neutral seed derivation
//!
//! Environments that require publicly verifiable randomness can expose a VRF
//! output as part of the transcript assembly. The VRF bytes should be
//! serialized using the same length-prefixed, little-endian framing before
//! being absorbed into the transcript. Implementations of [`ChallengeDeriver`]
//! may then derive neutral seeds by mixing the deterministic transcript hash
//! with the VRF output, ensuring that challenge derivation remains unbiased
//! while still reproducible for honest parties.

use crate::StarkResult;

/// Domain separation tag for transcript personalization.
pub const TRANSCRIPT_DOMAIN_TAG: &str = "RPP-STARK-V1";

/// Enumerates the canonical sections of the STARK transcript.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TranscriptSectionKind {
    /// Domain tag anchoring the transcript serialization.
    DomainTag,
    /// Public inputs supplied by the prover.
    PublicInputs,
    /// Commitment roots for Merkle/Fri structures.
    CommitmentRoots,
    /// Digest of prover/verifier parameters.
    ParameterDigest,
    /// Ambient block or execution context data.
    BlockContext,
}

impl TranscriptSectionKind {
    /// Returns the zero-based ordinal of the section in the canonical layout.
    pub const fn ordinal(self) -> usize {
        match self {
            Self::DomainTag => 0,
            Self::PublicInputs => 1,
            Self::CommitmentRoots => 2,
            Self::ParameterDigest => 3,
            Self::BlockContext => 4,
        }
    }
}

/// Descriptor that couples a [`TranscriptSectionKind`] with its positional index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SectionDescriptor {
    /// Section identifier.
    pub kind: TranscriptSectionKind,
    /// Zero-based index within the transcript layout.
    pub index: usize,
}

impl SectionDescriptor {
    /// Creates a descriptor for a canonical section, automatically deriving the index.
    pub const fn canonical(kind: TranscriptSectionKind) -> Self {
        Self {
            kind,
            index: kind.ordinal(),
        }
    }
}

/// Canonical layout wrapper for the transcript.
#[derive(Debug, Clone)]
pub struct TranscriptLayout {
    sections: [TranscriptSectionKind; 5],
}

impl TranscriptLayout {
    /// Constructs the default layout using the canonical ordering.
    pub const fn new() -> Self {
        Self {
            sections: [
                TranscriptSectionKind::DomainTag,
                TranscriptSectionKind::PublicInputs,
                TranscriptSectionKind::CommitmentRoots,
                TranscriptSectionKind::ParameterDigest,
                TranscriptSectionKind::BlockContext,
            ],
        }
    }

    /// Returns the ordered sections as an array reference.
    pub const fn sections(&self) -> &[TranscriptSectionKind; 5] {
        &self.sections
    }

    /// Provides the domain tag bytes used during serialization.
    pub const fn domain_tag(&self) -> &'static str {
        TRANSCRIPT_DOMAIN_TAG
    }
}

impl Default for TranscriptLayout {
    fn default() -> Self {
        Self::new()
    }
}

/// Human-readable label identifying a challenge stream draw.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChallengeLabel(pub &'static str);

/// Builder trait that finalizes a transcript into a challenge stream.
pub trait ChallengeDeriver {
    /// Concrete challenge stream implementation returned by the builder.
    type Stream: ChallengeStream;

    /// Finalizes the transcript and produces the challenge stream.
    fn into_stream(self) -> StarkResult<Self::Stream>;
}

/// Streaming interface for deterministic challenge extraction.
pub trait ChallengeStream {
    /// Fills `output` with challenge bytes associated with `label`.
    ///
    /// The produced bytes must be derived solely from the transcript state and
    /// adhere to the canonical little-endian framing rules described at the
    /// module level.
    fn draw_challenge(&mut self, label: ChallengeLabel, output: &mut [u8]) -> StarkResult<()>;
}
