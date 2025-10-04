//! Transcript layout tying together domain separation, public inputs and
//! parameter binding.
//!
//! The transcript is byte-oriented and must follow the framing described in
//! the specification. This module enumerates the section order, phase tags and
//! the deterministic derivations for challenges. Only contracts are provided;
//! no hashing logic is implemented here.

use crate::config::{AirSpecId, ParamDigest, PoseidonParamId, TranscriptVersionId};
use crate::hash::blake3::{
    Blake3TranscriptSection, Blake3TranscriptSpec, Blake3TranscriptVersion,
    FiatShamirChallengeRules, TranscriptPhaseTag,
};
use crate::proof::public_inputs::ProofKind;
use crate::StarkResult;

/// Canonical transcript version identifier used by Phase 3.
pub const TRANSCRIPT_VERSION: Blake3TranscriptVersion = Blake3TranscriptVersion::V1;

/// Canonical transcript sections absorbed during proof generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TranscriptSectionLayout;

impl TranscriptSectionLayout {
    /// Ordered list of transcript sections.
    pub const ORDER: &'static [Blake3TranscriptSection; 5] = Blake3TranscriptSpec::SECTIONS;
    /// Description of the framing rule.
    pub const FRAMING: &'static str = Blake3TranscriptSpec::FRAMING_RULE;
}

/// Transcript phase tags inserted between major protocol stages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TranscriptPhaseRules;

impl TranscriptPhaseRules {
    /// Order of phase tags.
    pub const ORDER: &'static [TranscriptPhaseTag; 2] =
        &[TranscriptPhaseTag::Air, TranscriptPhaseTag::Fri];

    /// Description of reseeding behaviour.
    pub const RESEED_RULE: &'static str =
        "Insert RPP-PHASE-AIR before AIR sections and RPP-PHASE-FRI before FRI sections";
}

/// Specification of the transcript seed derivation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TranscriptSeedSpec;

impl TranscriptSeedSpec {
    /// Formula for deriving the initial seed.
    pub const INITIAL_SEED_RULE: &'static str =
        "seed_0 = BLAKE3(domain_prefix || ParamDigest || block_context)";

    /// Formula for deriving seeds per proof kind.
    pub const KIND_SEED_RULE: &'static str = "seed_kind = BLAKE3(seed_0 || ProofKind.code())";
}

/// Challenge derivation specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChallengeDerivationSpec;

impl ChallengeDerivationSpec {
    /// Description of challenge extraction.
    pub const RULE: &'static str = FiatShamirChallengeRules::DESCRIPTION;

    /// Mapping between phases and challenge draws.
    pub const PHASE_CHALLENGES: &'static [&'static str] = &[
        "AIR: α-vector",
        "FRI: query positions",
        "FINAL: integrity salt",
    ];

    /// Poseidon parameter domain separation hint.
    pub const DOMAIN_HINT: &'static str = FiatShamirChallengeRules::SALT_PREFIX;
}

/// Metadata bound into the transcript header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TranscriptHeader {
    /// Transcript version identifier.
    pub version: TranscriptVersionId,
    /// Poseidon parameter identifier used for challenges.
    pub poseidon_param_id: PoseidonParamId,
    /// AIR specification identifier.
    pub air_spec_id: AirSpecId,
    /// Proof kind currently being processed.
    pub proof_kind: ProofKind,
    /// Parameter digest binding global configuration.
    pub param_digest: ParamDigest,
}

/// Block context fields absorbed into the transcript.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TranscriptBlockContext {
    /// Block height (little-endian u64).
    pub block_height: u64,
    /// Previous state root (32 bytes).
    pub previous_state_root: [u8; 32],
    /// Network identifier (little-endian u32).
    pub network_id: u32,
}

/// Label used to denote challenge draws.
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
    /// Fills `output` with challenge bytes associated with `label` using the
    /// deterministic chaining rules captured in [`ChallengeDerivationSpec`].
    fn draw_challenge(&mut self, label: ChallengeLabel, output: &mut [u8]) -> StarkResult<()>;
}

/// Documentation of transcript validation errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TranscriptValidationError {
    /// Sections were emitted in a non-canonical order.
    SectionOrderMismatch,
    /// Encountered an invalid length prefix.
    LengthPrefixInvalid,
    /// Domain tag did not match the negotiated ASCII prefix.
    UnknownDomainTag,
    /// Parameter digest disagreed with the negotiated digest.
    ParameterDigestMismatch,
    /// Encountered an unknown phase tag while restarting sections.
    UnknownPhaseTag,
}
