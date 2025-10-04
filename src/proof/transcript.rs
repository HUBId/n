//! Transcript layout tying together domain separation, public inputs and
//! parameter binding.
//!
//! The transcript is byte-oriented and must follow the framing described in
//! [`crate::hash::blake3::Blake3TranscriptSpec`].  This module enumerates the
//! section order, the field ordering inside each section and the block context
//! that gets bound before Fiat–Shamir challenges are derived.

use crate::hash::blake3::{
    Blake3TranscriptSection, Blake3TranscriptSpec, Blake3TranscriptVersion,
    FiatShamirChallengeRules, TranscriptPhaseTag,
};
use crate::hash::merkle::MerkleSchemeDigest;
use crate::hash::poseidon::PoseidonConstantsV1;
use crate::StarkResult;

/// Canonical transcript version identifier.
pub const TRANSCRIPT_VERSION: Blake3TranscriptVersion = Blake3TranscriptVersion::V1;

/// Ordering of sections within the transcript prior to hashing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TranscriptSectionLayout;

impl TranscriptSectionLayout {
    /// Canonical sequence of sections that must be absorbed before deriving `challenge_0`.
    pub const ORDER: &'static [Blake3TranscriptSection; 5] = Blake3TranscriptSpec::SECTIONS;
    /// Framing rule applied to each section (delegated to the BLAKE3 specification).
    pub const FRAMING: &'static str = Blake3TranscriptSpec::FRAMING_RULE;
}

/// Public input section describing the serialization of the witness header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicInputsSectionSpec;

impl PublicInputsSectionSpec {
    /// Every field is preceded by a 32-bit little-endian length.
    pub const LENGTH_PREFIX_RULE: &'static str =
        "prefix each entry with u32 (LE) length before raw bytes";
    /// Canonical ordering of public input groups.
    pub const FIELD_GROUPS: &'static [&'static str] = &["proof_kind_header", "public_input_body"];
    /// Endianness applied to integers inside the public input body.
    pub const ENDIANNESS: &'static str = "little-endian for counters and field bytes";
}

/// Commitment root section ordering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommitmentRootsSectionSpec;

impl CommitmentRootsSectionSpec {
    /// Canonical ordering for Merkle and FRI roots.
    pub const ROOT_ORDER: &'static [&'static str] = &[
        "main_trace_root",
        "composition_root",
        "fri_layer_0_root",
        "fri_layer_1_root",
        "fri_layer_last_root",
    ];
    /// Hashing rule for internal nodes as documented in [`crate::hash::merkle`].
    pub const HASH_RULE: &'static str = "BLAKE3(child0 || child1 || child2 || child3)";
}

/// Parameter digest specification binding global configuration knobs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParameterDigestSpec;

impl ParameterDigestSpec {
    /// Canonical ordering of fields absorbed into the digest.
    pub const FIELD_ORDER: &'static [&'static str] = &[
        "field_id",
        "poseidon_param_id",
        "lde_factor",
        "fri_plan",
        "query_budget",
        "merkle_scheme_id",
        "transcript_version_id",
    ];
    /// Poseidon parameter digest folded into the parameter binding.
    pub const POSEIDON_PARAM_DIGEST: &'static [u8; 32] = &PoseidonConstantsV1::PARAM_DIGEST;
    /// Merkle scheme identifier consumed by the digest.
    pub const MERKLE_SCHEME_ID: MerkleSchemeDigest = MerkleSchemeDigest::BLAKE3_QUATERNARY_V1;
    /// FRI plan description (fold factor and depth).
    pub const FRI_PLAN_DESCRIPTION: &'static str =
        "fold=4, depth>=log2(lde_factor), aligns with >=64 queries";
}

/// Block context fields sealed inside the transcript.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockContextSectionSpec;

impl BlockContextSectionSpec {
    /// Ordering of the context fields.
    pub const FIELD_ORDER: &'static [&'static str] = &[
        "block_height:u64",
        "previous_state_root:32bytes",
        "network_id:u32",
        "proof_version:u8",
    ];
}

/// Transcript phase management mirroring [`TranscriptPhaseTag`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TranscriptPhaseSpec;

impl TranscriptPhaseSpec {
    /// AIR phase tag inserted before the first section batch.
    pub const AIR_TAG: TranscriptPhaseTag = TranscriptPhaseTag::Air;
    /// FRI phase tag inserted before restarting with section order.
    pub const FRI_TAG: TranscriptPhaseTag = TranscriptPhaseTag::Fri;
    /// Description of the restart behaviour.
    pub const DESCRIPTION: &'static str =
        "Insert phase tag bytes, reset section counter, reapply DOMAIN_TAG..BLOCK_CONTEXT";
}

/// Fiat–Shamir derivation helper exposing the chained challenge rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TranscriptChallengeSpec;

impl TranscriptChallengeSpec {
    /// Description of the recurrence used for challenge generation.
    pub const RULE: &'static str = FiatShamirChallengeRules::DESCRIPTION;
    /// Salt prefix inserted after the first challenge draw.
    pub const SALT_PREFIX: &'static str = FiatShamirChallengeRules::SALT_PREFIX;
}

/// Proof version counter starting at 1.
pub const PROOF_VERSION_INITIAL: u8 = 1;

/// Guidance on proof version vs. parameter digest evolution.
pub const VERSIONING_RULES: &str =
    "Increase ProofVersion for non-backwards compatible layout changes; update ParamDigest for parameter tweaks";

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
    /// deterministic chaining rules captured in [`TranscriptChallengeSpec`].
    fn draw_challenge(&mut self, label: ChallengeLabel, output: &mut [u8]) -> StarkResult<()>;
}

/// Error terms produced while validating transcript assembly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TranscriptValidationError {
    /// Sections were emitted in a non-canonical order.
    SectionOrderMismatch,
    /// Encountered an invalid length prefix.
    LengthPrefixInvalid,
    /// Domain tag did not match the negotiated ASCII prefix.
    UnknownDomainTag,
    /// Parameter digest disagreed with [`ParameterDigestSpec`].
    ParameterDigestMismatch,
    /// Encountered an unknown phase tag while restarting sections.
    UnknownPhaseTag,
}
