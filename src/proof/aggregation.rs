//! Batch aggregation rules for combining multiple proofs deterministically.
//!
//! The aggregation layer never executes hashing or verification; it merely
//! documents how seeds, ordering rules and digest binding must behave.  This is
//! sufficient for verifiers to reproduce the same commitments when provided with
//! an implementation that honours the documented contracts.

use crate::proof::public_inputs::{ProofKind, ProofKindTag};

/// Domain prefix used when deriving aggregation seeds.
pub const AGGREGATION_DOMAIN_PREFIX: &str = "RPP-AGG";

/// Ordering rules for the block-scoped aggregation seed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockSeedRules;

impl BlockSeedRules {
    /// Description of the BLAKE3 input layout for the block seed.
    pub const DESCRIPTION: &'static str =
        "block_seed = BLAKE3('RPP-AGG' || block_context || sorted(ProofKindTag))";
    /// Ordering of proof kinds when assembling the seed.
    pub const PROOF_KIND_ORDER: &'static [ProofKindTag; 3] = ProofKindTag::ORDER;
}

/// Per-proof seed derivation rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProofSeedRules;

impl ProofSeedRules {
    /// Description of the per-proof seed formula.
    pub const DESCRIPTION: &'static str =
        "seed_i = BLAKE3(block_seed || u32_le(i) || proof_kind_tag)";
    /// Endianness applied to the proof index.
    pub const INDEX_ENDIANNESS: &'static str = "u32 little-endian";
}

/// Deterministic query selection derived from per-proof seeds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuerySelectionRules;

impl QuerySelectionRules {
    /// Description of the pseudo-random index extraction.
    pub const DESCRIPTION: &'static str =
        "Interpret seed_i as an infinite little-endian byte stream; repeatedly take u32 values modulo evaluation domain length";
    /// Requirement on reproducibility.
    pub const DETERMINISM_NOTE: &'static str =
        "No external randomness; all queries depend solely on transcript-derived seeds";
}

/// Aggregated digest computation rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AggregationDigestRules;

impl AggregationDigestRules {
    /// Sorting rule prior to concatenation.
    pub const SORTING_RULE: &'static str =
        "Sort individual proof digests lexicographically by (ProofKindTag, canonical public input digest)";
    /// Hashing rule applied to the concatenated stream.
    pub const HASH_RULE: &'static str =
        "aggregate_digest = BLAKE3(concat(sorted_individual_digests))";
}

/// Metadata captured for aggregated proofs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AggregationContextFields;

impl AggregationContextFields {
    /// Fields that must be bound when deriving the block seed.
    pub const FIELD_ORDER: &'static [&'static str] = &[
        "block_height:u64",
        "prev_block_hash:32bytes",
        "network_id:u32",
        "aggregator_id:u32",
    ];
}

/// Helper exposing the canonical ordering of proof kinds when aggregating.
pub fn proof_kind_order() -> &'static [ProofKind] {
    &[
        ProofKind::Execution,
        ProofKind::Aggregation,
        ProofKind::Recursion,
    ]
}

/// Error classes signalling aggregation validation failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AggregationValidationError {
    /// The block seed recomputed by the verifier disagreed with the prover-supplied seed.
    BlockSeedMismatch,
    /// Individual proof digests were missing or out of order.
    ProofDigestOrderingMismatch,
    /// Parameter digest mismatch detected during aggregation binding.
    ParameterDigestMismatch,
}
