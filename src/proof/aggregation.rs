//! Batch aggregation rules for combining multiple proofs deterministically.
//!
//! All items in this module are declarative contracts capturing ordering,
//! hashing domains and failure signalling for the batch verification API.

use crate::proof::public_inputs::ProofKind;
use crate::utils::serialization::ProofBytes;

use super::errors::VerificationFailure;
use super::public_inputs::PublicInputs;

/// Domain prefix used when deriving aggregation seeds.
pub const AGGREGATION_DOMAIN_PREFIX: &str = "RPP-AGG";

/// Block context bound into the aggregation transcript.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockContext {
    /// Canonical rollup height.
    pub block_height: u64,
    /// Previous state root.
    pub previous_state_root: [u8; 32],
    /// Network identifier used by the rollup chain.
    pub network_id: u32,
}

/// Record describing a proof participating in a batch verification call.
#[derive(Debug, Clone)]
pub struct BatchProofRecord<'a> {
    /// Declared proof kind using the canonical RPP encoding.
    pub kind: ProofKind,
    /// Public inputs (Phase-2 layout) supplied by the caller.
    pub public_inputs: &'a PublicInputs<'a>,
    /// Serialized proof bytes (envelope) for the proof.
    pub proof_bytes: &'a ProofBytes,
}

/// Outcome returned by batch verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BatchVerificationOutcome {
    /// All proofs were accepted.
    Accept,
    /// Verification aborted because a proof failed.
    Reject {
        /// Index of the failing proof in the input slice.
        failing_proof_index: usize,
        /// Documented failure class.
        error: VerificationFailure,
    },
}

/// Batch verification specification capturing deterministic orchestration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BatchVerificationSpec;

impl BatchVerificationSpec {
    /// Steps performed by batch verification.
    pub const STEPS: &'static [&'static str] = &[
        "derive_block_seed",
        "precheck_envelopes_and_parameters",
        "derive_per_proof_seeds",
        "schedule_queries",
        "execute_fri_batch",
        "aggregate_digests",
    ];

    /// Description of the block seed derivation formula.
    pub const BLOCK_SEED_RULE: &'static str =
        "block_seed = BLAKE3('RPP-AGG' || block_context || sorted ProofKind codes)";

    /// Description of the per proof seed derivation formula.
    pub const PER_PROOF_SEED_RULE: &'static str =
        "seed_i = BLAKE3(block_seed || u32_le(i) || proof_kind_code)";

    /// Description of the query scheduling rule.
    pub const QUERY_SELECTION_RULE: &'static str =
        "interpret seed_i as little-endian stream; map to domain via modulo";

    /// Description of the aggregation digest rule.
    pub const AGGREGATION_DIGEST_RULE: &'static str =
        "BLAKE3(concat(sorted individual digests by (ProofKind, PI digest)))";
}
