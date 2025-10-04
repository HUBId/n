//! Prover pipeline specification.
//!
//! This module documents the deterministic sequence of steps required to
//! construct a proof. Each phase is labelled with the transcript tags and
//! contextual requirements mandated by the specification.

use crate::config::{ChunkingPolicy, ProverContext, ThreadPoolProfile};

/// Summary of the prover pipeline phases.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PipelineSpec;

impl PipelineSpec {
    /// Ordered list of pipeline phases.
    pub const PHASES: &'static [&'static str] = &[
        "trace_build",
        "trace_info_validation",
        "low_degree_extension",
        "commit_merkle_roots",
        "composition_polynomial",
        "ood_evaluations",
        "fri_recursion",
        "proof_assembly",
        "integrity_digest",
        "size_guard",
    ];

    /// Transcript tags inserted between major phases.
    pub const PHASE_TAGS: &'static [&'static str] = &[
        "RPP-PHASE-AIR",
        "RPP-PHASE-COMMIT",
        "RPP-PHASE-FRI",
        "RPP-PHASE-FINAL",
    ];

    /// Description of the α-vector derivation for composition.
    pub const COMPOSITION_ALPHA_RULE: &'static str =
        "Draw α-vector from transcript after commitment phase using PoseidonParamID";

    /// Description of the DEEP composition evaluation order.
    pub const DEEP_ORDER: &'static [&'static str] = &[
        "sample α-vector",
        "evaluate composition polynomial",
        "enforce degree bounds",
    ];
}

/// Documentation of the deterministic resources used by the prover.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProverResourceSpec {
    /// Thread pool profile (no work stealing).
    pub thread_pool: ThreadPoolProfile,
    /// Chunking policy for work distribution.
    pub chunking: ChunkingPolicy,
    /// Maximum proof size enforced before serialization.
    pub max_proof_size_bytes: u32,
}

/// Wrapper struct describing deterministic transcript reseeding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TranscriptReseedingRules;

impl TranscriptReseedingRules {
    /// Ordering of reseed operations.
    pub const ORDER: &'static [&'static str] = &[
        "insert RPP-PHASE-AIR before trace commitments",
        "insert RPP-PHASE-FRI before FRI folding",
        "insert RPP-PHASE-FINAL before integrity digest",
    ];

    /// Seed derivation formula for Phase 3 transcripts.
    pub const SEED_RULE: &'static str = "Seed = BLAKE3(domain_tag || ParamDigest || block_context)";
}

/// Structured description of the prover context usage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProverContextUsage<'ctx> {
    /// Reference to the deterministic context.
    pub context: &'ctx ProverContext,
    /// Resources obtained from the context.
    pub resources: ProverResourceSpec,
}

impl<'ctx> ProverContextUsage<'ctx> {
    /// Constructs a documentation instance tying context and resources.
    pub fn new(context: &'ctx ProverContext) -> Self {
        Self {
            context,
            resources: ProverResourceSpec {
                thread_pool: context.thread_pool,
                chunking: context.chunking,
                max_proof_size_bytes: context.limits.max_proof_size_bytes,
            },
        }
    }
}

/// Deterministic guard verifying proof size limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProofSizeGuardSpec;

impl ProofSizeGuardSpec {
    /// Description of the guard rule.
    pub const RULE: &'static str =
        "abort if serialized envelope length > limits.max_proof_size_bytes";
}
