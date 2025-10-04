//! Verifier specification for deterministic proof validation.
//!
//! This module mirrors the single-proof and batch-proof verification rules.
//! No executable logic is provided; the goal is to document the sequence of
//! checks and the data dependencies required by implementers.

use crate::config::{ResourceLimits, VerifierContext};

use super::errors::VerificationFailure;

/// Specification of the single-proof verification cascade.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SingleVerifySpec;

impl SingleVerifySpec {
    /// Ordered verification steps.
    pub const STEPS: &'static [&'static str] = &[
        "envelope_sanity",
        "param_digest_check",
        "decode_public_inputs",
        "recompute_commitment_digest",
        "reconstruct_transcript",
        "derive_composition_alphas",
        "derive_ood_points",
        "validate_ood_openings",
        "fri_verify",
        "integrity_digest_check",
    ];

    /// Envelope sanity checks performed upfront.
    pub const ENVELOPE_SANITY_CHECKS: &'static [&'static str] = &[
        "ProofVersion == supported",
        "ProofKind matches declared kind",
        "HeaderLength and BodyLength match buffer bounds",
        "total_size <= limits.max_proof_size_bytes",
    ];

    /// Deterministic ordering of FRI verification tasks.
    pub const FRI_RULES: &'static [&'static str] = &[
        "layer_roots checked in canonical order",
        "query positions derived via transcript seed",
        "4-ary paths validated with index byte in [0,3]",
        "reconstruct top layer to match composition value",
    ];
}

/// Specification of the deterministic parallelisation policy for the verifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifierParallelSpec;

impl VerifierParallelSpec {
    /// Description of chunking behaviour for query verification.
    pub const QUERY_CHUNK_RULE: &'static str =
        "split queries into fixed-size batches according to limits.max_queries";

    /// Description of the thread pool policy.
    pub const THREAD_POOL_RULE: &'static str =
        "fixed thread pool (no work stealing), deterministic scheduling";
}

/// Structured description tying verifier context and limits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifierContextUsage<'ctx> {
    /// Reference to the verifier context.
    pub context: &'ctx VerifierContext,
    /// Limits used for guard checks.
    pub limits: ResourceLimits,
}

impl<'ctx> VerifierContextUsage<'ctx> {
    /// Constructs the usage documentation from the context.
    pub fn new(context: &'ctx VerifierContext) -> Self {
        Self {
            context,
            limits: context.limits,
        }
    }
}

/// Helper describing possible failure propagation within the verifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerificationFailureFlow;

impl VerificationFailureFlow {
    /// Mapping between verification steps and failure classes.
    pub const MAP: &'static [(&'static str, VerificationFailure); 11] = &[
        ("envelope_sanity", VerificationFailure::ErrEnvelopeMalformed),
        (
            "param_digest_check",
            VerificationFailure::ErrParamDigestMismatch,
        ),
        (
            "decode_public_inputs",
            VerificationFailure::ErrPublicInputMismatch,
        ),
        (
            "recompute_commitment_digest",
            VerificationFailure::ErrCommitmentDigestMismatch,
        ),
        (
            "reconstruct_transcript",
            VerificationFailure::ErrTranscriptOrder,
        ),
        ("derive_ood_points", VerificationFailure::ErrOODInvalid),
        ("validate_ood_openings", VerificationFailure::ErrOODInvalid),
        ("fri_verify", VerificationFailure::ErrFRILayerRootMismatch),
        (
            "fri_path_validation",
            VerificationFailure::ErrFRIPathInvalid,
        ),
        (
            "fri_query_bounds",
            VerificationFailure::ErrFRIQueryOutOfRange,
        ),
        ("degree_bounds", VerificationFailure::ErrDegreeBoundExceeded),
    ];
}
