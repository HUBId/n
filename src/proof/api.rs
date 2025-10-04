//! Top-level proof lifecycle contracts.
//!
//! The functions exposed by [`crate::generate_proof`],
//! [`crate::verify_proof`] and [`crate::batch_verify`] are documented here in
//! terms of inputs, outputs and deterministic sequencing. Only the shapes of
//! the API are provided—no runtime behaviour is implemented.

use crate::config::{ProofSystemConfig, ProverContext, VerifierContext};
use crate::utils::serialization::{ProofBytes, WitnessBlob};

use super::aggregation::{BatchProofRecord, BatchVerificationOutcome, BlockContext};
use super::errors::VerificationFailure;
use super::public_inputs::{ProofKind, PublicInputs};

/// Documentation container describing the full lifecycle of a proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProofLifecycleSpec;

impl ProofLifecycleSpec {
    /// Canonical order of the lifecycle steps.
    pub const STEPS: &'static [&'static str] = &[
        "ingest_public_inputs",
        "prepare_contexts",
        "execute_prover_pipeline",
        "assemble_envelope",
        "single_verify",
        "optional_batch_verify",
    ];
}

/// Signature contract for [`crate::generate_proof`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GenerateProofContract;

impl GenerateProofContract {
    /// Human-readable documentation of the inputs.
    pub const INPUTS: &'static [&'static str] = &[
        "kind: ProofKind (canonical RPP u8 coding)",
        "public_inputs: Phase-2 header/body container",
        "witness: application specific opaque bytes",
        "config: ProofSystemConfig (Phase 2/3/4/5 profile)",
        "prover_context: deterministic pipeline descriptor",
    ];

    /// Output produced by the function.
    pub const OUTPUT: &'static str = "proof_bytes: serialized envelope as ProofBytes";

    /// Determinism requirements for the function.
    pub const DETERMINISM: &'static [&'static str] = &[
        "no OS time, randomness derived solely from transcript",
        "thread scheduling fixed via ProverContext::thread_pool",
        "witness consumed exactly once in documented order",
    ];
}

/// Signature contract for [`crate::verify_proof`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifyProofContract;

impl VerifyProofContract {
    /// Human-readable documentation of the inputs.
    pub const INPUTS: &'static [&'static str] = &[
        "kind: ProofKind declared by caller",
        "public_inputs: authoritative Phase-2 layout",
        "proof_bytes: serialized envelope",
        "config: ProofSystemConfig",
        "verifier_context: deterministic verifier descriptor",
    ];

    /// Output produced by the function.
    pub const OUTPUT: &'static str =
        "verdict: Accept | Reject(VerificationFailure) wrapped in VerificationVerdict";

    /// Determinism requirements for the function.
    pub const DETERMINISM: &'static [&'static str] = &[
        "derive all randomness from TranscriptVersionId",
        "validate limits before hashing or polynomial checks",
        "metrics collection must avoid time-based counters",
    ];
}

/// Signature contract for [`crate::batch_verify`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BatchVerifyContract;

impl BatchVerifyContract {
    /// Human-readable documentation of the inputs.
    pub const INPUTS: &'static [&'static str] = &[
        "block_context: aggregation binding (height, prev_state_root, network_id)",
        "proofs: slice of BatchProofRecord(kind, public_inputs, proof_bytes)",
        "config: ProofSystemConfig",
        "verifier_context: deterministic verifier descriptor",
    ];

    /// Output produced by the function.
    pub const OUTPUT: &'static str = "BatchVerificationOutcome: Accept | Reject{index, error}";

    /// Determinism requirements for the function.
    pub const DETERMINISM: &'static [&'static str] = &[
        "block seed = BLAKE3('RPP-AGG' || block_context || sorted ProofKind codes)",
        "per-proof seed = BLAKE3(block_seed || u32_le(i) || ProofKind code)",
        "query positions derived strictly from per-proof seed",
    ];
}

/// Helper describing how witness containers are structured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WitnessContainerSpec;

impl WitnessContainerSpec {
    /// Documentation of the canonical little-endian framing.
    pub const LAYOUT: &'static [&'static str] = &[
        "u32_le witness_length",
        "witness_bytes (opaque to documentation layer)",
    ];
}

/// Forward declaration of the generate_proof function (no implementation).
pub fn generate_proof(
    _kind: ProofKind,
    _public_inputs: &PublicInputs<'_>,
    _witness: WitnessBlob<'_>,
    _config: &ProofSystemConfig,
    _prover_context: &ProverContext,
) -> Result<ProofBytes, VerificationFailure> {
    unimplemented!("interface declaration only")
}

/// Forward declaration of the verify_proof function (no implementation).
pub fn verify_proof(
    _kind: ProofKind,
    _public_inputs: &PublicInputs<'_>,
    _proof_bytes: &ProofBytes,
    _config: &ProofSystemConfig,
    _verifier_context: &VerifierContext,
) -> Result<(), VerificationFailure> {
    unimplemented!("interface declaration only")
}

/// Forward declaration of the batch_verify function (no implementation).
pub fn batch_verify(
    _block_context: &BlockContext,
    _proofs: &[BatchProofRecord<'_>],
    _config: &ProofSystemConfig,
    _verifier_context: &VerifierContext,
) -> Result<BatchVerificationOutcome, VerificationFailure> {
    unimplemented!("interface declaration only")
}
