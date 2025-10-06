#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]

//! Core library entry point for the `rpp-stark` proof system.
//!
//! The crate exposes declarative contracts for proof generation, verification
//! and aggregation. All functions are intentionally left without
//! implementations; they simply document the required parameters and the
//! deterministic sequencing dictated by the specification.

pub mod air;
pub mod config;
pub mod fft;
pub mod field;
pub mod fri;
pub mod hash;
pub mod merkle;
pub mod params;
pub mod proof;
pub mod transcript;
pub mod utils;
pub mod vrf;

use config::{ProofSystemConfig, ProverContext, VerifierContext};
use proof::aggregation::{BatchProofRecord, BatchVerificationOutcome};
use proof::public_inputs::PublicInputs;
use proof::types::VerifyError;
use proof::ProofKind;
use utils::serialization::{ProofBytes, WitnessBlob};

pub use air::example::{
    lfsr::PublicInputs as LfsrPublicInputs, LfsrAir as ExampleLfsrAir,
    LfsrTraceBuilder as ExampleLfsrTraceBuilder,
};
pub use air::traits::{
    Air as AirContract, BoundaryBuilder as AirBoundaryBuilder,
    BoundaryConstraint as AirBoundaryConstraint, Constraint as AirConstraint,
    Evaluator as AirEvaluator, PolyExpr as AirPolyExpr, PublicInputsCodec as AirPublicInputsCodec,
    TraceBuilder as AirTraceBuilder,
};
pub use air::types::{
    AirError, BoundaryAt, DegreeBounds, LdeOrder, PublicFieldMeta, PublicFieldType, PublicSpec,
    SerKind, TraceColMeta, TraceData, TraceRole, TraceSchema,
};

/// Result type used throughout the library to surface deterministic errors.
pub type StarkResult<T> = core::result::Result<T, StarkError>;

/// Error enumeration for the STARK engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StarkError {
    /// The requested feature is not yet implemented.
    NotImplemented(&'static str),
    /// The provided input failed validation checks.
    InvalidInput(&'static str),
    /// A generic error surfaced from a subsystem.
    SubsystemFailure(&'static str),
}

/// Verdict returned by verification functions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationVerdict {
    /// Proof accepted after all checks.
    Accept,
    /// Proof rejected with a documented failure class.
    Reject(VerifyError),
}

/// Generates a proof for the specified [`ProofKind`].
///
/// The function follows the canonical lifecycle:
/// 1. Bind the [`ProofSystemConfig`] and [`ProverContext`] against the declared
///    `kind`.
/// 2. Ingest the phase-2 public input layout using [`PublicInputs`].
/// 3. Absorb the witness container and execute the pipeline described in
///    [`proof::prover::PipelineSpec`].
/// 4. Assemble the envelope defined in [`proof::envelope::ProofEnvelopeSpec`]
///    and emit the serialized bytes.
///
/// No implementation logic is provided here; integrators must supply the
/// execution engine while preserving the documented order of operations.
pub fn generate_proof(
    kind: ProofKind,
    public_inputs: &PublicInputs<'_>,
    witness: WitnessBlob<'_>,
    config: &ProofSystemConfig,
    prover_context: &ProverContext,
) -> StarkResult<ProofBytes> {
    let _ = (kind, public_inputs, witness, config, prover_context);
    Err(StarkError::NotImplemented("generate_proof contract only"))
}

/// Verifies a single proof and returns a [`VerificationVerdict`].
///
/// The verification logic MUST execute the steps described in
/// [`proof::verifier::SingleVerifySpec`]. The `config` and `verifier_context`
/// parameters must match the ones used by the prover; otherwise
/// [`proof::types::VerifyError::ParamDigestMismatch`] is expected.
pub fn verify_proof(
    kind: ProofKind,
    public_inputs: &PublicInputs<'_>,
    proof_bytes: &ProofBytes,
    config: &ProofSystemConfig,
    verifier_context: &VerifierContext,
) -> StarkResult<VerificationVerdict> {
    let _ = (kind, public_inputs, proof_bytes, config, verifier_context);
    Err(StarkError::NotImplemented("verify_proof contract only"))
}

/// Verifies a batch of proofs under a shared block context.
///
/// Implementations must follow the aggregation rules documented in
/// [`proof::aggregation::BatchVerificationSpec`]. The returned outcome records
/// whether all proofs were accepted and, in case of failures, which
/// [`proof::types::VerifyError`] triggered the rejection.
pub fn batch_verify(
    block_context: &proof::aggregation::BlockContext,
    proofs: &[BatchProofRecord<'_>],
    config: &ProofSystemConfig,
    verifier_context: &VerifierContext,
) -> StarkResult<BatchVerificationOutcome> {
    let _ = (block_context, proofs, config, verifier_context);
    Err(StarkError::NotImplemented("batch_verify contract only"))
}

/// Convenience helper returning the canonical proof envelope layout.
pub fn proof_envelope_spec() -> &'static str {
    "See proof::envelope for the canonical layout implementation."
}
