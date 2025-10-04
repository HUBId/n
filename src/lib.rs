//! Core library entry point for the `rpp-stark` proof system.
//! This module exposes the high-level and low-level APIs for proof generation
//! and verification. All functions are intentionally left without
//! implementation logic and instead serve as documentation of the intended
//! interface surface.

pub mod air;
pub mod config;
pub mod fft;
pub mod field;
pub mod fri;
pub mod hash;
pub mod proof;
pub mod utils;

use config::{ProverContext, StarkConfig, VerifierContext};
use proof::envelope::ProofEnvelope;
use proof::public_inputs::PublicInputs;
use proof::{ProofKind, ProofRequest, ProofResponse};
use utils::serialization::{ProofBytes, WitnessBlob};

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

/// High-level interface for proof generation.
///
/// The function ties together the documented configuration pieces and passes
/// them to [`proof::api::generate_proof`]. The return value mirrors the
/// envelope structure described in the proof module.
pub fn generate_proof(
    kind: ProofKind,
    public_inputs: PublicInputs<'_>,
    witness: WitnessBlob<'_>,
    config: &StarkConfig,
    context: &ProverContext,
) -> StarkResult<ProofResponse> {
    let request = ProofRequest {
        kind,
        public_inputs,
        witness,
        parallelization: context.parallelization,
        context,
    };
    let _ = config;
    proof::api::generate_proof(request)
}

/// High-level interface for proof verification.
///
/// Verifiers pass the expected proof kind, public inputs and envelope plus the
/// agreed upon context. This stub intentionally forwards into the proof API
/// without performing any logic.
pub fn verify_proof(
    kind: ProofKind,
    public_inputs: &PublicInputs<'_>,
    envelope: &ProofEnvelope,
    config: &StarkConfig,
    context: &VerifierContext,
) -> StarkResult<()> {
    let _ = (config, context);
    proof::api::verify_proof(kind, public_inputs, envelope, context)
}

/// Convenience helper for consumers that already assembled a full
/// [`ProofRequest`].
pub fn generate_proof_with_request(request: ProofRequest<'_>) -> StarkResult<ProofResponse> {
    proof::api::generate_proof(request)
}

/// Convenience helper returning the raw proof bytes from a [`ProofResponse`].
pub fn extract_proof_bytes(response: &ProofResponse) -> &ProofBytes {
    &response.bytes
}
