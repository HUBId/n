//! High-level API glue for the proof subsystem.
//!
//! This module collects the forward declarations that the public library
//! surface requires. All items are intentionally free of implementation so
//! that downstream integrators can plug in their own execution engines while
//! relying on a stable documentation layer.

use crate::config::{ParallelizationRules, ProverContext, VerifierContext};
use crate::proof::envelope::ProofEnvelope;
use crate::proof::public_inputs::{ProofKind, PublicInputs};
use crate::utils::serialization::{ProofBytes, WitnessBlob};
use crate::StarkResult;

/// Request object passed to [`generate_proof`].
///
/// Each field is described explicitly to make room for additional
/// instrumentation such as determinism counters or replay guards without
/// changing the high-level API signature.
#[derive(Debug, Clone)]
pub struct ProofRequest<'a> {
    /// Declares the type of proof that should be produced and which
    /// header layout applies.
    pub kind: ProofKind,
    /// The public inputs for the proof including the header section.
    pub public_inputs: PublicInputs<'a>,
    /// Arbitrary witness bytes supplied by the caller. The blob is opaque to
    /// the documentation layer and is only constrained by the configuration
    /// object carried in [`ProverContext`].
    pub witness: WitnessBlob<'a>,
    /// Parallelisation parameters negotiated between caller and runtime.
    pub parallelization: ParallelizationRules,
    /// Optional protocol specific configuration. This is a passive reference
    /// into the user provided context to avoid unnecessary cloning.
    pub context: &'a ProverContext,
}

/// Response object produced by [`generate_proof`].
#[derive(Debug, Clone)]
pub struct ProofResponse {
    /// Full envelope containing versioned metadata and the proof body.
    pub envelope: ProofEnvelope,
    /// Raw proof bytes that may be streamed or cached.
    pub bytes: ProofBytes,
}

/// High-level proof generation entry point.
///
/// The documentation specifies the intended call flow:
/// - Choose a [`ProofKind`].
/// - Assemble [`PublicInputs`] matching the declared header layout.
/// - Provide witness data in a [`WitnessBlob`].
/// - Reuse the configured [`ProverContext`] alongside negotiated
///   [`ParallelizationRules`].
///
/// The implementation is intentionally left unspecified.
pub fn generate_proof(_request: ProofRequest<'_>) -> StarkResult<ProofResponse> {
    unimplemented!("interface declaration only")
}

/// High-level proof verification entry point.
///
/// Consumers supply the [`ProofKind`] they expect, the authoritative public
/// inputs and the envelope returned by [`generate_proof`]. The verifier
/// context is kept separate to highlight that VRF sampling and transcript
/// binding can be evolved independently from the prover configuration.
pub fn verify_proof(
    _kind: ProofKind,
    _public_inputs: &PublicInputs<'_>,
    _envelope: &ProofEnvelope,
    _context: &VerifierContext,
) -> StarkResult<()> {
    unimplemented!("interface declaration only")
}
