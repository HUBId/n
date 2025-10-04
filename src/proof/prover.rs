//! Prover interface for the `rpp-stark` engine.
//!
//! This module captures the declarative interface exposed by the prover. The
//! implementation is intentionally omitted; instead we document how the prover
//! interacts with configuration objects, witnesses and VRF decoupling points.

use crate::config::ProverContext;
use crate::proof::api::{ProofRequest, ProofResponse};
use crate::proof::envelope::ProofEnvelope;
use crate::utils::serialization::ProofBytes;
use crate::StarkResult;

/// Prover struct encapsulating the deterministic pipeline.
#[derive(Debug, Clone)]
pub struct Prover<'ctx> {
    /// Context containing configuration parameters shared with the verifier.
    pub context: &'ctx ProverContext,
}

impl<'ctx> Prover<'ctx> {
    /// Creates a new prover with the provided context.
    pub fn new(context: &'ctx ProverContext) -> Self {
        Self { context }
    }

    /// Executes proof generation over the supplied proof request.
    ///
    /// The request carries a [`ProofKind`](crate::proof::public_inputs::ProofKind),
    /// the public inputs for the specific proof type and an opaque witness blob.
    /// The prover is responsible for:
    /// - Validating that the request kind matches the negotiated profile.
    /// - Feeding the witness into the execution trace generator.
    /// - Producing a deterministic transcript that yields [`ProofBytes`].
    ///
    /// VRF decoupling: the prover must not sample randomness from the verifier.
    /// Instead, it publishes the commitments required for a verifiable random
    /// function (VRF) handshake inside the returned [`ProofEnvelope`]. The
    /// verifier will recompute the VRF challenge independently.
    pub fn generate(&self, _request: ProofRequest<'_>) -> StarkResult<ProofResponse> {
        unimplemented!("interface declaration only")
    }

    /// Produces raw proof bytes without the surrounding envelope.
    ///
    /// This is useful for benchmarks or transports that require streaming the
    /// proof body directly. The caller is responsible for adding envelope
    /// metadata before passing the data to verifiers.
    pub fn export_bytes(&self, _request: ProofRequest<'_>) -> StarkResult<ProofBytes> {
        unimplemented!("interface declaration only")
    }

    /// Helper returning the VRF binding commitments contained in a response.
    pub fn extract_vrf_commitments(_response: &ProofResponse) -> StarkResult<&ProofEnvelope> {
        unimplemented!("interface declaration only")
    }
}
