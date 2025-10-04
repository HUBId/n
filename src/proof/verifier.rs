//! Verifier interface for the `rpp-stark` engine.
//!
//! The verifier consumes proof envelopes and replays the transcript checks in a
//! deterministic manner. This module documents the expected interface and the
//! VRF decoupling points without providing an actual implementation.

use crate::config::VerifierContext;
use crate::proof::envelope::ProofEnvelope;
use crate::proof::public_inputs::PublicInputs;
use crate::utils::serialization::DigestBytes;
use crate::StarkResult;

/// Verifier struct encapsulating deterministic verification logic.
#[derive(Debug, Clone)]
pub struct Verifier<'ctx> {
    /// Context containing configuration parameters.
    pub context: &'ctx VerifierContext,
}

impl<'ctx> Verifier<'ctx> {
    /// Constructs a new verifier.
    pub fn new(context: &'ctx VerifierContext) -> Self {
        Self { context }
    }

    /// Verifies the provided proof envelope against the context.
    ///
    /// Verification is expected to perform the following steps:
    /// - Check the envelope header against the documented [`PublicInputs`]
    ///   layout.
    /// - Recompute transcript digests according to the security goals and
    ///   confirm they match the declared integrity digest.
    /// - Derive VRF challenges locally, using the commitments embedded in the
    ///   proof envelope without round-tripping to the prover.
    pub fn verify(
        &self,
        _public_inputs: &PublicInputs<'_>,
        _envelope: &ProofEnvelope,
    ) -> StarkResult<()> {
        unimplemented!("interface declaration only")
    }

    /// Extracts VRF commitments from the envelope for external auditors.
    pub fn vrf_commitments(_envelope: &ProofEnvelope) -> StarkResult<DigestBytes> {
        unimplemented!("interface declaration only")
    }
}
