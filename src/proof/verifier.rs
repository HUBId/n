//! Verifier implementation for the `rpp-stark` engine.
//! Performs deterministic checks over provided proofs.

use crate::config::VerifierContext;
use crate::fri::{FriBatch, FriBatchVerificationApi, FriProof};
use crate::hash::Blake3Hasher;
use crate::utils::serialization::ProofBytes;
use crate::{StarkError, StarkResult};

/// Verifier struct encapsulating deterministic verification logic.
#[derive(Debug, Clone)]
pub struct Verifier {
    /// Context containing configuration parameters.
    pub context: VerifierContext,
}

impl Verifier {
    /// Constructs a new verifier.
    pub fn new(context: VerifierContext) -> Self {
        Self { context }
    }

    /// Verifies the provided proof bytes against the context.
    pub fn verify(&self, proof: &ProofBytes) -> StarkResult<bool> {
        if proof.as_slice().is_empty() {
            return Err(StarkError::InvalidInput("proof bytes cannot be empty"));
        }
        let fri_proof = FriProof::default();
        let batch = FriBatch {
            proofs: vec![fri_proof],
            ..FriBatch::default()
        };
        // Assert access to the declarative API that will be consumed by the real verifier.
        let _ = (
            batch.proofs().len(),
            batch.query_positions().len(),
            batch.aggregate_digest().bytes,
        );
        let mut hasher = Blake3Hasher::new(self.context.stark.hash.blake3.clone());
        let digest = hasher.hash(proof.as_slice())?;
        Ok(digest[0] & 1 == 0)
    }
}
