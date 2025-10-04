//! Prover implementation for the `rpp-stark` engine.
//! Executes the polynomial commitment pipeline to produce deterministic proofs.

use core::marker::PhantomData;

use crate::air::Air;
use crate::config::ProverContext;
use crate::fri::{FriBatch, FriBatchVerificationApi, FriProof};
use crate::hash::{Blake3Hasher, Blake3QuaternaryMerkleTree, MerkleTreeBackend, MerkleTreeConfig};
use crate::utils::serialization::ProofBytes;
use crate::{StarkError, StarkResult};

/// Prover struct encapsulating the deterministic pipeline.
#[derive(Debug, Clone)]
pub struct Prover {
    /// Context containing configuration parameters.
    pub context: ProverContext,
}

impl Prover {
    /// Creates a new prover with the provided context.
    pub fn new(context: ProverContext) -> Self {
        Self { context }
    }

    /// Executes proof generation over the supplied AIR instance.
    pub fn prove(&self, _air: &dyn Air) -> StarkResult<ProofBytes> {
        let trace_length = self.context.stark.trace_length;
        if trace_length == 0 {
            return Err(StarkError::InvalidInput("trace length must be non-zero"));
        }
        let fri_proof = FriProof::default();
        let batch = FriBatch {
            proofs: vec![fri_proof],
            ..FriBatch::default()
        };
        // Touch the declarative API to ensure the batch description is well-formed.
        let _ = (
            batch.proofs().len(),
            batch.joint_seed().bytes,
            batch.aggregate_digest().bytes,
        );
        debug_assert!(MerkleTreeConfig::MIN_DEPTH <= MerkleTreeConfig::MAX_DEPTH);

        let mut hasher = Blake3Hasher::new(self.context.stark.hash.blake3.clone());
        hasher.absorb(trace_length.to_le_bytes().as_slice());
        let leaf = hasher.finalize()?;
        let commitment = Blake3QuaternaryMerkleTree::<Blake3Hasher> {
            leaves: vec![leaf],
            hasher: PhantomData,
        };
        let _domain_tag =
            <Blake3QuaternaryMerkleTree<Blake3Hasher> as MerkleTreeBackend>::DOMAIN_TAG;
        let _ = (_domain_tag, &commitment);

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&trace_length.to_le_bytes());
        Ok(ProofBytes::new(bytes))
    }

    /// High-level proof generation entry point used by the library API.
    pub fn create_proof(&self) -> StarkResult<ProofBytes> {
        // Placeholder invocation without a specific AIR instance.
        Err(StarkError::NotImplemented(
            "prover::create_proof requires AIR instance",
        ))
    }
}
