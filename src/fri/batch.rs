//! Batch verification API description for FRI proofs.
//! Exposes declarative structures for aggregating multiple proofs under a shared seed.

use super::proof::FriProof;

/// Seed shared across the batch, typically derived from a transcript challenge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchSeed {
    /// Raw bytes sourced from the Fiat-Shamir transcript.
    pub bytes: [u8; 32],
}

impl Default for BatchSeed {
    fn default() -> Self {
        Self { bytes: [0u8; 32] }
    }
}

/// Aggregated digest binding all batched openings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchDigest {
    /// Canonical digest over the ordered batch openings.
    pub bytes: [u8; 32],
}

impl Default for BatchDigest {
    fn default() -> Self {
        Self { bytes: [0u8; 32] }
    }
}

/// Describes a query position inside a batched verification request.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BatchQueryPosition {
    /// Index of the proof inside the batch.
    pub proof_index: usize,
    /// Position queried in the corresponding codeword.
    pub position: usize,
}

/// Declarative container describing the inputs to a batched FRI verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FriBatch {
    /// Proofs participating in the batch.
    pub proofs: Vec<FriProof>,
    /// Seed that is common across all proofs in the batch.
    pub joint_seed: BatchSeed,
    /// Disjoint query positions assigned to each proof.
    pub query_positions: Vec<BatchQueryPosition>,
    /// Digest aggregating all openings in the order imposed by the transcript.
    pub aggregate_digest: BatchDigest,
}

impl Default for FriBatch {
    fn default() -> Self {
        Self {
            proofs: Vec::new(),
            joint_seed: BatchSeed::default(),
            query_positions: Vec::new(),
            aggregate_digest: BatchDigest::default(),
        }
    }
}

/// Trait summarising the read-only API required by batched verification logic.
pub trait FriBatchVerificationApi {
    /// Returns the proofs being verified.
    fn proofs(&self) -> &[FriProof];

    /// Returns the joint seed used to derive batched randomness.
    fn joint_seed(&self) -> &BatchSeed;

    /// Returns the disjoint set of query positions.
    fn query_positions(&self) -> &[BatchQueryPosition];

    /// Returns the digest binding the batched openings.
    fn aggregate_digest(&self) -> &BatchDigest;
}

impl FriBatchVerificationApi for FriBatch {
    fn proofs(&self) -> &[FriProof] {
        &self.proofs
    }

    fn joint_seed(&self) -> &BatchSeed {
        &self.joint_seed
    }

    fn query_positions(&self) -> &[BatchQueryPosition] {
        &self.query_positions
    }

    fn aggregate_digest(&self) -> &BatchDigest {
        &self.aggregate_digest
    }
}
