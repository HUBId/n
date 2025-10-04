//! FRI proof descriptors.
//! Captures how layer commitments, query mappings, and openings are arranged.

use crate::fri::folding::LayerCommitment;

/// Mapping from a verifier query to the ordered set of layer openings required
/// to answer it under quartic folding.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct QueryMapping {
    /// Global index of the sampled position in the root codeword.
    pub query_index: usize,
    /// Ordered list of layer indices visited while descending to the residual polynomial.
    pub layer_path: Vec<usize>,
}

/// Describes the sequence in which layer openings are transmitted to the verifier.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OpeningSequence {
    /// Layer indices enumerated in the order they appear on the wire.
    pub layer_indices: Vec<usize>,
}

/// Declarative representation of a FRI proof.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FriProof {
    /// Commitments produced for each folded layer.
    pub commitments: Vec<LayerCommitment>,
    /// Mapping of verifier queries to the layers required for reconstruction.
    pub query_mappings: Vec<QueryMapping>,
    /// Canonical ordering in which openings must be provided.
    pub opening_order: OpeningSequence,
}

/// Trait used by prover and verifier components to reason about proof structure.
pub trait FriProofDescriptor {
    /// Returns the commitment descriptors for each layer.
    fn commitments(&self) -> &[LayerCommitment];

    /// Returns the query mappings describing how verifier samples are routed.
    fn query_mappings(&self) -> &[QueryMapping];

    /// Returns the sequence controlling the order of opening disclosures.
    fn opening_order(&self) -> &OpeningSequence;
}

impl FriProofDescriptor for FriProof {
    fn commitments(&self) -> &[LayerCommitment] {
        &self.commitments
    }

    fn query_mappings(&self) -> &[QueryMapping] {
        &self.query_mappings
    }

    fn opening_order(&self) -> &OpeningSequence {
        &self.opening_order
    }
}
