//! FRI proof representation.
//! Defines serialisable structures used during proof generation and verification.

use crate::field::FieldElement;

/// Represents a single query within a FRI proof.
#[derive(Debug, Clone)]
pub struct FriQuery {
    /// Index of the sampled position.
    pub index: usize,
    /// Evaluations associated with the query.
    pub values: Vec<FieldElement>,
}

/// Full FRI proof containing folded layers and query openings.
#[derive(Debug, Clone)]
pub struct FriProof {
    /// Layers produced during folding.
    pub layers: Vec<Vec<FieldElement>>,
    /// Queries sampled for verification.
    pub queries: Vec<FriQuery>,
}

impl FriProof {
    /// Creates an empty FRI proof.
    pub fn new() -> Self {
        Self {
            layers: Vec::new(),
            queries: Vec::new(),
        }
    }
}
