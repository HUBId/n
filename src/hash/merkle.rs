//! Merkle tree commitments constructed from Blake3 hashes.
//! Provides deterministic construction and proof verification routines.

use super::Blake3Hasher;
use crate::{StarkError, StarkResult};

/// Merkle path element representing a neighbour hash and its orientation.
#[derive(Debug, Clone)]
pub struct MerklePath {
    /// Sibling hash bytes.
    pub sibling: [u8; 32],
    /// Indicates whether the sibling is on the left.
    pub left: bool,
}

/// Deterministic Merkle tree implementation.
#[derive(Debug, Clone)]
pub struct MerkleTree {
    /// Leaf hashes forming the base layer.
    pub leaves: Vec<[u8; 32]>,
}

impl MerkleTree {
    /// Constructs a new Merkle tree from leaf data using the provided hasher factory.
    pub fn new(leaves: Vec<[u8; 32]>) -> StarkResult<Self> {
        if leaves.is_empty() {
            return Err(StarkError::InvalidInput(
                "merkle tree requires at least one leaf",
            ));
        }
        Ok(Self { leaves })
    }

    /// Computes the Merkle root deterministically.
    pub fn root(&self, mut hasher: Blake3Hasher) -> StarkResult<[u8; 32]> {
        let mut current = self.leaves.clone();
        while current.len() > 1 {
            let mut next = Vec::with_capacity((current.len() + 1) / 2);
            for chunk in current.chunks(2) {
                let pair = if chunk.len() == 2 {
                    [chunk[0], chunk[1]]
                } else {
                    [chunk[0], chunk[0]]
                };
                hasher.absorb(&pair[0]);
                hasher.absorb(&pair[1]);
                next.push(hasher.finalize()?);
            }
            current = next;
        }
        Ok(current[0])
    }

    /// Verifies a Merkle path against the root.
    pub fn verify(
        &self,
        mut hasher: Blake3Hasher,
        leaf: [u8; 32],
        path: &[MerklePath],
        expected_root: [u8; 32],
    ) -> StarkResult<bool> {
        let mut hash = leaf;
        for step in path {
            if step.left {
                hasher.absorb(&step.sibling);
                hasher.absorb(&hash);
            } else {
                hasher.absorb(&hash);
                hasher.absorb(&step.sibling);
            }
            hash = hasher.finalize()?;
        }
        Ok(hash == expected_root)
    }
}
