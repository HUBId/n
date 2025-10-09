use crate::hash::deterministic::Hasher;
use crate::hash::merkle::{LEAF_DOMAIN_TAG, NODE_DOMAIN_TAG};
use crate::params::HashFamily;
use std::convert::TryInto;

use super::traits::MerkleHasher;

/// Deterministic pseudo BLAKE-based Merkle hasher used for testing.
pub struct DeterministicMerkleHasher;

impl MerkleHasher for DeterministicMerkleHasher {
    type Digest = [u8; 32];

    fn hash_leaves_with_tag(
        leaf_domain_tag: u8,
        domain_sep: u64,
        ordered_leaf_bytes: &[u8],
    ) -> Self::Digest {
        hash_with_tag(leaf_domain_tag, domain_sep, ordered_leaf_bytes)
    }

    fn hash_nodes_with_tag(
        node_domain_tag: u8,
        domain_sep: u64,
        ordered_children: &[Self::Digest],
    ) -> Self::Digest {
        let mut hasher = Hasher::new();
        hasher.update(&[node_domain_tag]);
        hasher.update(&domain_sep.to_le_bytes());
        for digest in ordered_children {
            hasher.update(digest);
        }
        hasher.finalize().into_bytes()
    }

    fn digest_size() -> usize {
        match Self::hash_family() {
            HashFamily::Blake2s => crate::hash::merkle::DIGEST_SIZE,
            _ => unreachable!("deterministic merkle hasher only supports Blake2s"),
        }
    }

    fn from_bytes(bytes: &[u8]) -> Option<Self::Digest> {
        bytes.try_into().ok()
    }

    fn hash_family() -> HashFamily {
        HashFamily::Blake2s
    }
}

fn hash_with_tag(tag: u8, domain_sep: u64, payload: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(&[tag]);
    hasher.update(&domain_sep.to_le_bytes());
    hasher.update(payload);
    hasher.finalize().into_bytes()
}

impl DeterministicMerkleHasher {
    /// Returns the canonical leaf domain separation tag used for Blake2s Merkle commitments.
    pub const fn leaf_domain_tag() -> u8 {
        LEAF_DOMAIN_TAG
    }

    /// Returns the canonical node domain separation tag used for Blake2s Merkle commitments.
    pub const fn node_domain_tag() -> u8 {
        NODE_DOMAIN_TAG
    }
}
