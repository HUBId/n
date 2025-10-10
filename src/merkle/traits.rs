use crate::hash::merkle::{LEAF_DOMAIN_TAG, NODE_DOMAIN_TAG};
use crate::params::{HashFamily, StarkParams};

use super::types::{Leaf, MerkleError};

/// Hash abstraction used by the Merkle commitment layer.
pub trait MerkleHasher {
    type Digest: AsRef<[u8]>
        + Eq
        + Copy
        + Clone
        + Send
        + Sync
        + serde::Serialize
        + serde::de::DeserializeOwned;

    fn hash_leaves(domain_sep: u64, ordered_leaf_bytes: &[u8]) -> Self::Digest {
        Self::hash_leaves_with_tag(LEAF_DOMAIN_TAG, domain_sep, ordered_leaf_bytes)
    }

    fn hash_nodes(domain_sep: u64, ordered_children: &[Self::Digest]) -> Self::Digest {
        Self::hash_nodes_with_tag(NODE_DOMAIN_TAG, domain_sep, ordered_children)
    }

    fn hash_leaves_with_tag(
        leaf_domain_tag: u8,
        domain_sep: u64,
        ordered_leaf_bytes: &[u8],
    ) -> Self::Digest;

    fn hash_nodes_with_tag(
        node_domain_tag: u8,
        domain_sep: u64,
        ordered_children: &[Self::Digest],
    ) -> Self::Digest;

    fn digest_size() -> usize;

    fn from_bytes(bytes: &[u8]) -> Option<Self::Digest>;

    fn hash_family() -> HashFamily;
}

/// Commitment front-end exposed to the rest of the proving system.
pub trait MerkleCommit {
    type Hasher: MerkleHasher;

    fn commit<I>(
        params: &StarkParams,
        leaves: I,
    ) -> Result<(super::types::Digest, super::tree::CommitAux), MerkleError>
    where
        I: ExactSizeIterator<Item = Leaf>;

    fn open(
        params: &StarkParams,
        aux: &super::tree::CommitAux,
        indices: &[u32],
    ) -> Result<super::proof::MerkleProof, MerkleError>;

    fn verify(
        params: &StarkParams,
        root: &super::types::Digest,
        proof: &super::proof::MerkleProof,
        leaves: &[Leaf],
    ) -> Result<(), MerkleError>;
}
