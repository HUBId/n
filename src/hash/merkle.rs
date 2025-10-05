//! BLAKE3-based 4-ary Merkle tree implementation used by the proving system.
//!
//! The tree adheres to the specification circulated with the repository:
//!
//! * Inner nodes hash the concatenation of their four children in order.
//! * Leaves are hashed as `BLAKE3(u32_le(len) || payload)`.
//! * Missing children on the right-hand side are padded with a fixed
//!   `EMPTY` digest derived from the string `"RPP-MERKLE-EMPTY\0"`.
//! * Authentication paths serialise an index byte followed by the three
//!   sibling digests ordered by their position (0..3) within the parent.
//!
//! The module provides helpers to build Merkle trees, derive authentication
//! paths and recompute the root from a path.  Errors are surfaced when a
//! caller attempts to verify malformed paths (e.g. mismatched padding or
//! tampered length prefixes).

use crate::hash::{hash, Hasher};

/// Number of children per internal node.
const ARITY: usize = 4;

/// Size of a digest emitted by the tree (BLAKE3 output size).
pub const DIGEST_SIZE: usize = 32;

/// Canonical digest for an empty child.
pub const EMPTY_DIGEST: [u8; DIGEST_SIZE] = [
    0x10, 0x68, 0x98, 0xac, 0xc4, 0xcc, 0xf4, 0xd1, 0x1d, 0x07, 0x4a, 0x00, 0x09, 0xbc, 0x4a, 0x8e,
    0x56, 0x29, 0x03, 0x5a, 0xf3, 0x05, 0x46, 0xdc, 0xdb, 0xff, 0xba, 0x19, 0x77, 0xa7, 0x59, 0x61,
];

/// Digest binding the documented Merkle layout for parameter commitments.
pub const MERKLE_SCHEME_ID: [u8; DIGEST_SIZE] = [
    0xe3, 0x5d, 0x68, 0x51, 0x56, 0xe8, 0xb8, 0x9f, 0x9d, 0x2e, 0x9a, 0xe1, 0xfc, 0x7b, 0x02, 0xa0,
    0x29, 0x2e, 0x38, 0x4a, 0xf9, 0x23, 0x85, 0xae, 0xc3, 0x2b, 0xbb, 0xc9, 0x1a, 0x96, 0x5b, 0xe0,
];

/// Index of a child within a 4-ary node (stored as little-endian byte in proofs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MerkleIndex(pub u8);

impl MerkleIndex {
    /// Maximum allowed index for the 4-ary fan-out.
    pub const MAX: u8 = 3;
}

/// Path element capturing siblings and the caller position.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerklePathElement {
    /// Position of the caller node within the parent (`0..=3`).
    pub index: MerkleIndex,
    /// Sibling hashes ordered from left (0) to right (3).
    pub siblings: [[u8; DIGEST_SIZE]; ARITY - 1],
}

/// Errors reported while verifying or constructing Merkle proofs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MerkleError {
    /// The u32 little-endian length prefix disagrees with the payload size.
    ErrMerkleLeafLength,
    /// Missing leaves on the right-hand side were not padded with `EMPTY`.
    ErrMerkleEmptyPadding,
    /// Encountered an invalid index byte or inconsistent path structure.
    ErrPathIndexByte,
}

/// Convenience wrapper for a 4-ary BLAKE3 Merkle tree.
#[derive(Debug, Clone)]
pub struct Blake3MerkleTree {
    levels: Vec<Vec<[u8; DIGEST_SIZE]>>,
    leaf_count: usize,
}

impl Blake3MerkleTree {
    /// Builds a Merkle tree from canonical leaf encodings.
    ///
    /// Each leaf must follow the framing `len: u32 (little-endian) || payload`.
    pub fn from_leaves<I, B>(leaves: I) -> Result<Self, MerkleError>
    where
        I: IntoIterator<Item = B>,
        B: AsRef<[u8]>,
    {
        let mut hashed = Vec::new();
        let mut leaf_count = 0usize;
        for leaf in leaves {
            let leaf_bytes = leaf.as_ref();
            hashed.push(hash_leaf(leaf_bytes)?);
            leaf_count += 1;
        }

        if leaf_count == 0 {
            return Ok(Self {
                levels: vec![vec![EMPTY_DIGEST]],
                leaf_count: 0,
            });
        }

        let mut levels = Vec::new();
        levels.push(hashed.clone());
        let mut current = hashed;

        while current.len() > 1 {
            let mut next = Vec::with_capacity((current.len() + ARITY - 1) / ARITY);
            for chunk in current.chunks(ARITY) {
                let mut children = [[0u8; DIGEST_SIZE]; ARITY];
                for (position, child) in children.iter_mut().enumerate() {
                    *child = if position < chunk.len() {
                        chunk[position]
                    } else {
                        EMPTY_DIGEST
                    };
                }
                next.push(hash_internal(&children));
            }
            levels.push(next.clone());
            current = next;
        }

        Ok(Self { levels, leaf_count })
    }

    /// Returns the Merkle root digest.
    pub fn root(&self) -> [u8; DIGEST_SIZE] {
        self.levels
            .last()
            .and_then(|level| level.first().copied())
            .unwrap_or(EMPTY_DIGEST)
    }

    /// Number of leaves provided when building the tree (after implicit padding).
    pub fn leaf_count(&self) -> usize {
        self.leaf_count
    }

    /// Generates an authentication path for the leaf at `index`.
    pub fn open(&self, index: usize) -> Result<Vec<MerklePathElement>, MerkleError> {
        if index >= self.leaf_count {
            return Err(MerkleError::ErrPathIndexByte);
        }

        let mut path = Vec::with_capacity(self.levels.len().saturating_sub(1));
        let mut current_index = index;

        for level in 0..self.levels.len().saturating_sub(1) {
            let nodes = &self.levels[level];
            let parent_index = current_index / ARITY;
            let position = current_index % ARITY;
            let chunk_base = parent_index * ARITY;
            let chunk_len = nodes.len().saturating_sub(chunk_base).min(ARITY);

            let mut siblings = [[0u8; DIGEST_SIZE]; ARITY - 1];
            let mut s_idx = 0;
            for offset in 0..ARITY {
                if offset == position {
                    continue;
                }
                siblings[s_idx] = if offset < chunk_len {
                    nodes[chunk_base + offset]
                } else {
                    EMPTY_DIGEST
                };
                s_idx += 1;
            }

            path.push(MerklePathElement {
                index: MerkleIndex(position as u8),
                siblings,
            });

            current_index /= ARITY;
        }

        Ok(path)
    }
}

/// Encodes raw payload bytes into the canonical leaf representation.
pub fn encode_leaf(payload: &[u8]) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(4 + payload.len());
    encoded.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    encoded.extend_from_slice(payload);
    encoded
}

/// Hashes a leaf using the canonical framing rules while checking the length prefix.
pub fn hash_leaf(encoded_leaf: &[u8]) -> Result<[u8; DIGEST_SIZE], MerkleError> {
    if encoded_leaf.len() < 4 {
        return Err(MerkleError::ErrMerkleLeafLength);
    }

    let mut len_bytes = [0u8; 4];
    len_bytes.copy_from_slice(&encoded_leaf[..4]);
    let declared_len = u32::from_le_bytes(len_bytes) as usize;
    let payload = &encoded_leaf[4..];

    if declared_len != payload.len() {
        return Err(MerkleError::ErrMerkleLeafLength);
    }

    Ok(hash(encoded_leaf).into())
}

/// Hashes four child digests into their parent digest.
pub fn hash_internal(children: &[[u8; DIGEST_SIZE]; ARITY]) -> [u8; DIGEST_SIZE] {
    let mut hasher = Hasher::new();
    for child in children {
        hasher.update(child);
    }
    hasher.finalize().into()
}

/// Recomputes the Merkle root from a leaf and its authentication path.
///
/// * `leaf`: canonical encoding `len || payload`.
/// * `index`: position of the leaf within the tree (0-based).
/// * `leaf_count`: total number of leaves committed by the tree.
/// * `path`: authentication path (leaf to root order).
pub fn compute_root_from_path(
    leaf: &[u8],
    index: usize,
    leaf_count: usize,
    path: &[MerklePathElement],
) -> Result<[u8; DIGEST_SIZE], MerkleError> {
    if leaf_count == 0 || index >= leaf_count {
        return Err(MerkleError::ErrPathIndexByte);
    }

    let mut hash = hash_leaf(leaf)?;
    let mut current_index = index;
    let mut nodes_in_level = leaf_count;

    for element in path {
        if element.index.0 > MerkleIndex::MAX {
            return Err(MerkleError::ErrPathIndexByte);
        }
        let expected_position = current_index % ARITY;
        if element.index.0 as usize != expected_position {
            return Err(MerkleError::ErrPathIndexByte);
        }

        let parent_index = current_index / ARITY;
        let chunk_base = parent_index * ARITY;
        let chunk_len = nodes_in_level.saturating_sub(chunk_base).min(ARITY);

        let mut children = [[0u8; DIGEST_SIZE]; ARITY];
        let mut sibling_iter = element.siblings.iter();
        for offset in 0..ARITY {
            if offset == expected_position {
                children[offset] = hash;
                continue;
            }
            let sibling = sibling_iter
                .next()
                .copied()
                .ok_or(MerkleError::ErrPathIndexByte)?;
            if offset >= chunk_len && sibling != EMPTY_DIGEST {
                return Err(MerkleError::ErrMerkleEmptyPadding);
            }
            children[offset] = if offset < chunk_len {
                sibling
            } else {
                EMPTY_DIGEST
            };
        }

        hash = hash_internal(&children);
        current_index = parent_index;
        nodes_in_level = (nodes_in_level + ARITY - 1) / ARITY;
    }

    if current_index != 0 {
        return Err(MerkleError::ErrPathIndexByte);
    }

    Ok(hash)
}

/// Verifies a Merkle path against an expected root digest.
pub fn verify_path(
    leaf: &[u8],
    index: usize,
    leaf_count: usize,
    path: &[MerklePathElement],
    expected_root: &[u8; DIGEST_SIZE],
) -> Result<(), MerkleError> {
    let computed = compute_root_from_path(leaf, index, leaf_count, path)?;
    if &computed != expected_root {
        return Err(MerkleError::ErrPathIndexByte);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_digest_matches_reference() {
        assert_eq!(EMPTY_DIGEST, hash(b"RPP-MERKLE-EMPTY\0").into_bytes());
    }

    #[test]
    fn empty_tree_root_is_empty() {
        let leaves: Vec<Vec<u8>> = Vec::new();
        let tree = Blake3MerkleTree::from_leaves(leaves).expect("tree");
        assert_eq!(tree.leaf_count(), 0);
        assert_eq!(tree.root(), EMPTY_DIGEST);
    }

    #[test]
    fn roundtrip_proofs() {
        let payloads = vec![
            encode_leaf(&[1, 2, 3]),
            encode_leaf(&[4, 5, 6, 7]),
            encode_leaf(&[]),
            encode_leaf(&[9; 12]),
            encode_leaf(b"final"),
        ];

        let tree = Blake3MerkleTree::from_leaves(payloads.iter()).expect("tree");
        let root = tree.root();

        for (index, leaf) in payloads.iter().enumerate() {
            let path = tree.open(index).expect("path");
            verify_path(leaf, index, tree.leaf_count(), &path, &root).expect("verify");
        }
    }

    #[test]
    fn detects_length_mismatch() {
        let mut leaf = encode_leaf(&[1, 2, 3]);
        leaf[0] ^= 0x01; // corrupt the length prefix
        let path = Vec::new();
        let error = compute_root_from_path(&leaf, 0, 1, &path).unwrap_err();
        assert_eq!(error, MerkleError::ErrMerkleLeafLength);
    }

    #[test]
    fn rejects_incorrect_padding() {
        let payloads = vec![encode_leaf(&[1]), encode_leaf(&[2])];
        let tree = Blake3MerkleTree::from_leaves(payloads.iter()).expect("tree");
        let mut path = tree.open(0).expect("path");
        // Force an incorrect padding hash for the last sibling at the top level.
        path.last_mut().unwrap().siblings[2] = [0u8; DIGEST_SIZE];
        let err = compute_root_from_path(&payloads[0], 0, tree.leaf_count(), &path).unwrap_err();
        assert_eq!(err, MerkleError::ErrMerkleEmptyPadding);
    }

    #[test]
    fn index_byte_three_with_padding() {
        let payloads = (0..6).map(|i| encode_leaf(&[i as u8])).collect::<Vec<_>>();
        let tree = Blake3MerkleTree::from_leaves(payloads.iter()).expect("tree");
        let index = 3usize; // position 3 within its chunk
        let path = tree.open(index).expect("path");
        verify_path(
            &payloads[index],
            index,
            tree.leaf_count(),
            &path,
            &tree.root(),
        )
        .expect("verification");
    }

    #[test]
    fn sibling_order_mismatch_rejected() {
        let payloads = vec![
            encode_leaf(&[1, 2, 3, 4]),
            encode_leaf(&[5, 6, 7, 8]),
            encode_leaf(&[9, 10, 11, 12]),
            encode_leaf(&[13, 14, 15, 16]),
        ];

        let tree = Blake3MerkleTree::from_leaves(payloads.iter()).expect("tree");
        let mut path = tree.open(2).expect("path");
        // Swap two siblings to break the order constraint.
        path[0].siblings.swap(0, 1);
        let err = verify_path(&payloads[2], 2, tree.leaf_count(), &path, &tree.root()).unwrap_err();
        assert_eq!(err, MerkleError::ErrPathIndexByte);
    }
}
