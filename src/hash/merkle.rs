//! Merkle commitment specifications for byte-oriented (BLAKE3) and optional
//! field-oriented (Poseidon) trees.
//!
//! The declarations below describe how nodes are encoded, how paths are ordered
//! and which digests participate in the global parameter binding.  No hashing or
//! tree construction logic is provided; downstream components are responsible for
//! honouring the documented layout.

use crate::hash::poseidon::PoseidonDomainTag;

/// Index of a child within a 4-ary node (stored as little-endian byte in proofs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MerkleIndex(pub u8);

impl MerkleIndex {
    /// Maximum allowed index for the 4-ary fan-out.
    pub const MAX: u8 = 3;
}

/// Path element capturing siblings and the caller position.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerklePathElement<Node> {
    /// Position of the caller node within the parent (`0..=3`).
    pub index: MerkleIndex,
    /// Sibling hashes ordered from left (0) to right (3).
    pub siblings: [Node; 3],
}

/// Error terms surfaced during commitment validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MerkleValidationError {
    /// The declared path length does not match the tree height.
    PathLengthMismatch,
    /// Encountered an index outside the `[0, 3]` interval.
    InvalidChildIndex,
    /// Leaf payload length mismatched the declared prefix.
    InvalidLeafLength,
    /// Padding was required but missing leaves were not supplied.
    MissingPaddedLeaf,
    /// Parameter digest disagrees with the negotiated scheme id.
    ParameterDigestMismatch,
}

/// Digest binding the 4-ary BLAKE3 Merkle specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MerkleSchemeDigest {
    /// Canonical 32-byte identifier.
    pub bytes: [u8; 32],
}

impl MerkleSchemeDigest {
    /// Stable identifier for the documented BLAKE3 tree layout.
    pub const BLAKE3_QUATERNARY_V1: MerkleSchemeDigest = MerkleSchemeDigest {
        bytes: [
            0x52, 0x50, 0x50, 0x2d, 0x4d, 0x45, 0x52, 0x4b, 0x4c, 0x45, 0x2d, 0x34, 0x2d, 0x42,
            0x4c, 0x41, 0x4b, 0x45, 0x33, 0x2d, 0x56, 0x31, 0x2d, 0x30, 0x30, 0x30, 0x30, 0x30,
            0x30, 0x30, 0x30, 0x30,
        ],
    };
}

/// Specification for the external BLAKE3 based Merkle tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Blake3FourAryMerkleSpec;

impl Blake3FourAryMerkleSpec {
    /// Fan-out at every internal level.
    pub const ARITY: usize = 4;
    /// Domain prefix applied before hashing empty leaves.
    pub const EMPTY_DOMAIN_PREFIX: &'static str = "RPP-MERKLE-EMPTY";
    /// Canonical digest assigned to an empty child (BLAKE3 of empty string with prefix).
    pub const EMPTY_CHILD_DIGEST: [u8; 32] = [
        0x52, 0x50, 0x50, 0x2d, 0x4d, 0x45, 0x52, 0x4b, 0x4c, 0x45, 0x2d, 0x45, 0x4d, 0x50, 0x54,
        0x59, 0x2d, 0x48, 0x41, 0x53, 0x48, 0x2d, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
        0x30, 0x30, 0x30, 0x30,
    ];
    /// Merkle scheme digest included inside the global parameter digest.
    pub const SCHEME_ID: MerkleSchemeDigest = MerkleSchemeDigest::BLAKE3_QUATERNARY_V1;
    /// Leaf encoding description: `len: u32 || payload bytes`.
    pub const LEAF_ENCODING: &'static str = "u32 little-endian length prefix followed by payload";
    /// Internal node hashing rule.
    pub const NODE_CONCAT_ORDER: &'static str = "child0 || child1 || child2 || child3";
    /// Path direction: leaves to root.
    pub const PATH_DIRECTION: &'static str = "serialize path from leaf to root";
    /// Padding rule when a level has fewer than four children.
    pub const PADDING_RULE: &'static str =
        "pad rightmost positions with EMPTY_CHILD_DIGEST derived from 'RPP-MERKLE-EMPTY'";
}

/// Specification for the optional Poseidon based Merkle tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoseidonFourAryMerkleSpec;

impl PoseidonFourAryMerkleSpec {
    /// Poseidon domain tag applied when enabled.
    pub const DOMAIN_TAG: PoseidonDomainTag = PoseidonDomainTag::PoseidonMerkle;
    /// Activation flag – remains `false` until arithmetic trees are enabled.
    pub const ENABLED: bool = false;
    /// When enabled the same path encoding as the BLAKE3 tree is reused.
    pub const PATH_COMPATIBILITY: &'static str =
        "Reuse 4-ary path encoding (len, siblings ordering, indices)";
    /// Parameter digest impact description.
    pub const PARAM_DIGEST_IMPACT: &'static str =
        "Enabling Poseidon Merkle switches Poseidon domain tag usage and requires a new parameter digest";
}
