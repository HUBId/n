//! Abstract Merkle tree definitions shared by the prover and verifier.
//!
//! The module only declares the structures and traits required to describe the
//! tree layout. Concrete construction and verification logic lives in the
//! prover/verifier specific crates.
//!
//! ## Serialization & indexing conventions
//!
//! * **Leaves** – byte based trees (BLAKE3) accept 32-byte leaf records that are
//!   canonical little-endian encodings of field elements or raw transcript
//!   digests. Field based trees (Poseidon) store canonical field elements
//!   directly. Implementations must convert them to the modulus-respecting
//!   byte representation before passing them to external interfaces.
//! * **Internal nodes** – nodes are serialized by concatenating the canonical
//!   encodings of their children from left to right. For the 4-ary layout the
//!   concatenation order is `[child_0 || child_1 || child_2 || child_3]`.
//!   Implementations may compact this representation but the logical ordering
//!   must stay intact.
//! * **Endianness** – the canonical encoding for byte based trees follows
//!   little-endian order; field based trees adopt the natural ordering of the
//!   underlying field element representation to avoid limb reversals.
//! * **Path indexing** – Merkle paths enumerate siblings from the leaf level to
//!   the root. The `index` field records the zero-based position of the leaf
//!   inside its parent fan-out before hashing.
//! * **Sibling ordering** – the `siblings` vector stores neighbours ordered from
//!   left to right. When hashing an internal node the implementation must
//!   insert the queried leaf at position `index` and then apply the backend
//!   hash.
//!
//! ## Domain separation
//!
//! * **Byte trees** – use [`BLAKE3_COMMITMENT_DOMAIN_TAG`] for every hash call to
//!   avoid collisions with transcript hashing.
//! * **Field trees** – use [`POSEIDON_ARITHMETIC_DOMAIN_TAG`] when invoking the
//!   Poseidon permutation so that field commitments cannot collide with sponge
//!   evaluations.

use core::marker::PhantomData;

use super::{Blake3Hasher, BLAKE3_COMMITMENT_DOMAIN_TAG, POSEIDON_ARITHMETIC_DOMAIN_TAG};
use crate::hash::poseidon::PoseidonPermutationSpec;

/// Static configuration shared by all Merkle tree backends.
#[derive(Debug, Clone, Copy)]
pub struct MerkleTreeConfig;

impl MerkleTreeConfig {
    /// Minimal depth accepted for commitments to remain collision resistant.
    pub const MIN_DEPTH: usize = 2;
    /// Maximal depth allowed before resource usage becomes prohibitive.
    pub const MAX_DEPTH: usize = 64;
    /// Budget for the number of Blake3 invocations during root computation.
    pub const MAX_BLAKE3_HASH_CALLS: usize = 1 << 20;
    /// Budget for the number of Poseidon invocations during root computation.
    pub const MAX_POSEIDON_HASH_CALLS: usize = 1 << 18;
}

/// Merkle path element describing sibling orientation and position.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerklePath<Node> {
    /// Position of the leaf within the parent fan-out before hashing.
    pub index: u8,
    /// Sibling nodes ordered from left to right.
    pub siblings: Vec<Node>,
}

/// Describes the capabilities expected from a Merkle tree backend.
pub trait MerkleTreeBackend {
    /// Hash primitive used to combine nodes.
    type Hasher;
    /// Leaf representation handled by the backend.
    type Leaf;
    /// Node representation produced by the backend.
    type Node;

    /// Fan-out for each internal level.
    const ARITY: usize;
    /// Domain separation tag applied to every hash invocation.
    const DOMAIN_TAG: &'static [u8];
}

/// Marker trait describing types that can act as Poseidon Merkle leaves.
pub trait PoseidonLeaf {
    /// Underlying field type used by the Poseidon permutation.
    type Field;

    /// Provides a canonical representation ready for hashing.
    fn to_field_element(&self) -> Self::Field;
}

/// Marker structure describing a 4-ary Blake3 backed Merkle tree.
#[derive(Debug, Clone)]
pub struct Blake3QuaternaryMerkleTree<H = Blake3Hasher> {
    /// Canonical 32-byte little-endian leaf encodings.
    pub leaves: Vec<[u8; 32]>,
    /// Phantom link to the concrete hasher implementation.
    pub hasher: PhantomData<H>,
}

impl<H> MerkleTreeBackend for Blake3QuaternaryMerkleTree<H> {
    type Hasher = H;
    type Leaf = [u8; 32];
    type Node = [u8; 32];

    const ARITY: usize = 4;
    const DOMAIN_TAG: &'static [u8] = BLAKE3_COMMITMENT_DOMAIN_TAG;
}

/// Marker structure for field-friendly Poseidon-based Merkle trees.
#[derive(Debug, Clone)]
pub struct PoseidonMerkleTree<F, Spec>
where
    Spec: PoseidonPermutationSpec<Field = <F as PoseidonLeaf>::Field>,
    F: PoseidonLeaf,
{
    /// Canonical field element leaves.
    pub leaves: Vec<F>,
    /// Phantom marker carrying the Poseidon specification.
    pub spec: PhantomData<Spec>,
}

impl<F, Spec> MerkleTreeBackend for PoseidonMerkleTree<F, Spec>
where
    Spec: PoseidonPermutationSpec<Field = <F as PoseidonLeaf>::Field>,
    F: PoseidonLeaf,
{
    type Hasher = Spec;
    type Leaf = F;
    type Node = F;

    const ARITY: usize = 4;
    const DOMAIN_TAG: &'static [u8] = POSEIDON_ARITHMETIC_DOMAIN_TAG;
}
