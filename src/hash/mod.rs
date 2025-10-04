//! Hashing primitives for the `rpp-stark` engine.
//! Contains Poseidon for field-friendly hashing, Blake3 for byte hashing, and Merkle commitments.

pub mod blake3;
pub mod config;
pub mod merkle;
pub mod poseidon;

pub use blake3::TranscriptHasher;
pub use config::{
    Blake3Parameters, HashParameters, PoseidonParameters, BLAKE3_COMMITMENT_DOMAIN_TAG,
    BLAKE3_PARAMETERS_V1_ID, POSEIDON_ARITHMETIC_DOMAIN_TAG, POSEIDON_PARAMETERS_V1_ID,
};
pub use merkle::{MerklePath, MerkleTree};
pub use poseidon::{
    PoseidonMdsMatrix, PoseidonMdsMatrixV1, PoseidonPermutationOrder, PoseidonPermutationOrderV1,
    PoseidonPermutationSpec, PoseidonRoundConstants, PoseidonRoundConstantsV1, PoseidonSpecV1,
};
