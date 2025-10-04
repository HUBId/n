//! Quartic FRI prover and verifier implementation.
//!
//! The prover operates purely in-memory and produces fully deterministic proofs
//! that can be re-verified using the [`FriVerifier`] helper.  Hashing and query
//! sampling rely on the pseudo-BLAKE3 primitives from [`crate::fri`], keeping the
//! implementation self-contained and dependency free.

use core::fmt;
use std::collections::HashSet;

use crate::field::FieldElement;
use crate::fri::folding::{quartic_fold, QUARTIC_FOLD};
use crate::fri::{
    field_from_hash, field_to_bytes, hash_internal, hash_leaf, pseudo_blake3, PseudoBlake3Xof,
};
use crate::hash::blake3::FiatShamirChallengeRules;
use crate::hash::merkle::{Blake3FourAryMerkleSpec, MerkleIndex, MerklePathElement};

/// Transcript seed used when instantiating the FRI prover and verifier.
pub type FriTranscriptSeed = [u8; 32];

/// Security profiles supported by the FRI engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FriSecurityLevel {
    /// Standard profile with 64 queries.
    Standard,
    /// High security profile with 96 queries.
    HiSec,
    /// Throughput oriented profile with 48 queries.
    Throughput,
}

impl FriSecurityLevel {
    /// Returns the query budget associated with the profile.
    pub const fn query_budget(self) -> usize {
        match self {
            FriSecurityLevel::Standard => 64,
            FriSecurityLevel::HiSec => 96,
            FriSecurityLevel::Throughput => 48,
        }
    }

    fn tag(self) -> &'static str {
        match self {
            FriSecurityLevel::Standard => "STD",
            FriSecurityLevel::HiSec => "HISEC",
            FriSecurityLevel::Throughput => "THR",
        }
    }
}

/// FRI verification errors mapped to the specification failure classes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FriError {
    /// No evaluations were provided to the prover.
    EmptyCodeword,
    /// Query position exceeded the LDE domain size.
    QueryOutOfRange { position: usize },
    /// Merkle path was malformed (index byte mismatch or inconsistent height).
    PathInvalid { layer: usize },
    /// Merkle layer root mismatch.
    LayerRootMismatch { layer: usize },
    /// Proof declared a different security profile.
    SecurityLevelMismatch,
    /// Proof declared an unexpected number of queries.
    QueryBudgetMismatch { expected: usize, actual: usize },
    /// Generic structure error (missing layer, inconsistent lengths, etc.).
    InvalidStructure(&'static str),
}

impl fmt::Display for FriError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FriError::EmptyCodeword => write!(f, "codeword is empty"),
            FriError::QueryOutOfRange { position } => {
                write!(f, "query position {position} outside evaluation domain")
            }
            FriError::PathInvalid { layer } => write!(f, "invalid Merkle path at layer {layer}"),
            FriError::LayerRootMismatch { layer } => {
                write!(f, "layer {layer} root mismatch")
            }
            FriError::SecurityLevelMismatch => write!(f, "security profile mismatch"),
            FriError::QueryBudgetMismatch { expected, actual } => write!(
                f,
                "query budget mismatch (expected {expected}, got {actual})"
            ),
            FriError::InvalidStructure(reason) => write!(f, "invalid proof structure: {reason}"),
        }
    }
}

impl std::error::Error for FriError {}

/// Helper struct representing a prover transcript.
#[derive(Debug, Clone)]
struct FriTranscript {
    state: [u8; 32],
}

impl FriTranscript {
    fn new(seed: FriTranscriptSeed) -> Self {
        Self { state: seed }
    }

    fn absorb_layer(&mut self, layer_index: usize, root: &[u8; 32]) {
        let mut payload = Vec::with_capacity(48);
        payload.extend_from_slice(&self.state);
        payload.extend_from_slice(&(layer_index as u64).to_le_bytes());
        payload.extend_from_slice(root);
        self.state = pseudo_blake3(&payload);
    }

    fn draw_eta(&mut self, layer_index: usize) -> FieldElement {
        let label = format!("{}ETA-{layer_index}", FiatShamirChallengeRules::SALT_PREFIX);
        let mut payload = Vec::with_capacity(self.state.len() + label.len());
        payload.extend_from_slice(&self.state);
        payload.extend_from_slice(label.as_bytes());
        let challenge = pseudo_blake3(&payload);
        self.state = pseudo_blake3(&challenge);
        field_from_hash(&challenge)
    }

    fn absorb_final(&mut self, digest: &[u8; 32]) {
        let mut payload = Vec::with_capacity(64);
        payload.extend_from_slice(&self.state);
        payload.extend_from_slice(b"RPP-FS/FINAL");
        payload.extend_from_slice(digest);
        self.state = pseudo_blake3(&payload);
    }

    fn derive_query_seed(&mut self) -> [u8; 32] {
        let mut payload = Vec::with_capacity(64);
        payload.extend_from_slice(&self.state);
        payload.extend_from_slice(b"RPP-FS/QUERY-SEED");
        let seed = pseudo_blake3(&payload);
        self.state = pseudo_blake3(&seed);
        seed
    }
}

/// Merkle tree specialised for quartic arity.
#[derive(Debug, Clone)]
struct MerkleTree {
    levels: Vec<Vec<[u8; 32]>>,
}

impl MerkleTree {
    fn new(values: &[FieldElement]) -> Self {
        let mut levels = Vec::new();
        let mut current: Vec<[u8; 32]> = values.iter().map(hash_leaf).collect();
        if current.is_empty() {
            current.push(hash_leaf(&FieldElement::ZERO));
        }
        levels.push(current.clone());

        while current.len() > 1 {
            let mut next = Vec::with_capacity((current.len() + QUARTIC_FOLD - 1) / QUARTIC_FOLD);
            for chunk in current.chunks(QUARTIC_FOLD) {
                let mut children = [[0u8; 32]; QUARTIC_FOLD];
                for i in 0..QUARTIC_FOLD {
                    children[i] = if i < chunk.len() {
                        chunk[i]
                    } else {
                        Blake3FourAryMerkleSpec::EMPTY_CHILD_DIGEST
                    };
                }
                next.push(hash_internal(&children));
            }
            current = next.clone();
            levels.push(next);
        }

        Self { levels }
    }

    fn root(&self) -> [u8; 32] {
        self.levels
            .last()
            .and_then(|level| level.first())
            .copied()
            .unwrap_or(Blake3FourAryMerkleSpec::EMPTY_CHILD_DIGEST)
    }

    fn prove(&self, mut index: usize) -> Vec<MerklePathElement<[u8; 32]>> {
        let mut path = Vec::new();
        for level in 0..self.levels.len() - 1 {
            let nodes = &self.levels[level];
            let parent_index = index / QUARTIC_FOLD;
            let position = index % QUARTIC_FOLD;
            let base = parent_index * QUARTIC_FOLD;
            let mut siblings = [[0u8; 32]; 3];
            let mut s_idx = 0;
            for offset in 0..QUARTIC_FOLD {
                let digest = if base + offset < nodes.len() {
                    nodes[base + offset]
                } else {
                    Blake3FourAryMerkleSpec::EMPTY_CHILD_DIGEST
                };
                if offset != position {
                    siblings[s_idx] = digest;
                    s_idx += 1;
                }
            }
            path.push(MerklePathElement {
                index: MerkleIndex(position as u8),
                siblings,
            });
            index /= QUARTIC_FOLD;
        }
        path
    }
}

/// Residual polynomial commitment hashing all final-layer evaluations.
fn hash_final_layer(values: &[FieldElement]) -> [u8; 32] {
    let mut payload = Vec::with_capacity(4 + values.len() * 8);
    payload.extend_from_slice(&(values.len() as u32).to_le_bytes());
    for value in values {
        payload.extend_from_slice(&field_to_bytes(value));
    }
    pseudo_blake3(&payload)
}

/// Declarative representation of a single query opening.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FriQuery {
    /// Position sampled from the LDE domain.
    pub position: usize,
    /// Layer openings ascending from the original codeword to the residual layer.
    pub layers: Vec<FriQueryLayer>,
    /// Value revealed at the residual polynomial for this query.
    pub final_value: FieldElement,
}

/// Opening data for a specific FRI layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FriQueryLayer {
    /// Evaluation revealed at this layer.
    pub value: FieldElement,
    /// Merkle authentication path proving membership.
    pub path: Vec<MerklePathElement<[u8; 32]>>,
}

/// Declarative representation of a FRI proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FriProof {
    /// Declared security profile for the proof.
    pub security_level: FriSecurityLevel,
    /// Size of the initial evaluation domain.
    pub initial_domain_size: usize,
    /// Merkle roots for each folded layer.
    pub layer_roots: Vec<[u8; 32]>,
    /// Residual polynomial evaluations.
    pub final_polynomial: Vec<FieldElement>,
    /// Digest binding the final polynomial values.
    pub final_polynomial_digest: [u8; 32],
    /// Query openings.
    pub queries: Vec<FriQuery>,
}

impl FriProof {
    /// Generates a FRI proof from the provided LDE evaluations.
    pub fn prove(
        security_level: FriSecurityLevel,
        seed: FriTranscriptSeed,
        evaluations: &[FieldElement],
    ) -> Result<Self, FriError> {
        if evaluations.is_empty() {
            return Err(FriError::EmptyCodeword);
        }

        let mut transcript = FriTranscript::new(seed);
        let mut layers = Vec::new();
        let mut current = evaluations.to_vec();
        let mut layer_roots = Vec::new();

        while current.len() > 1024 {
            let tree = MerkleTree::new(&current);
            let root = tree.root();
            transcript.absorb_layer(layer_roots.len(), &root);
            let eta = transcript.draw_eta(layer_roots.len());
            layer_roots.push(root);
            layers.push((current.clone(), tree));
            current = quartic_fold(&current, eta);
        }

        // Record the final layer (values only).
        let final_polynomial = current.clone();
        let final_polynomial_digest = hash_final_layer(&final_polynomial);
        transcript.absorb_final(&final_polynomial_digest);
        let query_seed = transcript.derive_query_seed();

        let query_positions =
            derive_query_positions(query_seed, security_level.query_budget(), evaluations.len());

        let mut queries = Vec::with_capacity(query_positions.len());
        for &position in &query_positions {
            let mut index = position;
            let mut layers_openings = Vec::with_capacity(layers.len());
            for (_layer_idx, (layer_values, tree)) in layers.iter().enumerate() {
                if index >= layer_values.len() {
                    return Err(FriError::QueryOutOfRange { position });
                }
                let value = layer_values[index];
                let path = tree.prove(index);
                layers_openings.push(FriQueryLayer { value, path });
                index /= QUARTIC_FOLD;
            }

            if index >= final_polynomial.len() {
                return Err(FriError::QueryOutOfRange { position });
            }
            let final_value = final_polynomial[index];
            queries.push(FriQuery {
                position,
                layers: layers_openings,
                final_value,
            });
        }

        Ok(Self {
            security_level,
            initial_domain_size: evaluations.len(),
            layer_roots,
            final_polynomial,
            final_polynomial_digest,
            queries,
        })
    }
}

/// Derives the canonical query plan identifier.
pub fn derive_query_plan_id(level: FriSecurityLevel) -> [u8; 32] {
    let mut payload = Vec::new();
    payload.extend_from_slice(b"FRI-PLAN/QUARTIC");
    payload.extend_from_slice(&(QUARTIC_FOLD as u32).to_le_bytes());
    payload.extend_from_slice(&(256u32).to_le_bytes());
    payload.extend_from_slice(&(1024u32).to_le_bytes());
    payload.extend_from_slice(&(level.query_budget() as u32).to_le_bytes());
    payload.extend_from_slice(level.tag().as_bytes());
    payload.extend_from_slice(b"challenge-after-commit");
    payload.extend_from_slice(b"dedup-sort-stable");
    pseudo_blake3(&payload)
}

/// Verifier entry point.
pub struct FriVerifier;

impl FriVerifier {
    /// Verifies a FRI proof against the declared security level and transcript seed.
    pub fn verify<F>(
        proof: &FriProof,
        security_level: FriSecurityLevel,
        seed: FriTranscriptSeed,
        mut final_value_oracle: F,
    ) -> Result<(), FriError>
    where
        F: FnMut(usize) -> FieldElement,
    {
        if proof.security_level != security_level {
            return Err(FriError::SecurityLevelMismatch);
        }
        if proof.initial_domain_size == 0 {
            return Err(FriError::EmptyCodeword);
        }
        if proof.queries.len() != security_level.query_budget() {
            return Err(FriError::QueryBudgetMismatch {
                expected: security_level.query_budget(),
                actual: proof.queries.len(),
            });
        }

        let mut transcript = FriTranscript::new(seed);
        for (layer_index, root) in proof.layer_roots.iter().enumerate() {
            transcript.absorb_layer(layer_index, root);
            let _ = transcript.draw_eta(layer_index);
        }

        let recomputed_digest = hash_final_layer(&proof.final_polynomial);
        if recomputed_digest != proof.final_polynomial_digest {
            return Err(FriError::LayerRootMismatch {
                layer: proof.layer_roots.len(),
            });
        }

        transcript.absorb_final(&proof.final_polynomial_digest);
        let query_seed = transcript.derive_query_seed();
        let expected_positions = derive_query_positions(
            query_seed,
            security_level.query_budget(),
            proof.initial_domain_size,
        );

        if expected_positions.len() != proof.queries.len() {
            return Err(FriError::InvalidStructure("query count mismatch"));
        }

        for (expected_position, query) in expected_positions.iter().zip(proof.queries.iter()) {
            if query.position != *expected_position {
                return Err(FriError::InvalidStructure("query position mismatch"));
            }
            let mut index = *expected_position;
            for (layer_idx, layer) in query.layers.iter().enumerate() {
                let root = proof
                    .layer_roots
                    .get(layer_idx)
                    .ok_or(FriError::InvalidStructure("missing layer root"))?;
                verify_path(layer.value, &layer.path, root, index, layer_idx)?;
                index /= QUARTIC_FOLD;
            }

            if index >= proof.final_polynomial.len() {
                return Err(FriError::QueryOutOfRange {
                    position: *expected_position,
                });
            }

            if proof.final_polynomial[index] != query.final_value {
                return Err(FriError::LayerRootMismatch {
                    layer: proof.layer_roots.len(),
                });
            }

            let expected_final = final_value_oracle(index);
            if expected_final != query.final_value {
                return Err(FriError::LayerRootMismatch {
                    layer: proof.layer_roots.len(),
                });
            }
        }

        Ok(())
    }
}

fn derive_query_positions(seed: [u8; 32], count: usize, domain_size: usize) -> Vec<usize> {
    assert!(domain_size > 0, "domain size must be positive");
    let mut xof = PseudoBlake3Xof::new(&seed);
    let mut unique = Vec::with_capacity(count);
    let mut seen = HashSet::new();
    while unique.len() < count {
        let word = xof.next_u64();
        let position = (word % (domain_size as u64)) as usize;
        if seen.insert(position) {
            unique.push(position);
        }
    }
    unique.sort();
    unique
}

fn verify_path(
    value: FieldElement,
    path: &[MerklePathElement<[u8; 32]>],
    expected_root: &[u8; 32],
    mut index: usize,
    layer_index: usize,
) -> Result<(), FriError> {
    let mut hash = hash_leaf(&value);
    for element in path {
        if element.index.0 > MerkleIndex::MAX {
            return Err(FriError::PathInvalid { layer: layer_index });
        }
        let expected_child = (index % QUARTIC_FOLD) as u8;
        if element.index.0 != expected_child {
            return Err(FriError::PathInvalid { layer: layer_index });
        }
        let mut children = [[0u8; 32]; QUARTIC_FOLD];
        let mut sibling_iter = element.siblings.iter();
        for offset in 0..QUARTIC_FOLD {
            if offset == expected_child as usize {
                children[offset] = hash;
            } else {
                let sibling = sibling_iter
                    .next()
                    .copied()
                    .unwrap_or(Blake3FourAryMerkleSpec::EMPTY_CHILD_DIGEST);
                children[offset] = sibling;
            }
        }
        hash = hash_internal(&children);
        index /= QUARTIC_FOLD;
    }

    if hash != *expected_root {
        return Err(FriError::LayerRootMismatch { layer: layer_index });
    }
    if index != 0 {
        return Err(FriError::PathInvalid { layer: layer_index });
    }
    Ok(())
}
