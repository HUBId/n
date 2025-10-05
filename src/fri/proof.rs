//! Binary FRI prover and verifier implementation.
//!
//! The prover operates purely in-memory and produces fully deterministic proofs
//! that can be re-verified using the [`FriVerifier`] helper.  Hashing and query
//! sampling rely on the pseudo-BLAKE3 primitives from [`crate::fri`], keeping the
//! implementation self-contained and dependency free.

use crate::field::FieldElement;
use crate::fri::folding::derive_coset_shift;
use crate::fri::types::{
    FriError, FriProof, FriQuery, FriQueryLayer, FriSecurityLevel, FriTranscriptSeed,
};
use crate::fri::{binary_fold, next_domain_size, parent_index, phi, BINARY_FOLD_ARITY};
use crate::fri::{
    field_from_hash, field_to_bytes, hash_internal, hash_leaf, pseudo_blake3, PseudoBlake3Xof,
};
use crate::hash::blake3::FiatShamirChallengeRules;
use crate::hash::merkle::{
    compute_root_from_path, encode_leaf, MerkleError, MerkleIndex, MerklePathElement, EMPTY_DIGEST,
};
use crate::params::{BuiltinProfile, StarkParams, StarkParamsBuilder};
use std::sync::OnceLock;

const MERKLE_ARITY: usize = 2;

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
            let mut next = Vec::with_capacity((current.len() + MERKLE_ARITY - 1) / MERKLE_ARITY);
            for chunk in current.chunks(MERKLE_ARITY) {
                let mut children = [EMPTY_DIGEST; MERKLE_ARITY];
                for (position, child) in chunk.iter().enumerate() {
                    children[position] = *child;
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
            .unwrap_or(EMPTY_DIGEST)
    }

    fn prove(&self, mut index: usize) -> Vec<MerklePathElement> {
        let mut path = Vec::new();
        for level in 0..self.levels.len() - 1 {
            let nodes = &self.levels[level];
            let parent_index = index / MERKLE_ARITY;
            let position = index % MERKLE_ARITY;
            let base = parent_index * MERKLE_ARITY;
            let sibling = if position == 0 {
                if base + 1 < nodes.len() {
                    nodes[base + 1]
                } else {
                    EMPTY_DIGEST
                }
            } else if base < nodes.len() {
                nodes[base]
            } else {
                EMPTY_DIGEST
            };
            path.push(MerklePathElement {
                index: MerkleIndex(position as u8),
                siblings: [sibling],
            });
            index /= MERKLE_ARITY;
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

fn default_fri_params() -> &'static StarkParams {
    static PARAMS: OnceLock<StarkParams> = OnceLock::new();
    PARAMS.get_or_init(|| {
        StarkParamsBuilder::from_profile(BuiltinProfile::PROFILE_X8)
            .build()
            .expect("default FRI params")
    })
}

/// Maximum degree allowed for the residual polynomial.
const CAP_DEGREE: usize = 256;
/// Maximum number of leaf values that can be committed in the final layer.
const CAP_SIZE: usize = 1024;

impl FriProof {
    /// Generates a FRI proof from the provided LDE evaluations.
    pub fn prove(
        security_level: FriSecurityLevel,
        seed: FriTranscriptSeed,
        evaluations: &[FieldElement],
    ) -> Result<Self, FriError> {
        let params = default_fri_params();
        Self::prove_with_params(security_level, seed, evaluations, params)
    }

    /// Generates a FRI proof using the provided [`StarkParams`].
    pub fn prove_with_params(
        security_level: FriSecurityLevel,
        seed: FriTranscriptSeed,
        evaluations: &[FieldElement],
        params: &StarkParams,
    ) -> Result<Self, FriError> {
        if evaluations.is_empty() {
            return Err(FriError::EmptyCodeword);
        }

        struct LayerWitness {
            values: Vec<FieldElement>,
            tree: MerkleTree,
        }

        let mut transcript = FriTranscript::new(seed);
        let mut witnesses: Vec<LayerWitness> = Vec::new();
        let mut current = evaluations.to_vec();
        let mut layer_roots = Vec::new();
        let mut layer_index = 0usize;
        let mut coset_shift = derive_coset_shift(params);

        while current.len() > 1 && (current.len() > CAP_DEGREE || current.len() > CAP_SIZE) {
            let tree = MerkleTree::new(&current);
            let root = tree.root();
            transcript.absorb_layer(layer_index, &root);
            let eta = transcript.draw_eta(layer_index);
            layer_roots.push(root);

            let next = binary_fold(&current, eta, coset_shift);
            witnesses.push(LayerWitness {
                values: current,
                tree,
            });

            current = next;
            coset_shift = phi(coset_shift);
            layer_index += 1;
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
            let mut layers_openings = Vec::with_capacity(witnesses.len());
            for witness in witnesses.iter() {
                if index >= witness.values.len() {
                    return Err(FriError::QueryOutOfRange { position });
                }
                let value = witness.values[index];
                let path = witness.tree.prove(index);
                layers_openings.push(FriQueryLayer { value, path });
                index = parent_index(index);
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
pub fn derive_query_plan_id(level: FriSecurityLevel, params: &StarkParams) -> [u8; 32] {
    let mut payload = Vec::new();
    payload.extend_from_slice(b"FRI-PLAN/BINARY");
    payload.extend_from_slice(&(BINARY_FOLD_ARITY as u32).to_le_bytes());
    payload.extend_from_slice(&(CAP_DEGREE as u32).to_le_bytes());
    payload.extend_from_slice(&(CAP_SIZE as u32).to_le_bytes());
    payload.extend_from_slice(&(level.query_budget() as u32).to_le_bytes());
    payload.push(params.fri().folding.code());
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
        final_value_oracle: F,
    ) -> Result<(), FriError>
    where
        F: FnMut(usize) -> FieldElement,
    {
        let params = default_fri_params();
        Self::verify_with_params(proof, security_level, seed, params, final_value_oracle)
    }

    /// Verifies a FRI proof using the provided [`StarkParams`].
    pub fn verify_with_params<F>(
        proof: &FriProof,
        security_level: FriSecurityLevel,
        seed: FriTranscriptSeed,
        _params: &StarkParams,
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
            if query.layers.len() != proof.layer_roots.len() {
                return Err(FriError::InvalidStructure("layer count mismatch"));
            }
            let mut index = *expected_position;
            let mut layer_domain_size = proof.initial_domain_size;
            for (layer_idx, layer) in query.layers.iter().enumerate() {
                let root = &proof.layer_roots[layer_idx];
                verify_path(
                    layer.value,
                    &layer.path,
                    root,
                    index,
                    layer_idx,
                    layer_domain_size,
                )?;
                index = parent_index(index);
                layer_domain_size = next_domain_size(layer_domain_size);
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
    let target = count.min(domain_size);
    let mut unique = Vec::with_capacity(target);
    let mut seen = vec![false; domain_size];
    while unique.len() < target {
        let word = xof.next_u64();
        let position = (word % (domain_size as u64)) as usize;
        if !seen[position] {
            seen[position] = true;
            unique.push(position);
        }
    }
    unique.sort();
    unique
}

fn verify_path(
    value: FieldElement,
    path: &[MerklePathElement],
    expected_root: &[u8; 32],
    index: usize,
    layer_index: usize,
    leaf_count: usize,
) -> Result<(), FriError> {
    let encoded_leaf = encode_leaf(&field_to_bytes(&value));
    let computed =
        compute_root_from_path(&encoded_leaf, index, leaf_count, path).map_err(|err| {
            FriError::PathInvalid {
                layer: layer_index,
                reason: err,
            }
        })?;

    if &computed != expected_root {
        return Err(FriError::PathInvalid {
            layer: layer_index,
            reason: MerkleError::ErrMerkleSiblingOrder,
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_evaluations() -> Vec<FieldElement> {
        (0..1024).map(|i| FieldElement(i as u64 + 1)).collect()
    }

    fn sample_seed() -> FriTranscriptSeed {
        [42u8; 32]
    }

    fn final_value_oracle(values: Vec<FieldElement>) -> impl FnMut(usize) -> FieldElement {
        move |index| values[index]
    }

    #[test]
    fn fri_prover_handles_coset_folding() {
        let evaluations = sample_evaluations();
        let seed = sample_seed();
        let params = StarkParamsBuilder::from_profile(BuiltinProfile::PROFILE_HISEC_X16)
            .build()
            .expect("coset params");

        let proof =
            FriProof::prove_with_params(FriSecurityLevel::HiSec, seed, &evaluations, &params)
                .expect("coset proof");

        let finals = proof.final_polynomial.clone();
        FriVerifier::verify_with_params(
            &proof,
            FriSecurityLevel::HiSec,
            seed,
            &params,
            final_value_oracle(finals),
        )
        .expect("verification");
    }

    #[test]
    fn fri_prover_is_deterministic() {
        let evaluations = sample_evaluations();
        let seed = sample_seed();

        let proof_a =
            FriProof::prove(FriSecurityLevel::Standard, seed, &evaluations).expect("first proof");
        let proof_b =
            FriProof::prove(FriSecurityLevel::Standard, seed, &evaluations).expect("second proof");

        assert_eq!(proof_a, proof_b, "proofs must be identical across runs");

        let finals = proof_a.final_polynomial.clone();
        FriVerifier::verify(
            &proof_a,
            FriSecurityLevel::Standard,
            seed,
            final_value_oracle(finals),
        )
        .expect("verification");
    }

    #[test]
    fn fri_verifier_enforces_query_budget() {
        let evaluations = sample_evaluations();
        let seed = sample_seed();

        let proof = FriProof::prove(FriSecurityLevel::Standard, seed, &evaluations).expect("proof");
        let mut tampered = proof.clone();
        tampered.queries.pop();

        let finals = tampered.final_polynomial.clone();
        let err = FriVerifier::verify(
            &tampered,
            FriSecurityLevel::Standard,
            seed,
            final_value_oracle(finals),
        )
        .expect_err("query budget mismatch");

        assert!(
            matches!(err, FriError::QueryBudgetMismatch { expected, actual } if expected == FriSecurityLevel::Standard.query_budget() && actual + 1 == expected)
        );
    }

    #[test]
    fn fri_verifier_reports_path_mismatch() {
        let evaluations = sample_evaluations();
        let seed = sample_seed();
        let proof = FriProof::prove(FriSecurityLevel::Standard, seed, &evaluations).expect("proof");

        let mut tampered = proof.clone();
        if let Some(layer) = tampered
            .queries
            .get_mut(0)
            .and_then(|query| query.layers.get_mut(0))
        {
            if let Some(element) = layer.path.get_mut(0) {
                element.siblings[0][0] ^= 0x01;
            }
        }

        let finals = tampered.final_polynomial.clone();
        let err = FriVerifier::verify(
            &tampered,
            FriSecurityLevel::Standard,
            seed,
            final_value_oracle(finals),
        )
        .expect_err("path corruption");

        assert!(matches!(err, FriError::PathInvalid { layer: 0, .. }));
    }

    #[test]
    fn fri_verifier_reports_query_out_of_range() {
        let seed = sample_seed();
        let security = FriSecurityLevel::Standard;
        let final_polynomial: Vec<FieldElement> = Vec::new();
        let final_digest = hash_final_layer(&final_polynomial);

        let mut transcript = FriTranscript::new(seed);
        transcript.absorb_final(&final_digest);
        let query_seed = transcript.derive_query_seed();
        let positions = derive_query_positions(query_seed, security.query_budget(), 1024);

        let proof = FriProof {
            security_level: security,
            initial_domain_size: 1024,
            layer_roots: Vec::new(),
            final_polynomial,
            final_polynomial_digest: final_digest,
            queries: positions
                .into_iter()
                .map(|position| FriQuery {
                    position,
                    layers: Vec::new(),
                    final_value: FieldElement::ZERO,
                })
                .collect(),
        };

        let err = FriVerifier::verify(&proof, security, seed, |_| FieldElement::ZERO)
            .expect_err("query out of range");

        assert!(matches!(err, FriError::QueryOutOfRange { .. }));
    }
}
