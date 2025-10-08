//! Proof envelope implementation and serialization helpers.
//!
//! The builder defined in this module is responsible for assembling a
//! specification-compliant [`Proof`].  It enforces
//! structural invariants before emitting the proof and relies on the canonical
//! serialization helpers from [`crate::proof::ser`] to derive the telemetry and
//! size metrics.

use crate::params::ProofParams;
pub use crate::proof::ser::{
    compute_commitment_digest, compute_integrity_digest, compute_public_digest,
    serialize_public_inputs,
};
use crate::proof::ser::{
    deserialize_out_of_domain_opening, deserialize_proof, serialize_out_of_domain_opening,
    serialize_proof, serialize_proof_header, serialize_proof_payload,
};
use crate::proof::types::{
    MerkleProofBundle, Openings, OutOfDomainOpening, Proof, Telemetry, VerifyError,
};
use crate::ser::{SerError, SerKind};
use crate::{
    config::{AirSpecId, ParamDigest, ProofKind},
    fri::FriProof,
    utils::serialization::DigestBytes,
};
use std::convert::TryInto;

/// Result emitted by [`ProofBuilder::build`].
#[derive(Debug, Clone)]
pub struct BuiltProof {
    /// Fully validated proof envelope ready for serialization.
    pub proof: Proof,
    /// Digest over the serialized public-input payload.
    pub public_digest: [u8; 32],
    /// Total byte length of the canonical header + payload + integrity digest.
    pub bytes_total: usize,
}

impl BuiltProof {
    /// Consumes the container and returns the inner [`Proof`].
    pub fn into_proof(self) -> Proof {
        self.proof
    }
}

#[derive(Debug, Clone)]
struct HeaderFields {
    version: u16,
    kind: ProofKind,
    param_digest: ParamDigest,
    air_spec_id: AirSpecId,
    public_inputs: Vec<u8>,
}

/// Builder used to assemble and validate proof envelopes.
#[derive(Debug, Clone)]
pub struct ProofBuilder {
    params: ProofParams,
    header: Option<HeaderFields>,
    merkle: Option<MerkleProofBundle>,
    openings: Option<Openings>,
    fri_proof: Option<FriProof>,
    telemetry: Option<Telemetry>,
}

impl ProofBuilder {
    /// Creates a builder scoped to the provided proof-parameter subset.
    pub fn new(params: ProofParams) -> Self {
        Self {
            params,
            header: None,
            merkle: None,
            openings: None,
            fri_proof: None,
            telemetry: None,
        }
    }

    /// Injects the header fields for the envelope.
    pub fn with_header(
        mut self,
        version: u16,
        kind: ProofKind,
        param_digest: ParamDigest,
        air_spec_id: AirSpecId,
        public_inputs: Vec<u8>,
    ) -> Self {
        self.header = Some(HeaderFields {
            version,
            kind,
            param_digest,
            air_spec_id,
            public_inputs,
        });
        self
    }

    /// Sets the Merkle bundle for the envelope body.
    pub fn with_merkle_bundle(mut self, merkle: MerkleProofBundle) -> Self {
        self.merkle = Some(merkle);
        self
    }

    /// Sets the out-of-domain openings section.
    pub fn with_openings(mut self, openings: Openings) -> Self {
        self.openings = Some(openings);
        self
    }

    /// Attaches the FRI proof payload for the envelope.
    pub fn with_fri_proof(mut self, fri_proof: FriProof) -> Self {
        self.fri_proof = Some(fri_proof);
        self
    }

    /// Sets the telemetry frame associated with the proof.
    pub fn with_telemetry(mut self, telemetry: Telemetry) -> Self {
        self.telemetry = Some(telemetry);
        self
    }

    /// Builds and validates the proof envelope, returning the assembled proof
    /// together with the derived digests and size metadata.
    pub fn build(self) -> Result<BuiltProof, VerifyError> {
        let header = self
            .header
            .ok_or(VerifyError::Serialization(SerKind::Proof))?;
        if header.version != self.params.version {
            return Err(VerifyError::VersionMismatch {
                expected: self.params.version,
                actual: header.version,
            });
        }

        let merkle = self
            .merkle
            .ok_or(VerifyError::Serialization(SerKind::TraceCommitment))?;
        let openings = self
            .openings
            .ok_or(VerifyError::Serialization(SerKind::Openings))?;
        let fri_proof = self
            .fri_proof
            .ok_or(VerifyError::Serialization(SerKind::Fri))?;
        let telemetry = self
            .telemetry
            .ok_or(VerifyError::Serialization(SerKind::Telemetry))?;

        if openings.out_of_domain.is_empty() {
            return Err(VerifyError::EmptyOpenings);
        }

        ensure_sorted_indices(&fri_proof)?;
        merkle.ensure_consistency(&fri_proof)?;

        let public_digest = compute_public_digest(&header.public_inputs);

        if openings.composition.is_some() && merkle.aux_root == [0u8; 32] {
            return Err(VerifyError::CompositionInconsistent {
                reason: "missing_composition_root".to_string(),
            });
        }

        if openings.composition.is_none() && merkle.aux_root != [0u8; 32] {
            return Err(VerifyError::CompositionInconsistent {
                reason: "unexpected_composition_root".to_string(),
            });
        }

        let mut proof = Proof {
            version: header.version,
            kind: header.kind,
            param_digest: header.param_digest,
            air_spec_id: header.air_spec_id,
            public_inputs: header.public_inputs,
            public_digest: DigestBytes {
                bytes: public_digest,
            },
            trace_commit: DigestBytes {
                bytes: merkle.core_root,
            },
            composition_commit: openings.composition.as_ref().map(|_| DigestBytes {
                bytes: merkle.aux_root,
            }),
            merkle,
            openings,
            fri_proof,
            has_telemetry: true,
            telemetry,
        };

        let payload = serialize_proof_payload(&proof).map_err(VerifyError::from)?;
        let header_bytes = serialize_proof_header(&proof, &payload).map_err(VerifyError::from)?;

        proof.telemetry.header_length = header_bytes.len() as u32;
        proof.telemetry.body_length = (payload.len() + 32) as u32;
        let integrity = compute_integrity_digest(&header_bytes, &payload);
        proof.telemetry.integrity_digest = DigestBytes { bytes: integrity };

        let bytes_total = header_bytes.len() + payload.len() + 32;
        let limit_bytes = (self.params.max_size_kb as usize) * 1024;
        if bytes_total > limit_bytes {
            let got_kb = ((bytes_total + 1023) / 1024) as u32;
            return Err(VerifyError::ProofTooLarge {
                max_kb: self.params.max_size_kb,
                got_kb,
            });
        }

        Ok(BuiltProof {
            proof,
            public_digest,
            bytes_total,
        })
    }
}

fn ensure_sorted_indices(fri_proof: &FriProof) -> Result<(), VerifyError> {
    let mut previous: Option<usize> = None;
    for query in &fri_proof.queries {
        if let Some(prev) = previous {
            if query.position <= prev {
                let index = query.position.try_into().unwrap_or(u32::MAX);
                return Err(VerifyError::IndicesDuplicate { index });
            }
        }
        previous = Some(query.position);
    }
    Ok(())
}

impl Proof {
    /// Serialises the proof into a byte vector using the canonical layout.
    ///
    /// Returns an error if canonical serialization fails.
    pub fn to_bytes(&self) -> Result<Vec<u8>, SerError> {
        serialize_proof(self)
    }

    /// Parses an envelope from a byte slice, validating all length prefixes and
    /// integrity digests along the way.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, VerifyError> {
        deserialize_proof(bytes)
    }

    /// Serialises the proof header for the provided payload.
    pub fn serialize_header(&self, payload: &[u8]) -> Result<Vec<u8>, SerError> {
        serialize_proof_header(self, payload)
    }

    /// Serialises the proof payload (body) without the trailing integrity digest.
    pub fn serialize_payload(&self) -> Result<Vec<u8>, SerError> {
        serialize_proof_payload(self)
    }
}

impl Openings {
    /// Serialises the out-of-domain openings using the canonical layout.
    pub fn serialize(&self) -> Result<Vec<u8>, SerError> {
        crate::proof::ser::serialize_openings(self)
    }
}

impl OutOfDomainOpening {
    /// Serialises the opening block using the canonical layout.
    pub fn serialize(&self) -> Result<Vec<u8>, SerError> {
        serialize_out_of_domain_opening(self)
    }

    /// Deserialises an opening block from its canonical layout.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, VerifyError> {
        deserialize_out_of_domain_opening(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        build_prover_context, compute_param_digest, ChunkingPolicy, ParamDigest, ProofKind,
        ProofSystemConfig, ThreadPoolProfile, COMMON_IDENTIFIERS, PROFILE_STANDARD_CONFIG,
        PROOF_VERSION_V1,
    };
    use crate::field::prime_field::{CanonicalSerialize, FieldElementOps};
    use crate::field::FieldElement;
    use crate::fri::{FriProof, FriQueryLayerProof, FriQueryProof, FriSecurityLevel};
    use crate::hash::merkle::{MerkleIndex, MerklePathElement, DIGEST_SIZE};
    use crate::params::ProofParams;
    use crate::proof::params::canonical_stark_params;
    use crate::proof::prover::build_envelope as build_proof_envelope;
    use crate::proof::public_inputs::{ExecutionHeaderV1, PublicInputVersion, PublicInputs};
    use crate::proof::types::{
        CompositionOpenings, FriParametersMirror, MerkleAuthenticationPath, MerklePathNode,
        TraceOpenings,
    };
    use crate::utils::serialization::{DigestBytes, WitnessBlob};

    fn sample_fri_proof() -> FriProof {
        let evaluations: Vec<FieldElement> =
            (0..1024).map(|i| FieldElement(i as u64 + 1)).collect();
        let seed = [7u8; 32];
        let params = canonical_stark_params(&PROFILE_STANDARD_CONFIG);
        FriProof::prove_with_params(FriSecurityLevel::Standard, seed, &evaluations, &params)
            .expect("fri proof")
    }

    fn builder_params() -> ProofParams {
        ProofParams {
            version: crate::proof::types::PROOF_VERSION,
            max_size_kb: 2048,
        }
    }

    const LFSR_ALPHA: u64 = 5;
    const LFSR_BETA: u64 = 7;

    fn lfsr_witness(seed: FieldElement, rows: usize) -> Vec<u8> {
        let alpha = FieldElement::from(LFSR_ALPHA);
        let beta = FieldElement::from(LFSR_BETA);
        let mut column = Vec::with_capacity(rows);
        let mut state = seed;
        column.push(state);
        for _ in 1..rows {
            state = state.mul(&alpha).add(&beta);
            column.push(state);
        }

        let mut bytes = Vec::with_capacity(20 + rows * 8);
        bytes.extend_from_slice(&(rows as u32).to_le_bytes());
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        for value in column {
            let encoded = value.to_bytes().expect("fixture values must be canonical");
            bytes.extend_from_slice(&encoded);
        }
        bytes
    }

    fn sample_public_inputs() -> Vec<u8> {
        let seed = FieldElement::from(11u64);
        let body_bytes = seed.to_bytes().expect("fixture seed must be canonical");
        let header = ExecutionHeaderV1 {
            version: PublicInputVersion::V1,
            program_digest: DigestBytes { bytes: [2u8; 32] },
            trace_length: 64,
            trace_width: 1,
        };
        let body_vec = body_bytes.to_vec();
        let public_inputs = PublicInputs::Execution {
            header,
            body: &body_vec,
        };
        crate::proof::ser::serialize_public_inputs(&public_inputs)
            .expect("public inputs serialization")
    }

    fn sample_openings() -> Openings {
        let trace = TraceOpenings {
            indices: vec![0, 2, 4],
            leaves: vec![vec![0x10, 0x11], vec![0x12], vec![0x13, 0x14, 0x15]],
            paths: vec![
                MerkleAuthenticationPath {
                    nodes: vec![MerklePathNode {
                        index: 0,
                        sibling: [0x21u8; 32],
                    }],
                },
                MerkleAuthenticationPath {
                    nodes: vec![MerklePathNode {
                        index: 1,
                        sibling: [0x22u8; 32],
                    }],
                },
                MerkleAuthenticationPath { nodes: Vec::new() },
            ],
        };
        let composition = Some(CompositionOpenings {
            indices: vec![0, 2],
            leaves: vec![vec![0x33], vec![0x34, 0x35]],
            paths: vec![MerkleAuthenticationPath { nodes: Vec::new() }; 2],
        });
        Openings {
            trace,
            composition,
            out_of_domain: vec![OutOfDomainOpening {
                point: [3u8; 32],
                core_values: vec![[4u8; 32]],
                aux_values: Vec::new(),
                composition_value: [5u8; 32],
            }],
        }
    }

    fn sample_telemetry(query_budget: u16, cap_size: u32) -> Telemetry {
        Telemetry {
            header_length: 0,
            body_length: 0,
            fri_parameters: FriParametersMirror {
                fold: 2,
                cap_degree: 0,
                cap_size,
                query_budget,
            },
            integrity_digest: DigestBytes::default(),
        }
    }

    fn fri_proof_with_positions(positions: &[usize]) -> FriProof {
        let layer_roots = vec![[11u8; 32]];
        let fold_challenges = vec![FieldElement::ZERO];
        let final_polynomial = vec![FieldElement::ZERO];
        let queries = positions
            .iter()
            .map(|&position| FriQueryProof {
                position,
                layers: vec![FriQueryLayerProof {
                    value: FieldElement::ZERO,
                    path: vec![MerklePathElement {
                        index: MerkleIndex(0),
                        siblings: [[12u8; DIGEST_SIZE]; 1],
                    }],
                }],
                final_value: FieldElement::ZERO,
            })
            .collect();

        FriProof::new(
            FriSecurityLevel::Standard,
            4,
            layer_roots,
            fold_challenges,
            final_polynomial,
            [13u8; 32],
            queries,
        )
        .expect("synthetic fri proof")
    }

    fn build_sample_proof() -> Proof {
        let fri_proof = sample_fri_proof();
        let core_root = fri_proof.layer_roots.first().copied().unwrap_or([0u8; 32]);
        let aux_root = [1u8; 32];
        let merkle = MerkleProofBundle::from_fri_proof(core_root, aux_root, &fri_proof)
            .expect("merkle consistency");
        let telemetry = sample_telemetry(
            fri_proof.security_level.query_budget() as u16,
            fri_proof.final_polynomial.len() as u32,
        );

        ProofBuilder::new(builder_params())
            .with_header(
                crate::proof::types::PROOF_VERSION,
                ProofKind::Tx,
                ParamDigest(DigestBytes { bytes: [6u8; 32] }),
                crate::config::AirSpecId(DigestBytes { bytes: [7u8; 32] }),
                sample_public_inputs(),
            )
            .with_merkle_bundle(merkle)
            .with_openings(sample_openings())
            .with_fri_proof(fri_proof)
            .with_telemetry(telemetry)
            .build()
            .expect("build sample proof")
            .proof
    }

    #[test]
    fn proof_round_trip() {
        let proof = build_sample_proof();
        let bytes = proof.to_bytes().expect("serialize proof");
        let decoded = Proof::from_bytes(&bytes).expect("decode proof");
        assert_eq!(proof, decoded);
    }

    #[test]
    fn serialize_public_inputs_execution() {
        let header = ExecutionHeaderV1 {
            version: PublicInputVersion::V1,
            program_digest: DigestBytes { bytes: [9u8; 32] },
            trace_length: 1024,
            trace_width: 16,
        };
        let body_bytes = vec![1u8, 2, 3, 4];
        let inputs = PublicInputs::Execution {
            header,
            body: &body_bytes,
        };

        let encoded = serialize_public_inputs(&inputs).expect("public inputs serialization");
        assert!(!encoded.is_empty());
    }

    #[test]
    fn builder_rejects_empty_openings() {
        let fri_proof = fri_proof_with_positions(&[0]);
        let core_root = fri_proof.layer_roots.first().copied().unwrap();
        let merkle = MerkleProofBundle::from_fri_proof(core_root, [22u8; 32], &fri_proof)
            .expect("consistent merkle roots");
        let telemetry = sample_telemetry(1, 1);

        let result = ProofBuilder::new(builder_params())
            .with_header(
                crate::proof::types::PROOF_VERSION,
                ProofKind::Tx,
                ParamDigest(DigestBytes { bytes: [1u8; 32] }),
                crate::config::AirSpecId(DigestBytes { bytes: [2u8; 32] }),
                sample_public_inputs(),
            )
            .with_merkle_bundle(merkle)
            .with_openings({
                let mut openings = sample_openings();
                openings.out_of_domain.clear();
                openings
            })
            .with_fri_proof(fri_proof)
            .with_telemetry(telemetry)
            .build();

        assert!(matches!(result, Err(VerifyError::EmptyOpenings)));
    }

    #[test]
    fn builder_rejects_unsorted_indices() {
        let fri_proof = fri_proof_with_positions(&[1, 0]);
        let core_root = fri_proof.layer_roots.first().copied().unwrap();
        let merkle = MerkleProofBundle::from_fri_proof(core_root, [32u8; 32], &fri_proof)
            .expect("consistent merkle roots");
        let telemetry = sample_telemetry(1, 1);

        let result = ProofBuilder::new(builder_params())
            .with_header(
                crate::proof::types::PROOF_VERSION,
                ProofKind::Tx,
                ParamDigest(DigestBytes { bytes: [3u8; 32] }),
                crate::config::AirSpecId(DigestBytes { bytes: [4u8; 32] }),
                sample_public_inputs(),
            )
            .with_merkle_bundle(merkle)
            .with_openings(sample_openings())
            .with_fri_proof(fri_proof)
            .with_telemetry(telemetry)
            .build();

        assert!(matches!(result, Err(VerifyError::IndicesDuplicate { .. })));
    }

    #[test]
    fn builder_rejects_large_proofs() {
        let fri_proof = sample_fri_proof();
        let core_root = fri_proof.layer_roots.first().copied().unwrap();
        let merkle = MerkleProofBundle::from_fri_proof(core_root, [0xabu8; 32], &fri_proof)
            .expect("consistent merkle roots");
        let telemetry = sample_telemetry(
            fri_proof.security_level.query_budget() as u16,
            fri_proof.final_polynomial.len() as u32,
        );

        let params = ProofParams {
            version: crate::proof::types::PROOF_VERSION,
            max_size_kb: 1,
        };
        let result = ProofBuilder::new(params)
            .with_header(
                crate::proof::types::PROOF_VERSION,
                ProofKind::Tx,
                ParamDigest(DigestBytes { bytes: [8u8; 32] }),
                crate::config::AirSpecId(DigestBytes { bytes: [9u8; 32] }),
                sample_public_inputs(),
            )
            .with_merkle_bundle(merkle)
            .with_openings(sample_openings())
            .with_fri_proof(fri_proof)
            .with_telemetry(telemetry)
            .build();

        assert!(matches!(result, Err(VerifyError::ProofTooLarge { .. })));
    }

    #[test]
    fn envelope_spec_documentation() {
        let param_digest = compute_param_digest(&PROFILE_STANDARD_CONFIG, &COMMON_IDENTIFIERS);
        let config = ProofSystemConfig {
            proof_version: PROOF_VERSION_V1,
            profile: PROFILE_STANDARD_CONFIG.clone(),
            param_digest: param_digest.clone(),
        };
        let context = build_prover_context(
            &PROFILE_STANDARD_CONFIG,
            &COMMON_IDENTIFIERS,
            &param_digest,
            ThreadPoolProfile::SingleThread,
            ChunkingPolicy {
                min_chunk_items: 1,
                max_chunk_items: 1,
                stride: 1,
            },
        );

        let seed = FieldElement::from(13u64);
        let seed_bytes = seed.to_bytes().expect("fixture seed must be canonical");
        let public_inputs = PublicInputs::Execution {
            header: ExecutionHeaderV1 {
                version: PublicInputVersion::V1,
                program_digest: DigestBytes { bytes: [10u8; 32] },
                trace_length: 64,
                trace_width: 1,
            },
            body: &seed_bytes,
        };
        let witness_bytes = lfsr_witness(seed, 64);

        let envelope = build_proof_envelope(
            &public_inputs,
            WitnessBlob {
                bytes: &witness_bytes,
            },
            &config,
            &context,
        );

        assert!(envelope.is_ok(), "{:?}", envelope);
    }
}
