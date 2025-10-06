//! Proof envelope implementation and serialization helpers.
//!
//! This module intentionally keeps the implementation surface minimal by
//! delegating the heavy lifting to [`crate::proof::ser`].  The thin wrappers
//! exposed here exist purely for ergonomic access on [`crate::proof::types::Proof`]
//! and related structures.

pub use crate::proof::ser::{
    compute_commitment_digest, compute_integrity_digest, serialize_public_inputs,
};
use crate::proof::ser::{
    deserialize_out_of_domain_opening, deserialize_proof, serialize_out_of_domain_opening,
    serialize_proof, serialize_proof_header, serialize_proof_payload,
};
use crate::proof::types::{Openings, OutOfDomainOpening, Proof, VerifyError};

impl Proof {
    /// Serialises the proof into a byte vector using the canonical layout.
    pub fn to_bytes(&self) -> Vec<u8> {
        serialize_proof(self)
    }

    /// Parses an envelope from a byte slice, validating all length prefixes and
    /// integrity digests along the way.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, VerifyError> {
        deserialize_proof(bytes)
    }

    /// Serialises the proof header for the provided payload.
    pub fn serialize_header(&self, payload: &[u8]) -> Vec<u8> {
        serialize_proof_header(self, payload)
    }

    /// Serialises the proof payload (body) without the trailing integrity digest.
    pub fn serialize_payload(&self) -> Vec<u8> {
        serialize_proof_payload(self)
    }
}

impl Openings {
    /// Serialises the out-of-domain openings using the canonical layout.
    pub fn serialize(&self) -> Vec<u8> {
        crate::proof::ser::serialize_openings(self)
    }
}

impl OutOfDomainOpening {
    /// Serialises the opening block using the canonical layout.
    pub fn serialize(&self) -> Vec<u8> {
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
    use crate::field::FieldElement;
    use crate::fri::{FriProof, FriSecurityLevel};
    use crate::proof::prover::build_envelope as build_proof_envelope;
    use crate::proof::public_inputs::{ExecutionHeaderV1, PublicInputVersion, PublicInputs};
    use crate::utils::serialization::{DigestBytes, WitnessBlob};

    fn sample_fri_proof() -> FriProof {
        let evaluations: Vec<FieldElement> =
            (0..1024).map(|i| FieldElement(i as u64 + 1)).collect();
        let seed = [7u8; 32];
        FriProof::prove(FriSecurityLevel::Standard, seed, &evaluations).expect("fri proof")
    }

    fn build_sample_proof() -> Proof {
        let fri_proof = sample_fri_proof();
        let fri_layer_roots = fri_proof.layer_roots.clone();
        let core_root = fri_layer_roots.first().copied().unwrap_or([0u8; 32]);
        let aux_root = [1u8; 32];
        let commitment_digest = compute_commitment_digest(&core_root, &aux_root, &fri_layer_roots);

        let header = ExecutionHeaderV1 {
            version: PublicInputVersion::V1,
            program_digest: DigestBytes { bytes: [2u8; 32] },
            trace_length: 1024,
            trace_width: 16,
        };
        let body_bytes: Vec<u8> = Vec::new();
        let public_inputs = PublicInputs::Execution {
            header: header.clone(),
            body: &body_bytes,
        };
        let public_input_bytes = crate::proof::ser::serialize_public_inputs(&public_inputs);

        let merkle = crate::proof::types::MerkleProofBundle {
            core_root,
            aux_root,
            fri_layer_roots,
        };
        let openings = Openings {
            out_of_domain: vec![OutOfDomainOpening {
                point: [3u8; 32],
                core_values: vec![[4u8; 32]],
                aux_values: Vec::new(),
                composition_value: [5u8; 32],
            }],
        };
        let telemetry = crate::proof::types::Telemetry {
            header_length: 0,
            body_length: 0,
            fri_parameters: crate::proof::types::FriParametersMirror::default(),
            integrity_digest: DigestBytes::default(),
        };

        Proof {
            version: PROOF_VERSION_V1 as u16,
            kind: ProofKind::Tx,
            param_digest: ParamDigest(DigestBytes { bytes: [6u8; 32] }),
            air_spec_id: crate::config::AirSpecId(DigestBytes { bytes: [7u8; 32] }),
            public_inputs: public_input_bytes,
            commitment_digest,
            merkle,
            openings,
            fri_proof,
            telemetry,
        }
    }

    #[test]
    fn proof_round_trip() {
        let proof = build_sample_proof();
        let bytes = proof.to_bytes();
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

        let encoded = serialize_public_inputs(&inputs);
        assert!(!encoded.is_empty());
    }

    #[test]
    fn envelope_spec_documentation() {
        let config = ProofSystemConfig {
            proof_version: crate::config::ProofVersion(PROOF_VERSION_V1),
            param_digest: compute_param_digest(&PROFILE_STANDARD_CONFIG),
            thread_pool: ThreadPoolProfile::default(),
            chunking: ChunkingPolicy::Single,
        };
        let context = build_prover_context(
            &COMMON_IDENTIFIERS,
            &PROFILE_STANDARD_CONFIG,
            WitnessBlob { bytes: &[] },
        );

        let envelope = build_proof_envelope(
            &config,
            &context,
            ProofKind::Tx,
            PublicInputs::Execution {
                header: ExecutionHeaderV1 {
                    version: PublicInputVersion::V1,
                    program_digest: DigestBytes { bytes: [10u8; 32] },
                    trace_length: 1024,
                    trace_width: 16,
                },
                body: &[],
            },
        );

        assert!(envelope.is_ok());
    }
}
