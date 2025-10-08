use insta::assert_snapshot;
use rpp_stark::config::{AirSpecId, ParamDigest, ProofKind, PROFILE_STANDARD_CONFIG};
use rpp_stark::field::FieldElement;
use rpp_stark::fri::{FriProof, FriSecurityLevel};
use rpp_stark::merkle::{
    decode_proof as decode_merkle_proof, encode_proof as encode_merkle_proof, Digest, MerkleError,
    MerkleProof, ProofNode,
};
use rpp_stark::proof::params::canonical_stark_params;
use rpp_stark::proof::public_inputs::{ExecutionHeaderV1, PublicInputVersion, PublicInputs};
use rpp_stark::proof::ser::{
    compute_integrity_digest, deserialize_proof, serialize_proof, serialize_proof_header,
    serialize_proof_payload,
};
use rpp_stark::proof::types::{
    CompositionOpenings, FriParametersMirror, MerkleAuthenticationPath, MerklePathNode,
    MerkleProofBundle, Openings, OutOfDomainOpening, Proof, Telemetry, TraceOpenings,
    PROOF_VERSION,
};
use rpp_stark::ser::SerKind;
use rpp_stark::utils::serialization::DigestBytes;
use rpp_stark::VerifyError;

fn sample_merkle_proof() -> MerkleProof {
    MerkleProof {
        version: 1,
        arity: rpp_stark::params::MerkleArity::Binary,
        leaf_encoding: rpp_stark::params::Endianness::Little,
        path: vec![ProofNode::Arity2([Digest::new(vec![0x11; 32])])],
        indices: vec![0, 2],
        leaf_width: 2,
        domain_sep: 0xdead_beef,
        leaf_width_bytes: 16,
        digest_size: 32,
    }
}

fn sample_fri_proof() -> FriProof {
    let evaluations: Vec<FieldElement> = (0..32).map(|i| FieldElement(i as u64 + 1)).collect();
    let seed = [7u8; 32];
    let params = canonical_stark_params(&PROFILE_STANDARD_CONFIG);
    FriProof::prove_with_params(FriSecurityLevel::Standard, seed, &evaluations, &params)
        .expect("fri proof")
}

fn sample_proof() -> Proof {
    let fri_proof = sample_fri_proof();
    let fri_layer_roots = fri_proof.layer_roots.clone();
    let core_root = fri_layer_roots.first().copied().unwrap_or([0u8; 32]);
    let aux_root = [1u8; 32];

    let header = ExecutionHeaderV1 {
        version: PublicInputVersion::V1,
        program_digest: DigestBytes { bytes: [2u8; 32] },
        trace_length: 64,
        trace_width: 4,
    };
    let body_bytes = vec![1, 2, 3, 4];
    let public_inputs = PublicInputs::Execution {
        header: header.clone(),
        body: &body_bytes,
    };
    let public_input_bytes = rpp_stark::proof::ser::serialize_public_inputs(&public_inputs)
        .expect("public inputs serialization");
    let public_digest = rpp_stark::proof::ser::compute_public_digest(&public_input_bytes);

    let merkle = MerkleProofBundle {
        core_root,
        aux_root,
        fri_layer_roots,
    };
    let trace = TraceOpenings {
        indices: vec![0, 3],
        leaves: vec![vec![0xaa], vec![0xbb, 0xcc]],
        paths: vec![
            MerkleAuthenticationPath {
                nodes: vec![MerklePathNode {
                    index: 0,
                    sibling: [0x44u8; 32],
                }],
            },
            MerkleAuthenticationPath {
                nodes: vec![MerklePathNode {
                    index: 1,
                    sibling: [0x55u8; 32],
                }],
            },
        ],
    };
    let composition = Some(CompositionOpenings {
        indices: vec![0],
        leaves: vec![vec![0xdd, 0xee, 0xff]],
        paths: vec![MerkleAuthenticationPath { nodes: Vec::new() }],
    });
    let openings = Openings {
        trace,
        composition,
        out_of_domain: vec![OutOfDomainOpening {
            point: [3u8; 32],
            core_values: vec![[4u8; 32]],
            aux_values: Vec::new(),
            composition_value: [5u8; 32],
        }],
    };

    let mut proof = Proof {
        version: PROOF_VERSION,
        kind: ProofKind::Tx,
        param_digest: ParamDigest(DigestBytes { bytes: [6u8; 32] }),
        air_spec_id: AirSpecId(DigestBytes { bytes: [7u8; 32] }),
        public_inputs: public_input_bytes,
        public_digest: DigestBytes {
            bytes: public_digest,
        },
        trace_commit: DigestBytes { bytes: core_root },
        composition_commit: Some(DigestBytes { bytes: aux_root }),
        merkle,
        openings,
        fri_proof,
        has_telemetry: true,
        telemetry: Telemetry {
            header_length: 0,
            body_length: 0,
            fri_parameters: FriParametersMirror {
                fold: 2,
                cap_degree: 0,
                cap_size: 0,
                query_budget: 0,
            },
            integrity_digest: DigestBytes::default(),
        },
    };

    let payload = serialize_proof_payload(&proof).expect("proof payload serialization");
    let header_bytes =
        serialize_proof_header(&proof, &payload).expect("proof header serialization");
    let integrity = compute_integrity_digest(&header_bytes, &payload);
    proof.telemetry.header_length = header_bytes.len() as u32;
    proof.telemetry.body_length = (payload.len() + 32) as u32;
    proof.telemetry.integrity_digest = DigestBytes { bytes: integrity };
    proof
}

#[test]
fn merkle_proof_roundtrip_and_snapshot() {
    let proof = sample_merkle_proof();
    let bytes = encode_merkle_proof(&proof).expect("encode merkle proof");
    let decoded = decode_merkle_proof(&bytes).expect("decode merkle proof");
    assert_eq!(decoded, proof);
    let hex = bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(" ");
    assert_snapshot!("merkle_proof_bytes", hex);
}

#[test]
fn merkle_proof_decode_failure_on_truncation() {
    let proof = sample_merkle_proof();
    let mut bytes = encode_merkle_proof(&proof).expect("encode merkle proof");
    bytes.truncate(bytes.len() - 1);
    let err = decode_merkle_proof(&bytes).expect_err("should fail");
    assert!(matches!(err, MerkleError::Serialization(_)));
}

#[test]
fn fri_proof_roundtrip_and_snapshot() {
    let proof = sample_fri_proof();
    let bytes = proof.to_bytes().expect("fri to bytes");
    let decoded = FriProof::from_bytes(&bytes).expect("fri from bytes");
    assert_eq!(decoded.layer_roots, proof.layer_roots);
    let hex = bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(" ");
    assert_snapshot!("fri_proof_bytes", hex);
}

#[test]
fn fri_proof_decode_failure() {
    let proof = sample_fri_proof();
    let mut bytes = proof.to_bytes().expect("fri to bytes");
    bytes.pop();
    assert!(FriProof::from_bytes(&bytes).is_err());
}

#[test]
fn proof_roundtrip_and_snapshot() {
    let proof = sample_proof();
    let bytes = serialize_proof(&proof).expect("serialize proof");
    let decoded = deserialize_proof(&bytes).expect("decode proof");
    assert_eq!(decoded, proof);
    let hex = bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(" ");
    assert_snapshot!("proof_bytes", hex);
}

#[test]
fn proof_deserialize_failure_on_truncation() {
    let proof = sample_proof();
    let mut bytes = serialize_proof(&proof).expect("serialize proof");
    bytes.truncate(bytes.len() - 1);
    let err = deserialize_proof(&bytes).expect_err("should fail");
    assert!(matches!(
        err,
        VerifyError::Serialization(SerKind::Telemetry)
    ));
}

#[test]
fn proof_public_input_digest_mismatch() {
    let proof = sample_proof();
    let mut bytes = serialize_proof(&proof).expect("serialize proof");
    let body = [1u8, 2, 3, 4];
    if let Some(position) = bytes.windows(body.len()).position(|window| window == body) {
        bytes[position + body.len() - 1] ^= 0xff;
    } else {
        panic!("public input body not found in serialized proof");
    }
    let err = deserialize_proof(&bytes).expect_err("digest mismatch");
    assert!(matches!(err, VerifyError::PublicDigestMismatch));
}
