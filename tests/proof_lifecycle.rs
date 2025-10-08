use rpp_stark::config::{
    build_proof_system_config, build_prover_context, build_verifier_context, compute_param_digest,
    ChunkingPolicy, CommonIdentifiers, ParamDigest, ProfileConfig, ProofSystemConfig,
    ProverContext, ThreadPoolProfile, VerifierContext, COMMON_IDENTIFIERS, PROFILE_STANDARD_CONFIG,
};
use rpp_stark::field::prime_field::{CanonicalSerialize, FieldElementOps};
use rpp_stark::field::FieldElement;
use rpp_stark::proof::public_inputs::{
    ExecutionHeaderV1, ProofKind, PublicInputVersion, PublicInputs,
};
use rpp_stark::proof::ser::serialize_proof;
use rpp_stark::proof::types::{MerkleSection, VerifyError, PROOF_VERSION};
use rpp_stark::utils::serialization::{DigestBytes, ProofBytes, WitnessBlob};
use rpp_stark::{
    batch_verify, generate_proof, verify_proof, BatchProofRecord, BatchVerificationOutcome,
    BlockContext, StarkError, VerificationVerdict,
};

struct TestSetup {
    config: ProofSystemConfig,
    prover_context: ProverContext,
    verifier_context: VerifierContext,
    header: ExecutionHeaderV1,
    body: Vec<u8>,
    witness: Vec<u8>,
}

impl TestSetup {
    fn new() -> Self {
        let profile: ProfileConfig = PROFILE_STANDARD_CONFIG.clone();
        let common: CommonIdentifiers = COMMON_IDENTIFIERS.clone();
        let param_digest = compute_param_digest(&profile, &common);
        let config = build_proof_system_config(&profile, &param_digest);
        let prover_context = build_prover_context(
            &profile,
            &common,
            &param_digest,
            ThreadPoolProfile::SingleThread,
            ChunkingPolicy {
                min_chunk_items: 4,
                max_chunk_items: 32,
                stride: 1,
            },
        );
        let verifier_context = build_verifier_context(&profile, &common, &param_digest, None);

        let seed = FieldElement::from(3u64);
        let length = 128usize;
        let header = ExecutionHeaderV1 {
            version: PublicInputVersion::V1,
            program_digest: DigestBytes { bytes: [0u8; 32] },
            trace_length: length as u32,
            trace_width: 1,
        };
        let body = seed.to_bytes().to_vec();
        let witness = build_witness(seed, length);

        Self {
            config,
            prover_context,
            verifier_context,
            header,
            body,
            witness,
        }
    }
}

const LFSR_ALPHA: u64 = 5;
const LFSR_BETA: u64 = 7;

fn build_witness(seed: FieldElement, rows: usize) -> Vec<u8> {
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
        bytes.extend_from_slice(&value.to_bytes());
    }
    bytes
}

fn make_public_inputs<'a>(header: &'a ExecutionHeaderV1, body: &'a [u8]) -> PublicInputs<'a> {
    PublicInputs::Execution {
        header: header.clone(),
        body,
    }
}

#[test]
fn proof_lifecycle_accepts_valid_inputs() {
    let setup = TestSetup::new();
    let witness = WitnessBlob {
        bytes: &setup.witness,
    };

    let public_inputs = make_public_inputs(&setup.header, &setup.body);
    let proof = generate_proof(
        ProofKind::Execution,
        &public_inputs,
        witness,
        &setup.config,
        &setup.prover_context,
    )
    .expect("proof generation succeeds");
    let decoded = rpp_stark::Proof::from_bytes(proof.as_slice()).expect("decode proof");
    assert_eq!(
        decoded.fri_proof.queries.len(),
        setup.config.profile.fri_queries as usize,
        "unexpected query count"
    );

    assert_eq!(
        decoded.openings.trace.indices.len(),
        decoded.openings.trace.leaves.len(),
        "trace openings must align",
    );
    assert!(
        decoded
            .openings
            .trace
            .leaves
            .iter()
            .all(|leaf| !leaf.is_empty()),
        "trace leaves must contain bytes",
    );
    let composition = decoded
        .openings
        .composition
        .as_ref()
        .expect("composition openings present");
    assert_eq!(
        composition.indices.len(),
        composition.leaves.len(),
        "composition openings must align",
    );
    assert!(
        composition.leaves.iter().all(|leaf| !leaf.is_empty()),
        "composition leaves must contain bytes",
    );

    let verify_inputs = make_public_inputs(&setup.header, &setup.body);
    let verdict = verify_proof(
        ProofKind::Execution,
        &verify_inputs,
        &proof,
        &setup.config,
        &setup.verifier_context,
    )
    .expect("verification verdict");
    match verdict {
        VerificationVerdict::Accept => {}
        VerificationVerdict::Reject(err) => {
            panic!("expected verification to accept, got {:?}", err);
        }
    }
}

#[test]
fn verification_rejects_mismatched_public_inputs() {
    let setup = TestSetup::new();
    let witness = WitnessBlob {
        bytes: &setup.witness,
    };
    let public_inputs = make_public_inputs(&setup.header, &setup.body);
    let proof = generate_proof(
        ProofKind::Execution,
        &public_inputs,
        witness,
        &setup.config,
        &setup.prover_context,
    )
    .expect("proof generation succeeds");

    let mut mismatched_header = setup.header.clone();
    mismatched_header.trace_length += 1;
    let bad_inputs = make_public_inputs(&mismatched_header, &setup.body);
    let verdict = verify_proof(
        ProofKind::Execution,
        &bad_inputs,
        &proof,
        &setup.config,
        &setup.verifier_context,
    )
    .expect("verification verdict");
    assert!(matches!(
        verdict,
        VerificationVerdict::Reject(VerifyError::PublicInputMismatch)
    ));

    let record = BatchProofRecord {
        kind: ProofKind::Execution,
        public_inputs: &bad_inputs,
        proof_bytes: &proof,
    };
    let block_context = BlockContext {
        block_height: 7,
        previous_state_root: [1u8; 32],
        network_id: 7,
    };
    let outcome = batch_verify(
        &block_context,
        &[record],
        &setup.config,
        &setup.verifier_context,
    )
    .expect("batch verification");
    assert!(matches!(
        outcome,
        BatchVerificationOutcome::Reject {
            failing_proof_index: 0,
            error: VerifyError::PublicInputMismatch,
        }
    ));
}

#[test]
fn verification_rejects_tampered_trace_leaf() {
    let setup = TestSetup::new();
    let witness = WitnessBlob {
        bytes: &setup.witness,
    };
    let public_inputs = make_public_inputs(&setup.header, &setup.body);
    let proof_bytes = generate_proof(
        ProofKind::Execution,
        &public_inputs,
        witness,
        &setup.config,
        &setup.prover_context,
    )
    .expect("proof generation succeeds");

    let mut proof = rpp_stark::Proof::from_bytes(proof_bytes.as_slice()).expect("decode proof");
    proof.openings.trace.leaves[0][0] ^= 1;
    let mutated = serialize_proof(&proof).expect("serialize proof");
    let mutated_bytes = ProofBytes::new(mutated);

    let verify_inputs = make_public_inputs(&setup.header, &setup.body);
    let verdict = verify_proof(
        ProofKind::Execution,
        &verify_inputs,
        &mutated_bytes,
        &setup.config,
        &setup.verifier_context,
    )
    .expect("verification verdict");

    match verdict {
        VerificationVerdict::Reject(VerifyError::MerkleVerifyFailed { section }) => {
            assert_eq!(section, MerkleSection::TraceCommit);
        }
        other => panic!("unexpected verdict: {other:?}"),
    }
}

#[test]
fn verification_rejects_tampered_composition_leaf() {
    let setup = TestSetup::new();
    let witness = WitnessBlob {
        bytes: &setup.witness,
    };
    let public_inputs = make_public_inputs(&setup.header, &setup.body);
    let proof_bytes = generate_proof(
        ProofKind::Execution,
        &public_inputs,
        witness,
        &setup.config,
        &setup.prover_context,
    )
    .expect("proof generation succeeds");

    let mut proof = rpp_stark::Proof::from_bytes(proof_bytes.as_slice()).expect("decode proof");
    let composition = proof
        .openings
        .composition
        .as_mut()
        .expect("composition openings present");
    composition.leaves[0][0] ^= 1;
    let mutated = serialize_proof(&proof).expect("serialize proof");
    let mutated_bytes = ProofBytes::new(mutated);

    let verify_inputs = make_public_inputs(&setup.header, &setup.body);
    let verdict = verify_proof(
        ProofKind::Execution,
        &verify_inputs,
        &mutated_bytes,
        &setup.config,
        &setup.verifier_context,
    )
    .expect("verification verdict");

    match verdict {
        VerificationVerdict::Reject(VerifyError::MerkleVerifyFailed { section }) => {
            assert_eq!(section, MerkleSection::CompositionCommit);
        }
        other => panic!("unexpected verdict: {other:?}"),
    }
}

#[test]
fn verification_rejects_tampered_ood_values() {
    let setup = TestSetup::new();
    let witness = WitnessBlob {
        bytes: &setup.witness,
    };
    let public_inputs = make_public_inputs(&setup.header, &setup.body);
    let proof_bytes = generate_proof(
        ProofKind::Execution,
        &public_inputs,
        witness,
        &setup.config,
        &setup.prover_context,
    )
    .expect("proof generation succeeds");

    let mut proof = rpp_stark::Proof::from_bytes(proof_bytes.as_slice()).expect("decode proof");
    if let Some(first) = proof.openings.out_of_domain.first_mut() {
        first.composition_value[0] ^= 1;
    }
    let mutated = serialize_proof(&proof).expect("serialize proof");
    let mutated_bytes = ProofBytes::new(mutated);

    let verify_inputs = make_public_inputs(&setup.header, &setup.body);
    let verdict = verify_proof(
        ProofKind::Execution,
        &verify_inputs,
        &mutated_bytes,
        &setup.config,
        &setup.verifier_context,
    )
    .expect("verification verdict");

    match verdict {
        VerificationVerdict::Reject(VerifyError::CompositionOodMismatch) => {}
        other => panic!("unexpected verdict: {other:?}"),
    }
}

#[test]
fn verification_rejects_trace_indices_not_sorted() {
    let setup = TestSetup::new();
    let witness = WitnessBlob {
        bytes: &setup.witness,
    };
    let public_inputs = make_public_inputs(&setup.header, &setup.body);
    let proof = generate_proof(
        ProofKind::Execution,
        &public_inputs,
        witness,
        &setup.config,
        &setup.prover_context,
    )
    .expect("proof generation succeeds");

    let mut decoded = rpp_stark::Proof::from_bytes(proof.as_slice()).expect("decode proof");
    if decoded.openings.trace.indices.len() < 2 {
        panic!("expected at least two trace indices");
    }
    decoded.openings.trace.indices.swap(0, 1);
    let mutated_bytes = serialize_proof(&decoded).expect("serialize mutated proof");
    let mutated = ProofBytes::new(mutated_bytes);

    let verdict = verify_proof(
        ProofKind::Execution,
        &public_inputs,
        &mutated,
        &setup.config,
        &setup.verifier_context,
    )
    .expect("verification verdict");

    assert!(matches!(
        verdict,
        VerificationVerdict::Reject(VerifyError::IndicesNotSorted)
    ));
}

#[test]
fn verification_rejects_trace_indices_duplicate() {
    let setup = TestSetup::new();
    let witness = WitnessBlob {
        bytes: &setup.witness,
    };
    let public_inputs = make_public_inputs(&setup.header, &setup.body);
    let proof = generate_proof(
        ProofKind::Execution,
        &public_inputs,
        witness,
        &setup.config,
        &setup.prover_context,
    )
    .expect("proof generation succeeds");

    let mut decoded = rpp_stark::Proof::from_bytes(proof.as_slice()).expect("decode proof");
    if decoded.openings.trace.indices.len() < 2 {
        panic!("expected at least two trace indices");
    }
    decoded.openings.trace.indices[1] = decoded.openings.trace.indices[0];
    let mutated_bytes = serialize_proof(&decoded).expect("serialize mutated proof");
    let mutated = ProofBytes::new(mutated_bytes);

    let verdict = verify_proof(
        ProofKind::Execution,
        &public_inputs,
        &mutated,
        &setup.config,
        &setup.verifier_context,
    )
    .expect("verification verdict");

    assert!(matches!(
        verdict,
        VerificationVerdict::Reject(VerifyError::IndicesDuplicate)
    ));
}

#[test]
fn verification_rejects_trace_indices_mismatch() {
    let setup = TestSetup::new();
    let witness = WitnessBlob {
        bytes: &setup.witness,
    };
    let public_inputs = make_public_inputs(&setup.header, &setup.body);
    let proof = generate_proof(
        ProofKind::Execution,
        &public_inputs,
        witness,
        &setup.config,
        &setup.prover_context,
    )
    .expect("proof generation succeeds");

    let mut decoded = rpp_stark::Proof::from_bytes(proof.as_slice()).expect("decode proof");
    for index in &mut decoded.openings.trace.indices {
        *index = index.saturating_add(1);
    }
    let mutated_bytes = serialize_proof(&decoded).expect("serialize mutated proof");
    let mutated = ProofBytes::new(mutated_bytes);

    let verdict = verify_proof(
        ProofKind::Execution,
        &public_inputs,
        &mutated,
        &setup.config,
        &setup.verifier_context,
    )
    .expect("verification verdict");

    assert!(matches!(
        verdict,
        VerificationVerdict::Reject(VerifyError::IndicesMismatch)
    ));
}

#[test]
fn batch_verify_accepts_empty_batch() {
    let setup = TestSetup::new();
    let block_context = BlockContext {
        block_height: 0,
        previous_state_root: [0u8; 32],
        network_id: 0,
    };
    let outcome = batch_verify(&block_context, &[], &setup.config, &setup.verifier_context)
        .expect("empty batch should succeed");
    assert_eq!(outcome, BatchVerificationOutcome::Accept);
}

#[test]
fn generate_proof_propagates_param_digest_mismatch() {
    let setup = TestSetup::new();
    let mut wrong_config = setup.config.clone();
    wrong_config.param_digest = ParamDigest(DigestBytes { bytes: [1u8; 32] });

    let witness = WitnessBlob {
        bytes: &setup.witness,
    };
    let public_inputs = make_public_inputs(&setup.header, &setup.body);

    let error = generate_proof(
        ProofKind::Execution,
        &public_inputs,
        witness,
        &wrong_config,
        &setup.prover_context,
    )
    .expect_err("param digest mismatch propagates");
    assert!(matches!(
        error,
        StarkError::InvalidInput("prover_param_digest_mismatch")
    ));
}

#[test]
fn verify_proof_reports_decode_failures() {
    let setup = TestSetup::new();
    let witness = WitnessBlob {
        bytes: &setup.witness,
    };
    let public_inputs = make_public_inputs(&setup.header, &setup.body);
    let proof = generate_proof(
        ProofKind::Execution,
        &public_inputs,
        witness,
        &setup.config,
        &setup.prover_context,
    )
    .expect("proof generation succeeds");

    let mut corrupted_bytes = proof.as_slice().to_vec();
    if let Some(first) = corrupted_bytes.first_mut() {
        *first ^= 0xFF;
    }
    let corrupted = ProofBytes::new(corrupted_bytes);
    let verify_inputs = make_public_inputs(&setup.header, &setup.body);
    let result = verify_proof(
        ProofKind::Execution,
        &verify_inputs,
        &corrupted,
        &setup.config,
        &setup.verifier_context,
    );

    match result.expect_err("verification should fail") {
        StarkError::InvalidInput(label) => {
            assert_eq!(label, "version_mismatch");
        }
        other => panic!("unexpected error: {other:?}"),
    }

    assert_eq!(PROOF_VERSION, setup.config.proof_version.0 as u16);
}
