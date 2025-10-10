use std::convert::TryInto;

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
use rpp_stark::proof::ser::{
    compute_integrity_digest, compute_public_digest, map_public_to_config_kind, serialize_proof,
};
use rpp_stark::proof::types::{FriVerifyIssue, MerkleSection, Proof, VerifyError, PROOF_VERSION};
use rpp_stark::utils::serialization::{DigestBytes, ProofBytes, WitnessBlob};
use rpp_stark::{
    batch_verify, generate_proof, verify_proof, BatchProofRecord, BatchVerificationOutcome,
    BlockContext, StarkError, VerificationVerdict,
};

#[allow(dead_code)]
#[path = "fail_matrix/fixture.rs"]
mod fail_matrix_fixture;

use fail_matrix_fixture::{
    flip_composition_leaf_byte, perturb_fri_fold_challenge, FailMatrixFixture,
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
        let body = seed
            .to_bytes()
            .expect("fixture seed must be canonical")
            .to_vec();
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
        let encoded = value.to_bytes().expect("fixture values must be canonical");
        bytes.extend_from_slice(&encoded);
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
        decoded.fri_proof().queries.len(),
        setup.config.profile.fri_queries as usize,
        "unexpected query count"
    );

    let openings = decoded.openings();
    assert_eq!(
        openings.trace().indices().len(),
        openings.trace().leaves().len(),
        "trace openings must align",
    );
    assert!(
        openings
            .trace()
            .leaves()
            .iter()
            .all(|leaf| !leaf.is_empty()),
        "trace leaves must contain bytes",
    );
    let composition = openings
        .composition()
        .expect("composition openings present");
    assert_eq!(
        composition.indices().len(),
        composition.leaves().len(),
        "composition openings must align",
    );
    assert!(
        composition.leaves().iter().all(|leaf| !leaf.is_empty()),
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

fn decode_proof(bytes: &ProofBytes) -> Proof {
    Proof::from_bytes(bytes.as_slice()).expect("decode proof")
}

fn reencode_proof(proof: &mut Proof) -> ProofBytes {
    if proof.telemetry().is_present() {
        let mut canonical = proof.clone_using_parts();
        let telemetry = canonical.telemetry_mut().frame_mut();
        telemetry.set_header_length(0);
        telemetry.set_body_length(0);
        telemetry.set_integrity_digest(DigestBytes { bytes: [0u8; 32] });
        let payload = canonical
            .serialize_payload()
            .expect("serialize canonical payload");
        let header = canonical
            .serialize_header(&payload)
            .expect("serialize canonical header");
        let integrity = compute_integrity_digest(&header, &payload);
        let telemetry = proof.telemetry_mut().frame_mut();
        telemetry.set_header_length(header.len() as u32);
        telemetry.set_body_length((payload.len() + 32) as u32);
        telemetry.set_integrity_digest(DigestBytes { bytes: integrity });
    }

    ProofBytes::new(serialize_proof(proof).expect("serialize proof"))
}

#[test]
fn verification_report_records_total_bytes_and_telemetry() {
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

    let declared_kind = map_public_to_config_kind(ProofKind::Execution);
    let report = rpp_stark::proof::verifier::verify_proof_bytes(
        declared_kind,
        &public_inputs,
        &proof_bytes,
        &setup.config,
        &setup.verifier_context,
    )
    .expect("verification report");

    assert!(
        report.error.is_none(),
        "expected verification to accept, got {:?}",
        report.error
    );
    assert_eq!(
        report.total_bytes as usize,
        proof_bytes.as_slice().len(),
        "reported total bytes must match input length"
    );

    assert!(
        report.proof.telemetry().is_present(),
        "fixture proof should include telemetry"
    );
    let payload = report.proof.serialize_payload().expect("serialize payload");
    let header = report
        .proof
        .serialize_header(&payload)
        .expect("serialize header");
    let expected_body_length = (payload.len() + 32) as u32;
    assert_eq!(
        report.proof.telemetry().frame().body_length(),
        expected_body_length,
        "telemetry body length must match payload"
    );
    let expected_header_length = header.len() as u32;
    assert_eq!(
        report.proof.telemetry().frame().header_length(),
        expected_header_length,
        "telemetry header length must match header bytes"
    );
    let telemetry = report.proof.telemetry().frame();
    assert_eq!(
        u64::from(telemetry.header_length()) + u64::from(telemetry.body_length()),
        report.total_bytes + 32,
        "telemetry lengths must sum to total bytes plus the integrity digest"
    );

    let mut canonical = report.proof.clone_using_parts();
    let canonical_telemetry = canonical.telemetry_mut().frame_mut();
    canonical_telemetry.set_header_length(0);
    canonical_telemetry.set_body_length(0);
    canonical_telemetry.set_integrity_digest(DigestBytes { bytes: [0u8; 32] });
    let canonical_payload = canonical
        .serialize_payload()
        .expect("serialize canonical payload");
    let canonical_header = canonical
        .serialize_header(&canonical_payload)
        .expect("serialize canonical header");
    let expected_digest = compute_integrity_digest(&canonical_header, &canonical_payload);
    assert_eq!(
        report.proof.telemetry().frame().integrity_digest().bytes,
        expected_digest,
        "telemetry integrity digest must remain stable"
    );
}

#[test]
fn verification_rejects_tampered_telemetry_fields() {
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

    let declared_kind = map_public_to_config_kind(ProofKind::Execution);

    let mut tampered_header = decode_proof(&proof_bytes);
    {
        let telemetry = tampered_header.telemetry_mut().frame_mut();
        let updated = telemetry.header_length().saturating_add(4);
        telemetry.set_header_length(updated);
    }
    let tampered_header_bytes = ProofBytes::new(
        serialize_proof(&tampered_header).expect("serialize tampered header proof"),
    );
    let header_report = rpp_stark::proof::verifier::verify_proof_bytes(
        declared_kind,
        &public_inputs,
        &tampered_header_bytes,
        &setup.config,
        &setup.verifier_context,
    )
    .expect("header mismatch report");
    match header_report.error {
        Some(VerifyError::HeaderLengthMismatch { declared, actual }) => {
            assert_eq!(
                declared,
                tampered_header.telemetry().frame().header_length(),
                "report must echo tampered header length"
            );
            assert_ne!(declared, actual, "mismatch must surface differing lengths");
        }
        other => panic!("expected header length mismatch, got {:?}", other),
    }

    let mut tampered_digest = decode_proof(&proof_bytes);
    tampered_digest
        .telemetry_mut()
        .frame_mut()
        .integrity_digest_mut()
        .bytes[0] ^= 0x1;
    let tampered_digest_bytes = ProofBytes::new(
        serialize_proof(&tampered_digest).expect("serialize tampered digest proof"),
    );
    let digest_report = rpp_stark::proof::verifier::verify_proof_bytes(
        declared_kind,
        &public_inputs,
        &tampered_digest_bytes,
        &setup.config,
        &setup.verifier_context,
    )
    .expect("digest mismatch report");
    assert!(matches!(
        digest_report.error,
        Some(VerifyError::IntegrityDigestMismatch)
    ));
}

#[test]
fn verification_report_flags_param_digest_flip() {
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

    let mut proof = decode_proof(&proof_bytes);
    mutate_param_digest(&mut proof);
    let mutated_bytes = reencode_proof(&mut proof);

    let declared_kind = map_public_to_config_kind(ProofKind::Execution);
    let report = rpp_stark::proof::verifier::verify_proof_bytes(
        declared_kind,
        &public_inputs,
        &mutated_bytes,
        &setup.config,
        &setup.verifier_context,
    )
    .expect("verification report");

    assert!(matches!(
        report.error,
        Some(VerifyError::ParamsHashMismatch)
    ));
    assert!(!report.params_ok, "params stage must fail");
}

#[test]
fn verification_report_marks_all_stages_on_success_path() {
    let fixture = FailMatrixFixture::new();
    let public_inputs = fixture.public_inputs();
    let config = fixture.config();
    let context = fixture.verifier_context();
    let proof_bytes = fixture.proof_bytes();
    let declared_kind = map_public_to_config_kind(public_inputs.kind());

    let report = rpp_stark::proof::verifier::verify_proof_bytes(
        declared_kind,
        &public_inputs,
        &proof_bytes,
        &config,
        &context,
    )
    .expect("verification report");

    assert!(report.error.is_none(), "expected proof to succeed");
    assert!(report.params_ok, "params stage should succeed");
    assert!(report.public_ok, "public stage should succeed");
    assert!(report.merkle_ok, "merkle stage should succeed");
    assert!(report.composition_ok, "composition stage should succeed");
    assert!(report.fri_ok, "fri stage should succeed");
}

#[test]
fn verification_report_flags_public_stage_failure() {
    let fixture = FailMatrixFixture::new();
    let public_inputs = fixture.public_inputs();
    let config = fixture.config();
    let context = fixture.verifier_context();
    let mut mutated_proof = fixture.proof();
    if let Some(byte) = mutated_proof.public_inputs_mut().first_mut() {
        *byte ^= 0x01;
    } else {
        panic!("fixture must contain public input bytes");
    }
    let recomputed_digest = compute_public_digest(mutated_proof.public_inputs());
    mutated_proof.public_digest_mut().bytes = recomputed_digest;
    let mutated_bytes = reencode_proof(&mut mutated_proof);
    let declared_kind = map_public_to_config_kind(public_inputs.kind());

    let report = rpp_stark::proof::verifier::verify_proof_bytes(
        declared_kind,
        &public_inputs,
        &mutated_bytes,
        &config,
        &context,
    )
    .expect("verification report");

    assert!(matches!(
        report.error,
        Some(VerifyError::PublicInputMismatch)
    ));
    assert!(
        !report.params_ok,
        "parameter stage should remain false when public inputs mismatch"
    );
    assert!(!report.public_ok, "public stage must fail");
    assert!(
        !report.merkle_ok,
        "merkle stage should not execute after public failure"
    );
    assert!(
        !report.composition_ok,
        "composition stage should remain false after public failure"
    );
    assert!(
        !report.fri_ok,
        "fri stage should remain false after public failure"
    );
}

#[test]
fn verification_report_flags_merkle_stage_failure() {
    let fixture = FailMatrixFixture::new();
    let public_inputs = fixture.public_inputs();
    let config = fixture.config();
    let context = fixture.verifier_context();
    let mutated_bytes = corrupt_fri_layer_root(&fixture.proof());
    let declared_kind = map_public_to_config_kind(public_inputs.kind());

    let report = rpp_stark::proof::verifier::verify_proof_bytes(
        declared_kind,
        &public_inputs,
        &mutated_bytes,
        &config,
        &context,
    )
    .expect("verification report");

    assert!(matches!(
        report.error,
        Some(VerifyError::MerkleVerifyFailed {
            section: MerkleSection::FriRoots
        })
    ));
    assert!(
        report.params_ok,
        "parameter stage should succeed before merkle checks"
    );
    assert!(
        report.public_ok,
        "public stage should succeed before merkle checks"
    );
    assert!(!report.merkle_ok, "merkle stage must fail");
    assert!(
        !report.composition_ok,
        "composition stage should remain false after merkle failure"
    );
    assert!(
        !report.fri_ok,
        "fri stage should remain false after merkle failure"
    );
}

#[test]
fn verification_report_flags_composition_stage_failure() {
    let fixture = FailMatrixFixture::new();
    let public_inputs = fixture.public_inputs();
    let config = fixture.config();
    let context = fixture.verifier_context();
    let mutated =
        flip_composition_leaf_byte(&fixture.proof()).expect("composition openings present");
    let declared_kind = map_public_to_config_kind(public_inputs.kind());

    let report = rpp_stark::proof::verifier::verify_proof_bytes(
        declared_kind,
        &public_inputs,
        &mutated.bytes,
        &config,
        &context,
    )
    .expect("verification report");

    let reason = match report.error {
        Some(VerifyError::CompositionInconsistent { ref reason }) => reason,
        other => panic!("unexpected verification outcome: {other:?}"),
    };
    assert!(reason.starts_with("composition_leaf_bytes_mismatch"));
    assert!(
        report.params_ok,
        "parameter stage should succeed before composition checks"
    );
    assert!(
        report.public_ok,
        "public stage should succeed before composition checks"
    );
    assert!(
        report.merkle_ok,
        "merkle stage should succeed before composition checks"
    );
    assert!(!report.composition_ok, "composition stage must fail");
    assert!(
        !report.fri_ok,
        "fri stage should remain false after composition failure"
    );
}

#[test]
fn verification_report_flags_fri_stage_failure() {
    let fixture = FailMatrixFixture::new();
    let public_inputs = fixture.public_inputs();
    let config = fixture.config();
    let context = fixture.verifier_context();
    let mutated = perturb_fri_fold_challenge(&fixture.proof());
    let declared_kind = map_public_to_config_kind(public_inputs.kind());

    let report = rpp_stark::proof::verifier::verify_proof_bytes(
        declared_kind,
        &public_inputs,
        &mutated.bytes,
        &config,
        &context,
    )
    .expect("verification report");

    assert!(matches!(
        report.error,
        Some(VerifyError::FriVerifyFailed { .. }) | Some(VerifyError::MerkleVerifyFailed { .. })
    ));
    assert!(
        report.params_ok,
        "parameter stage should succeed before fri checks"
    );
    assert!(
        report.public_ok,
        "public stage should succeed before fri checks"
    );
    assert!(
        report.merkle_ok,
        "merkle stage should succeed before fri checks"
    );
    assert!(
        report.composition_ok,
        "composition stage should succeed before fri checks"
    );
    assert!(!report.fri_ok, "fri stage must fail");
}

fn mutate_header_trace_root(bytes: &ProofBytes) -> ProofBytes {
    let mut mutated = bytes.as_slice().to_vec();
    let offset = header_trace_root_offset(&mutated);
    mutated[offset] ^= 0x1;
    ProofBytes::new(mutated)
}

fn mutate_header_composition_root(bytes: &ProofBytes) -> ProofBytes {
    let mut mutated = bytes.as_slice().to_vec();
    let trace_offset = header_trace_root_offset(&mutated);
    let mut cursor = trace_offset + 32;
    let flag = mutated[cursor];
    assert_eq!(flag, 1, "expected composition commit to be present");
    cursor += 1;
    mutated[cursor] ^= 0x1;
    ProofBytes::new(mutated)
}

fn corrupt_fri_layer_root(proof: &Proof) -> ProofBytes {
    let mut mutated = proof.clone_using_parts();
    if let Some(root) = mutated
        .merkle_mut()
        .fri_layer_roots_mut()
        .first_mut()
    {
        if let Some(byte) = root.first_mut() {
            *byte ^= 0x1;
        } else {
            panic!("fri layer root must contain bytes");
        }
    } else {
        panic!("fri layer roots must be present");
    }

    reencode_proof(&mut mutated)
}

fn mutate_param_digest(proof: &mut Proof) {
    let mut updated = *proof.params_hash().as_bytes();
    updated[0] ^= 0x1;
    *proof.params_hash_mut() = ParamDigest(DigestBytes { bytes: updated });
}

fn mutate_public_digest(bytes: &ProofBytes) -> ProofBytes {
    let mut mutated = bytes.as_slice().to_vec();
    let offset = header_trace_root_offset(&mutated) - 32;
    mutated[offset] ^= 0x1;
    ProofBytes::new(mutated)
}

fn header_trace_root_offset(bytes: &[u8]) -> usize {
    let mut cursor = 0usize;
    cursor += 2; // version
    cursor += 1; // kind
    cursor += 32; // params hash
    cursor += 32; // air spec id
    let public_len =
        u32::from_le_bytes(bytes[cursor..cursor + 4].try_into().expect("len")) as usize;
    cursor += 4;
    cursor += public_len; // public inputs
    cursor += 32; // public digest
    cursor
}

#[test]
fn proof_decode_rejects_public_digest_tampering() {
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

    let mutated = mutate_public_digest(&proof_bytes);
    let decode_error =
        rpp_stark::Proof::from_bytes(mutated.as_slice()).expect_err("decode must fail");
    assert!(matches!(decode_error, VerifyError::PublicDigestMismatch));

    let declared_kind = map_public_to_config_kind(ProofKind::Execution);
    let verify_err = rpp_stark::proof::verifier::verify_proof_bytes(
        declared_kind,
        &public_inputs,
        &mutated,
        &setup.config,
        &setup.verifier_context,
    )
    .expect_err("verification must fail before building report");
    assert!(matches!(verify_err, VerifyError::PublicDigestMismatch));
}

#[test]
fn verification_rejects_tampered_ood_core_value() {
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

    let mut proof = decode_proof(&proof_bytes);
    let ood = proof
        .openings_mut()
        .out_of_domain_mut()
        .first_mut()
        .expect("ood payload present");
    let value = ood.core_values.first_mut().expect("core value present");
    value[0] ^= 0x1;

    let tampered_bytes = reencode_proof(&mut proof);
    let verify_inputs = make_public_inputs(&setup.header, &setup.body);
    let verdict = verify_proof(
        ProofKind::Execution,
        &verify_inputs,
        &tampered_bytes,
        &setup.config,
        &setup.verifier_context,
    )
    .expect("verification verdict");
    assert!(matches!(
        verdict,
        VerificationVerdict::Reject(VerifyError::TraceOodMismatch)
    ));
}

#[test]
fn verification_rejects_tampered_ood_composition_value() {
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

    let mut proof = decode_proof(&proof_bytes);
    let ood = proof
        .openings_mut()
        .out_of_domain_mut()
        .first_mut()
        .expect("ood payload present");
    ood.composition_value[0] ^= 0x1;

    let tampered_bytes = reencode_proof(&mut proof);
    let verify_inputs = make_public_inputs(&setup.header, &setup.body);
    let verdict = verify_proof(
        ProofKind::Execution,
        &verify_inputs,
        &tampered_bytes,
        &setup.config,
        &setup.verifier_context,
    )
    .expect("verification verdict");
    assert!(matches!(
        verdict,
        VerificationVerdict::Reject(VerifyError::CompositionOodMismatch)
    ));
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
    proof.openings_mut().trace_mut().leaves_mut()[0][0] ^= 1;
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
        .openings_mut()
        .composition_mut()
        .expect("composition openings present");
    composition.leaves_mut()[0][0] ^= 1;
    let composition_index = composition.indices()[0];
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

    let expected_reason =
        format!("composition_leaf_bytes_mismatch:pos=0:index={composition_index}");
    match verdict {
        VerificationVerdict::Reject(VerifyError::CompositionInconsistent { reason }) => {
            assert_eq!(reason, expected_reason);
        }
        other => panic!("unexpected verdict: {other:?}"),
    }
}

#[test]
fn verification_rejects_tampered_fri_fold_challenge() {
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

    let mut proof = decode_proof(&proof_bytes);
    assert!(
        !proof.fri_proof().fold_challenges.is_empty(),
        "expected fold challenges"
    );
    let fri_proof = proof.fri_proof_mut();
    fri_proof.final_polynomial[0] = fri_proof.final_polynomial[0].add(&FieldElement::from(1u64));
    let mutated_bytes = reencode_proof(&mut proof);

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
        VerificationVerdict::Reject(VerifyError::FriVerifyFailed { issue }) => {
            assert_eq!(issue, FriVerifyIssue::LayerMismatch);
        }
        other => panic!("unexpected verdict: {other:?}"),
    }
}

#[test]
fn verification_report_flags_fri_challenge_flip() {
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

    let mut proof = decode_proof(&proof_bytes);
    assert!(
        !proof.fri_proof().fold_challenges.is_empty(),
        "expected at least one fold challenge"
    );
    let fri_proof = proof.fri_proof_mut();
    let first = fri_proof.fold_challenges[0];
    fri_proof.fold_challenges[0] = first.add(&FieldElement::from(1u64));
    let mutated_bytes = reencode_proof(&mut proof);

    let declared_kind = map_public_to_config_kind(ProofKind::Execution);
    let report = rpp_stark::proof::verifier::verify_proof_bytes(
        declared_kind,
        &public_inputs,
        &mutated_bytes,
        &setup.config,
        &setup.verifier_context,
    )
    .expect("verification report");

    match report.error {
        Some(VerifyError::MerkleVerifyFailed {
            section: MerkleSection::FriPath,
        }) => {}
        other => panic!("unexpected verification outcome: {other:?}"),
    }
}

#[test]
fn verification_rejects_composition_leaf_misalignment_with_fri() {
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

    let mut proof = decode_proof(&proof_bytes);
    let composition_index = {
        let composition = proof
            .openings()
            .composition()
            .expect("composition openings present");
        assert!(
            !composition.indices().is_empty(),
            "expected composition indices"
        );
        composition.indices()[0]
    };
    let target_index = composition_index as usize;
    let query_position = proof
        .fri_proof()
        .queries
        .iter()
        .position(|query| query.position == target_index)
        .expect("matching FRI query");
    let query = proof
        .fri_proof_mut()
        .queries
        .get_mut(query_position)
        .expect("query index");
    let first_layer = query.layers.first_mut().expect("fri first layer");
    first_layer.value = first_layer.value.add(&FieldElement::from(1u64));
    let mutated_bytes = reencode_proof(&mut proof);

    let verify_inputs = make_public_inputs(&setup.header, &setup.body);
    let verdict = verify_proof(
        ProofKind::Execution,
        &verify_inputs,
        &mutated_bytes,
        &setup.config,
        &setup.verifier_context,
    )
    .expect("verification verdict");

    let expected_reason = format!(
        "composition_leaf_bytes_mismatch:pos={}:index={}",
        query_position, composition_index
    );
    match verdict {
        VerificationVerdict::Reject(VerifyError::CompositionInconsistent { reason }) => {
            assert_eq!(reason, expected_reason);
        }
        other => panic!("unexpected verdict: {other:?}"),
    }
}

#[test]
fn verification_rejects_tampered_header_trace_root() {
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

    let tampered_bytes = mutate_header_trace_root(&proof_bytes);
    let decode_err =
        rpp_stark::Proof::from_bytes(tampered_bytes.as_slice()).expect_err("decode must fail");
    assert!(matches!(
        decode_err,
        VerifyError::RootMismatch {
            section: MerkleSection::TraceCommit
        }
    ));
    let verify_inputs = make_public_inputs(&setup.header, &setup.body);
    let verdict = verify_proof(
        ProofKind::Execution,
        &verify_inputs,
        &tampered_bytes,
        &setup.config,
        &setup.verifier_context,
    );

    match verdict {
        Err(StarkError::InvalidInput(reason)) => assert_eq!(reason, "root_mismatch"),
        other => panic!("unexpected verdict: {other:?}"),
    }
}

#[test]
fn verification_report_flags_header_trace_root_mismatch() {
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

    let tampered = mutate_header_trace_root(&proof_bytes);
    let declared_kind = map_public_to_config_kind(ProofKind::Execution);
    let err = rpp_stark::proof::verifier::verify_proof_bytes(
        declared_kind,
        &public_inputs,
        &tampered,
        &setup.config,
        &setup.verifier_context,
    )
    .expect_err("root mismatch must abort decoding");
    assert!(matches!(
        err,
        VerifyError::RootMismatch {
            section: MerkleSection::TraceCommit
        }
    ));
}

#[test]
fn verification_rejects_tampered_header_composition_root() {
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

    let tampered_bytes = mutate_header_composition_root(&proof_bytes);
    let decode_err =
        rpp_stark::Proof::from_bytes(tampered_bytes.as_slice()).expect_err("decode must fail");
    assert!(matches!(
        decode_err,
        VerifyError::RootMismatch {
            section: MerkleSection::CompositionCommit
        }
    ));
    let verify_inputs = make_public_inputs(&setup.header, &setup.body);
    let verdict = verify_proof(
        ProofKind::Execution,
        &verify_inputs,
        &tampered_bytes,
        &setup.config,
        &setup.verifier_context,
    );

    match verdict {
        Err(StarkError::InvalidInput(reason)) => assert_eq!(reason, "root_mismatch"),
        other => panic!("unexpected verdict: {other:?}"),
    }
}

#[test]
fn verification_report_flags_header_composition_root_mismatch() {
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

    let tampered = mutate_header_composition_root(&proof_bytes);
    let declared_kind = map_public_to_config_kind(ProofKind::Execution);
    let err = rpp_stark::proof::verifier::verify_proof_bytes(
        declared_kind,
        &public_inputs,
        &tampered,
        &setup.config,
        &setup.verifier_context,
    )
    .expect_err("composition root mismatch must abort decoding");
    assert!(matches!(
        err,
        VerifyError::RootMismatch {
            section: MerkleSection::CompositionCommit
        }
    ));
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
    if let Some(first) = proof.openings_mut().out_of_domain_mut().first_mut() {
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
    if decoded.openings().trace().indices().len() < 2 {
        panic!("expected at least two trace indices");
    }
    decoded.openings_mut().trace_mut().indices_mut().swap(0, 1);
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
    if decoded.openings().trace().indices().len() < 2 {
        panic!("expected at least two trace indices");
    }
    let indices = decoded.openings_mut().trace_mut().indices_mut();
    indices[1] = indices[0];
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
        VerificationVerdict::Reject(VerifyError::IndicesDuplicate { .. })
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
    {
        let indices = decoded.openings_mut().trace_mut().indices_mut();
        for index in indices.iter_mut() {
            *index = index.saturating_add(1);
        }
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
fn verification_rejects_composition_indices_not_sorted() {
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
    let composition = decoded
        .openings_mut()
        .composition_mut()
        .expect("composition openings present");
    if composition.indices().len() < 2 {
        panic!("expected at least two composition indices");
    }
    composition.indices_mut().swap(0, 1);
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
fn verification_rejects_composition_indices_duplicate() {
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
    let composition = decoded
        .openings_mut()
        .composition_mut()
        .expect("composition openings present");
    if composition.indices().len() < 2 {
        panic!("expected at least two composition indices");
    }
    let indices = composition.indices_mut();
    indices[1] = indices[0];
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
        VerificationVerdict::Reject(VerifyError::IndicesDuplicate { .. })
    ));
}

#[test]
fn verification_rejects_composition_indices_mismatch() {
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
    let composition = decoded
        .openings_mut()
        .composition_mut()
        .expect("composition openings present");
    for index in composition.indices_mut().iter_mut() {
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
    .expect_err("params hash mismatch propagates");
    assert!(matches!(
        error,
        StarkError::InvalidInput("prover_params_hash_mismatch")
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

#[test]
fn verification_report_flags_proof_size_overflow() {
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

    let declared_kind = map_public_to_config_kind(ProofKind::Execution);
    let mut tight_context = setup.verifier_context.clone();
    tight_context.limits.max_proof_size_bytes = 64; // enforce a strict budget

    let report = rpp_stark::proof::verifier::verify_proof_bytes(
        declared_kind,
        &public_inputs,
        &proof_bytes,
        &setup.config,
        &tight_context,
    )
    .expect("verification report");

    match report.error {
        Some(VerifyError::ProofTooLarge { max_kb, got_kb }) => {
            assert!(got_kb > max_kb, "reported overflow must exceed budget");
        }
        other => panic!("unexpected verification outcome: {other:?}"),
    }
}
