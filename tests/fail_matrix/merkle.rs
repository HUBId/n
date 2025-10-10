use insta::assert_debug_snapshot;
use rpp_stark::config::ProofKind as ConfigProofKind;
use rpp_stark::proof::types::{MerkleSection, VerifyError};
use rpp_stark::proof::verifier::verify_proof_bytes;
use rpp_stark::utils::serialization::ProofBytes;
use std::convert::TryInto;

use super::{
    corrupt_merkle_path, mismatch_trace_root, truncate_trace_paths, FailMatrixFixture, MutatedProof,
};

fn hex_digest(bytes: &[u8; 32]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(out, "{:02x}", byte);
    }
    out
}

fn extract_roots(bytes: &ProofBytes) -> ([u8; 32], [u8; 32], [u8; 32]) {
    let slice = bytes.as_slice();
    let mut cursor = 0usize;
    cursor += 2; // version
    cursor += 1; // kind
    cursor += 32; // params hash
    cursor += 32; // air spec identifier

    let public_len_start = cursor;
    let public_len_end = public_len_start + 4;
    let public_len = u32::from_le_bytes(
        slice[public_len_start..public_len_end]
            .try_into()
            .expect("public length slice"),
    ) as usize;
    cursor += 4; // public length prefix
    cursor += public_len; // public input bytes

    cursor += 32; // public digest

    let trace_commit_start = cursor;
    let trace_commit = slice[trace_commit_start..trace_commit_start + 32]
        .try_into()
        .expect("trace commit slice");

    cursor = trace_commit_start + 32;
    let composition_flag = slice[cursor];
    cursor += 1;
    if composition_flag == 1 {
        cursor += 32; // composition digest
    }

    let merkle_len = u32::from_le_bytes(
        slice[cursor..cursor + 4]
            .try_into()
            .expect("merkle length slice"),
    ) as usize;
    cursor += 4; // merkle length prefix
    let fri_len = u32::from_le_bytes(
        slice[cursor..cursor + 4]
            .try_into()
            .expect("fri length slice"),
    ) as usize;
    cursor += 4; // fri length prefix
    let openings_len = u32::from_le_bytes(
        slice[cursor..cursor + 4]
            .try_into()
            .expect("openings length slice"),
    ) as usize;
    cursor += 4; // openings length prefix

    let telemetry_flag = slice[cursor];
    cursor += 1;
    if telemetry_flag == 1 {
        cursor += 4; // telemetry length prefix
    }

    let merkle_start = cursor;
    let core_root = slice[merkle_start..merkle_start + 32]
        .try_into()
        .expect("core root slice");
    let aux_root = slice[merkle_start + 32..merkle_start + 64]
        .try_into()
        .expect("aux root slice");

    // Ensure cursor accounts for the full merkle section for validation sanity.
    let _merkle_end = merkle_start + merkle_len;
    let _fri_end = _merkle_end + fri_len;
    let _openings_end = _fri_end + openings_len;

    (trace_commit, core_root, aux_root)
}

fn snapshot_roots(bytes: &ProofBytes) {
    let (trace_commit, core_root, aux_root) = extract_roots(bytes);
    let snapshot = vec![
        ("trace_commit", hex_digest(&trace_commit)),
        ("merkle_core_root", hex_digest(&core_root)),
        ("merkle_aux_root", hex_digest(&aux_root)),
    ];

    assert_debug_snapshot!("merkle_rejects_header_root_mismatch", snapshot);
}

#[test]
fn merkle_rejects_header_root_mismatch() {
    let fixture = FailMatrixFixture::new();
    let mutated_bytes = mismatch_trace_root(&fixture.proof_bytes());

    let public_inputs = fixture.public_inputs();
    let config = fixture.config();
    let context = fixture.verifier_context();

    let err = verify_proof_bytes(
        ConfigProofKind::Tx,
        &public_inputs,
        &mutated_bytes,
        &config,
        &context,
    )
    .expect_err("root mismatch must error");

    assert!(matches!(
        err,
        VerifyError::RootMismatch {
            section: MerkleSection::TraceCommit
        }
    ));

    snapshot_roots(&mutated_bytes);
}

fn snapshot_path_nodes(mutated: &MutatedProof) {
    let nodes: Vec<(u8, String)> = mutated
        .proof
        .openings()
        .trace
        .paths
        .first()
        .map(|path| {
            path.nodes
                .iter()
                .map(|node| (node.index, hex_digest(&node.sibling)))
                .collect()
        })
        .unwrap_or_default();

    assert_debug_snapshot!("merkle_rejects_corrupted_trace_path", nodes);
}

#[test]
fn merkle_rejects_corrupted_trace_path() {
    let fixture = FailMatrixFixture::new();
    let mutated = corrupt_merkle_path(&fixture.proof());

    let public_inputs = fixture.public_inputs();
    let config = fixture.config();
    let context = fixture.verifier_context();

    let report = verify_proof_bytes(
        ConfigProofKind::Tx,
        &public_inputs,
        &mutated.bytes,
        &config,
        &context,
    )
    .expect("report produced");

    let error = report.error.expect("expected verification failure");
    assert!(matches!(
        error,
        VerifyError::MerkleVerifyFailed {
            section: MerkleSection::TraceCommit
        }
    ));

    snapshot_path_nodes(&mutated);
}

fn snapshot_path_lengths(mutated: &MutatedProof) {
    let lengths: Vec<usize> = mutated
        .proof
        .openings()
        .trace
        .paths
        .iter()
        .map(|path| path.nodes.len())
        .collect();

    assert_debug_snapshot!("merkle_rejects_inconsistent_trace_paths", lengths);
}

#[test]
fn merkle_rejects_inconsistent_trace_paths() {
    let fixture = FailMatrixFixture::new();
    let mutated = truncate_trace_paths(&fixture.proof());

    let public_inputs = fixture.public_inputs();
    let config = fixture.config();
    let context = fixture.verifier_context();

    let report = verify_proof_bytes(
        ConfigProofKind::Tx,
        &public_inputs,
        &mutated.bytes,
        &config,
        &context,
    )
    .expect("report produced");

    let error = report.error.expect("expected verification failure");
    assert!(matches!(error, VerifyError::EmptyOpenings));

    snapshot_path_lengths(&mutated);
}
