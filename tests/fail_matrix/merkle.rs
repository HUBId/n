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
    cursor += 32; // params hash
    cursor += 32; // public digest

    let trace_commit_start = cursor;
    let trace_commit = slice[trace_commit_start..trace_commit_start + 32]
        .try_into()
        .expect("trace commit slice");

    cursor = trace_commit_start + 32;

    let binding_len = u32::from_le_bytes(
        slice[cursor..cursor + 4]
            .try_into()
            .expect("binding length slice"),
    ) as usize;
    cursor += 4 + binding_len;

    let openings_len = u32::from_le_bytes(
        slice[cursor..cursor + 4]
            .try_into()
            .expect("openings length slice"),
    ) as usize;
    cursor += 4;

    let fri_len = u32::from_le_bytes(
        slice[cursor..cursor + 4]
            .try_into()
            .expect("fri length slice"),
    ) as usize;
    cursor += 4;

    let telemetry_flag = slice[cursor];
    cursor += 1;
    let telemetry_len = if telemetry_flag == 1 {
        let len = u32::from_le_bytes(
            slice[cursor..cursor + 4]
                .try_into()
                .expect("telemetry length slice"),
        ) as usize;
        cursor += 4;
        Some((openings_len + fri_len, len))
    } else {
        None
    };

    let payload_start = cursor;
    let openings_offset = 0usize;
    let fri_offset = openings_len;

    let descriptor_start = payload_start + openings_offset;
    let mut descriptor_cursor = descriptor_start;
    let merkle_block_len = u32::from_le_bytes(
        slice[descriptor_cursor..descriptor_cursor + 4]
            .try_into()
            .expect("merkle block length slice"),
    ) as usize;
    descriptor_cursor += 4;

    let core_root = slice[descriptor_cursor..descriptor_cursor + 32]
        .try_into()
        .expect("core root slice");
    let aux_root = slice[descriptor_cursor + 32..descriptor_cursor + 64]
        .try_into()
        .expect("aux root slice");

    descriptor_cursor += merkle_block_len;
    let openings_block_len = u32::from_le_bytes(
        slice[descriptor_cursor..descriptor_cursor + 4]
            .try_into()
            .expect("openings block length slice"),
    ) as usize;
    descriptor_cursor += 4 + openings_block_len;

    debug_assert_eq!(descriptor_cursor - descriptor_start, openings_len);
    let fri_start = payload_start + fri_offset;
    let _fri_end = fri_start + fri_len;
    let _payload_end = match telemetry_len {
        Some((offset, len)) => payload_start + offset + len,
        None => _fri_end,
    };

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
        .trace()
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
        .trace()
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
