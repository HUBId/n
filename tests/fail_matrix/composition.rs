use insta::assert_debug_snapshot;
use rpp_stark::config::ProofKind as ConfigProofKind;
use rpp_stark::proof::types::{MerkleSection, VerifyError};
use rpp_stark::proof::verifier::verify_proof_bytes;

use super::{flip_composition_leaf_byte, FailMatrixFixture, MutatedProof};

fn hex_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(out, "{:02x}", byte);
    }
    out
}

fn snapshot_composition_leaves(mutated: &MutatedProof) {
    let leaves: Vec<String> = mutated
        .proof
        .openings
        .composition
        .as_ref()
        .map(|composition| {
            composition
                .leaves
                .iter()
                .map(|leaf| hex_bytes(leaf))
                .collect()
        })
        .unwrap_or_default();

    assert_debug_snapshot!("composition_rejects_leaf_mutation_leaves", leaves);
}

#[test]
fn composition_rejects_leaf_mutation() {
    let fixture = FailMatrixFixture::new();
    let Some(mutated) = flip_composition_leaf_byte(&fixture.proof()) else {
        eprintln!("fixture does not expose composition openings; skipping test");
        return;
    };

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
    match error {
        VerifyError::MerkleVerifyFailed {
            section: MerkleSection::CompositionCommit,
        } => {}
        other => panic!("unexpected verification outcome: {other:?}"),
    }

    snapshot_composition_leaves(&mutated);
}
