use insta::assert_debug_snapshot;
use rpp_stark::config::ProofKind as ConfigProofKind;
use rpp_stark::proof::types::VerifyError;
use rpp_stark::proof::verifier::verify_proof_bytes;

use super::{flip_composition_leaf_byte, FailMatrixFixture};

#[test]
fn composition_rejects_leaf_bytes_mismatch() {
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
    let reason = match error {
        VerifyError::CompositionInconsistent { reason } => reason,
        other => panic!("unexpected verification outcome: {other:?}"),
    };

    let composition = mutated
        .proof
        .openings()
        .composition
        .as_ref()
        .expect("composition openings available");

    let leaves = composition.leaves.clone();
    let indices = composition.indices.clone();
    let first_index = indices
        .first()
        .copied()
        .expect("composition index available");

    let expected_reason = format!("composition_leaf_bytes_mismatch:pos=0:index={first_index}");
    assert_eq!(reason, expected_reason);

    assert_debug_snapshot!("rejects_leaf_bytes_mismatch__leaves", leaves);
    assert_debug_snapshot!("rejects_leaf_bytes_mismatch__indices", &indices);
    assert_debug_snapshot!("rejects_leaf_bytes_mismatch__reason", &reason);
}
