use insta::assert_debug_snapshot;
use rpp_stark::config::ProofKind as ConfigProofKind;
use rpp_stark::proof::types::VerifyError;
use rpp_stark::proof::verifier::verify;

use super::{
    duplicate_composition_index, duplicate_trace_index, mismatch_composition_indices,
    mismatch_trace_indices, swap_composition_indices, swap_trace_indices, FailMatrixFixture,
};

#[test]
fn trace_rejects_unsorted_indices() {
    let fixture = FailMatrixFixture::new();
    let mutated = swap_trace_indices(&fixture.proof());

    let public_inputs = fixture.public_inputs();
    let config = fixture.config();
    let context = fixture.verifier_context();

    let report = verify(
        ConfigProofKind::Tx,
        &public_inputs,
        &mutated.bytes,
        &config,
        &context,
    );

    let error = report.error.expect("expected verification failure");
    assert!(matches!(error, VerifyError::IndicesNotSorted));

    assert_debug_snapshot!(
        "trace_rejects_unsorted_indices",
        mutated.proof.openings().trace().indices()
    );
}

#[test]
fn trace_rejects_duplicate_indices() {
    let fixture = FailMatrixFixture::new();
    let mutated = duplicate_trace_index(&fixture.proof());

    let public_inputs = fixture.public_inputs();
    let config = fixture.config();
    let context = fixture.verifier_context();

    let report = verify(
        ConfigProofKind::Tx,
        &public_inputs,
        &mutated.bytes,
        &config,
        &context,
    );

    let error = report.error.expect("expected verification failure");
    assert!(matches!(error, VerifyError::IndicesDuplicate { .. }));

    assert_debug_snapshot!(
        "trace_rejects_duplicate_indices",
        mutated.proof.openings().trace().indices()
    );
}

#[test]
fn trace_rejects_mismatched_indices() {
    let fixture = FailMatrixFixture::new();
    let mutated = mismatch_trace_indices(&fixture.proof());

    let public_inputs = fixture.public_inputs();
    let config = fixture.config();
    let context = fixture.verifier_context();

    let report = verify(
        ConfigProofKind::Tx,
        &public_inputs,
        &mutated.bytes,
        &config,
        &context,
    );

    let error = report.error.expect("expected verification failure");
    assert!(matches!(error, VerifyError::IndicesMismatch));

    assert_debug_snapshot!(
        "trace_rejects_mismatched_indices",
        mutated.proof.openings().trace().indices()
    );
}

#[test]
fn composition_rejects_unsorted_indices() {
    let fixture = FailMatrixFixture::new();
    let Some(mutated) = swap_composition_indices(&fixture.proof()) else {
        eprintln!("fixture does not expose composition openings; skipping test");
        return;
    };

    let public_inputs = fixture.public_inputs();
    let config = fixture.config();
    let context = fixture.verifier_context();

    let report = verify(
        ConfigProofKind::Tx,
        &public_inputs,
        &mutated.bytes,
        &config,
        &context,
    );

    let error = report.error.expect("expected verification failure");
    assert!(matches!(error, VerifyError::IndicesNotSorted));

    assert_debug_snapshot!(
        "composition_rejects_unsorted_indices",
        mutated
            .proof
            .openings()
            .composition()
            .expect("composition openings available")
            .indices()
    );
}

#[test]
fn composition_rejects_duplicate_indices() {
    let fixture = FailMatrixFixture::new();
    let Some(mutated) = duplicate_composition_index(&fixture.proof()) else {
        eprintln!("fixture does not expose composition openings; skipping test");
        return;
    };

    let public_inputs = fixture.public_inputs();
    let config = fixture.config();
    let context = fixture.verifier_context();

    let report = verify(
        ConfigProofKind::Tx,
        &public_inputs,
        &mutated.bytes,
        &config,
        &context,
    );

    let error = report.error.expect("expected verification failure");
    assert!(matches!(error, VerifyError::IndicesDuplicate { .. }));

    assert_debug_snapshot!(
        "composition_rejects_duplicate_indices",
        mutated
            .proof
            .openings()
            .composition()
            .expect("composition openings available")
            .indices()
    );
}

#[test]
fn composition_rejects_mismatched_indices() {
    let fixture = FailMatrixFixture::new();
    let Some(mutated) = mismatch_composition_indices(&fixture.proof()) else {
        eprintln!("fixture does not expose composition openings; skipping test");
        return;
    };

    let public_inputs = fixture.public_inputs();
    let config = fixture.config();
    let context = fixture.verifier_context();

    let report = verify(
        ConfigProofKind::Tx,
        &public_inputs,
        &mutated.bytes,
        &config,
        &context,
    );

    let error = report.error.expect("expected verification failure");
    assert!(matches!(error, VerifyError::IndicesMismatch));

    assert_debug_snapshot!(
        "composition_rejects_mismatched_indices",
        mutated
            .proof
            .openings()
            .composition()
            .expect("composition openings available")
            .indices()
    );
}
