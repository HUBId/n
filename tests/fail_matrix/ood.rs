use insta::assert_debug_snapshot;
use rpp_stark::config::ProofKind as ConfigProofKind;
use rpp_stark::proof::types::VerifyError;
use rpp_stark::proof::verifier::verify;

use super::{flip_ood_composition_value, flip_ood_trace_core_value, FailMatrixFixture};

#[test]
fn trace_ood_rejects_core_value_mismatch() {
    let fixture = FailMatrixFixture::new();
    let Some(mutated) = flip_ood_trace_core_value(&fixture.proof()) else {
        eprintln!("fixture does not expose OOD trace values; skipping test");
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
    assert!(matches!(error, VerifyError::TraceOodMismatch));

    let ood_openings = mutated.proof.openings().out_of_domain().clone();
    assert!(!ood_openings.is_empty(), "mutated proof lost OOD payloads");

    assert_debug_snapshot!("trace_ood_mismatch__tampered_out_of_domain", ood_openings);
}

#[test]
fn composition_ood_rejects_value_mismatch() {
    let fixture = FailMatrixFixture::new();
    let Some(mutated) = flip_ood_composition_value(&fixture.proof()) else {
        eprintln!("fixture does not expose OOD composition values; skipping test");
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
    assert!(matches!(error, VerifyError::CompositionOodMismatch));

    let ood_openings = mutated.proof.openings().out_of_domain().clone();
    assert!(!ood_openings.is_empty(), "mutated proof lost OOD payloads");

    assert_debug_snapshot!(
        "composition_ood_mismatch__tampered_out_of_domain",
        ood_openings
    );
}
