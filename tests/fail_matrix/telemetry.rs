use insta::assert_snapshot;
use rpp_stark::config::ProofKind as ConfigProofKind;
use rpp_stark::proof::types::VerifyError;
use rpp_stark::proof::verifier::verify;
use rpp_stark::utils::serialization::ProofBytes;

use super::fixture::header_layout;
use super::{
    mismatch_telemetry_body_length, mismatch_telemetry_header_length,
    mismatch_telemetry_integrity_digest, FailMatrixFixture,
};

fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{:02x}", byte)).collect()
}

fn telemetry_frame_bytes(bytes: &ProofBytes) -> Option<Vec<u8>> {
    let layout = header_layout(bytes.as_slice());
    let Some(handle) = layout.telemetry().handle() else {
        return None;
    };

    debug_assert_eq!(layout.openings().offset(), 0);
    debug_assert_eq!(
        layout.fri().offset(),
        layout.openings().offset() + layout.openings().length()
    );

    let payload_start = layout.payload_start();
    let slice = bytes.as_slice();
    let start = payload_start + handle.offset_usize();
    let end = start + handle.len_usize();
    Some(slice[start..end].to_vec())
}

#[test]
fn telemetry_rejects_header_length_mismatch() {
    let fixture = FailMatrixFixture::new();
    let Some(mutated_bytes) = mismatch_telemetry_header_length(&fixture.proof()) else {
        eprintln!("fixture does not expose telemetry; skipping test");
        return;
    };

    let public_inputs = fixture.public_inputs();
    let config = fixture.config();
    let context = fixture.verifier_context();

    let report = verify(
        ConfigProofKind::Tx,
        &public_inputs,
        &mutated_bytes,
        &config,
        &context,
    )
    .expect("report produced");

    let error = report.error.expect("expected verification failure");
    assert!(matches!(error, VerifyError::HeaderLengthMismatch { .. }));

    let telemetry_bytes =
        telemetry_frame_bytes(&mutated_bytes).expect("telemetry frame bytes available");
    assert_snapshot!(
        "telemetry_rejects_header_length_mismatch__frame",
        hex_bytes(&telemetry_bytes)
    );
}

#[test]
fn telemetry_rejects_body_length_mismatch() {
    let fixture = FailMatrixFixture::new();
    let Some(mutated_bytes) = mismatch_telemetry_body_length(&fixture.proof()) else {
        eprintln!("fixture does not expose telemetry; skipping test");
        return;
    };

    let public_inputs = fixture.public_inputs();
    let config = fixture.config();
    let context = fixture.verifier_context();

    let report = verify(
        ConfigProofKind::Tx,
        &public_inputs,
        &mutated_bytes,
        &config,
        &context,
    )
    .expect("report produced");

    let error = report.error.expect("expected verification failure");
    assert!(matches!(error, VerifyError::BodyLengthMismatch { .. }));

    let telemetry_bytes =
        telemetry_frame_bytes(&mutated_bytes).expect("telemetry frame bytes available");
    assert_snapshot!(
        "telemetry_rejects_body_length_mismatch__frame",
        hex_bytes(&telemetry_bytes)
    );
}

#[test]
fn telemetry_rejects_integrity_digest_mismatch() {
    let fixture = FailMatrixFixture::new();
    let Some(mutated_bytes) = mismatch_telemetry_integrity_digest(&fixture.proof()) else {
        eprintln!("fixture does not expose telemetry; skipping test");
        return;
    };

    let public_inputs = fixture.public_inputs();
    let config = fixture.config();
    let context = fixture.verifier_context();

    let report = verify(
        ConfigProofKind::Tx,
        &public_inputs,
        &mutated_bytes,
        &config,
        &context,
    )
    .expect("report produced");

    let error = report.error.expect("expected verification failure");
    assert!(matches!(error, VerifyError::IntegrityDigestMismatch));

    let telemetry_bytes =
        telemetry_frame_bytes(&mutated_bytes).expect("telemetry frame bytes available");
    assert_snapshot!(
        "telemetry_rejects_integrity_digest_mismatch__frame",
        hex_bytes(&telemetry_bytes)
    );
}
