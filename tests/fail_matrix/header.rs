use insta::assert_snapshot;
use rpp_stark::config::ProofKind as ConfigProofKind;
use rpp_stark::proof::types::VerifyError;
use rpp_stark::proof::verifier::verify_proof_bytes;
use rpp_stark::ser::SerKind;
use rpp_stark::utils::serialization::ProofBytes;

use super::fixture::header_layout;
use super::{
    flip_header_version, flip_param_digest_byte, flip_public_digest_byte, mismatch_fri_offset,
    mismatch_openings_offset, mismatch_telemetry_flag, mismatch_telemetry_offset,
    FailMatrixFixture,
};

fn hex_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(out, "{:02x}", byte);
    }
    out
}

fn header_bytes(bytes: &ProofBytes) -> Vec<u8> {
    let layout = header_layout(bytes.as_slice());
    bytes.as_slice()[..layout.payload_start()].to_vec()
}

#[test]
fn header_rejects_version_bump() {
    let fixture = FailMatrixFixture::new();
    let public_inputs = fixture.public_inputs();
    let config = fixture.config();
    let context = fixture.verifier_context();
    let mutated_bytes = flip_header_version(&fixture.proof());

    let err = verify_proof_bytes(
        ConfigProofKind::Tx,
        &public_inputs,
        &mutated_bytes,
        &config,
        &context,
    )
    .expect_err("version mismatch must error");

    assert!(matches!(err, VerifyError::VersionMismatch { .. }));

    assert_snapshot!(
        "header_rejects_version_bump",
        hex_bytes(&header_bytes(&mutated_bytes))
    );
}

#[test]
fn header_rejects_param_digest_mismatch() {
    let fixture = FailMatrixFixture::new();
    let public_inputs = fixture.public_inputs();
    let config = fixture.config();
    let context = fixture.verifier_context();
    let mutated_bytes = flip_param_digest_byte(&fixture.proof());

    let report = verify_proof_bytes(
        ConfigProofKind::Tx,
        &public_inputs,
        &mutated_bytes,
        &config,
        &context,
    )
    .expect("report produced");

    let error = report.error.expect("expected failure");
    assert!(matches!(error, VerifyError::ParamsHashMismatch));

    assert_snapshot!(
        "header_rejects_param_digest_mismatch",
        hex_bytes(&header_bytes(&mutated_bytes))
    );
}

#[test]
fn header_rejects_public_digest_mismatch() {
    let fixture = FailMatrixFixture::new();
    let public_inputs = fixture.public_inputs();
    let config = fixture.config();
    let context = fixture.verifier_context();
    let mutated_bytes = flip_public_digest_byte(&fixture.proof_bytes());

    let err = verify_proof_bytes(
        ConfigProofKind::Tx,
        &public_inputs,
        &mutated_bytes,
        &config,
        &context,
    )
    .expect_err("public digest mismatch must error");

    assert!(matches!(err, VerifyError::PublicDigestMismatch));

    assert_snapshot!(
        "header_rejects_public_digest_mismatch",
        hex_bytes(&header_bytes(&mutated_bytes))
    );
}

#[test]
fn header_rejects_excessive_proof_size() {
    let fixture = FailMatrixFixture::new();
    let public_inputs = fixture.public_inputs();
    let config = fixture.config();
    let mut context = fixture.verifier_context();
    context.limits.max_proof_size_bytes = 64;
    let proof_bytes = fixture.proof_bytes();

    let report = verify_proof_bytes(
        ConfigProofKind::Tx,
        &public_inputs,
        &proof_bytes,
        &config,
        &context,
    )
    .expect("report produced");

    let error = report.error.expect("expected failure");
    assert!(matches!(error, VerifyError::ProofTooLarge { .. }));

    assert_snapshot!(
        "header_rejects_excessive_proof_size",
        hex_bytes(&header_bytes(&proof_bytes))
    );
}

#[test]
fn header_rejects_openings_offset_mismatch() {
    let fixture = FailMatrixFixture::new();
    let public_inputs = fixture.public_inputs();
    let config = fixture.config();
    let context = fixture.verifier_context();
    let mutated_bytes = mismatch_openings_offset(&fixture.proof_bytes());

    let err = verify_proof_bytes(
        ConfigProofKind::Tx,
        &public_inputs,
        &mutated_bytes,
        &config,
        &context,
    )
    .expect_err("openings offset mismatch must error");

    assert!(matches!(err, VerifyError::Serialization(SerKind::Proof)));

    assert_snapshot!(
        "header_rejects_openings_offset_mismatch",
        hex_bytes(&header_bytes(&mutated_bytes))
    );
}

#[test]
fn header_rejects_fri_offset_mismatch() {
    let fixture = FailMatrixFixture::new();
    let public_inputs = fixture.public_inputs();
    let config = fixture.config();
    let context = fixture.verifier_context();
    let mutated_bytes = mismatch_fri_offset(&fixture.proof_bytes());

    let err = verify_proof_bytes(
        ConfigProofKind::Tx,
        &public_inputs,
        &mutated_bytes,
        &config,
        &context,
    )
    .expect_err("fri offset mismatch must error");

    assert!(matches!(err, VerifyError::Serialization(SerKind::Fri)));

    assert_snapshot!(
        "header_rejects_fri_offset_mismatch",
        hex_bytes(&header_bytes(&mutated_bytes))
    );
}

#[test]
fn header_rejects_telemetry_offset_mismatch() {
    let fixture = FailMatrixFixture::new();
    let Some(mutated_bytes) = mismatch_telemetry_offset(&fixture.proof_bytes()) else {
        eprintln!("fixture does not expose telemetry; skipping test");
        return;
    };

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
    .expect_err("telemetry offset mismatch must error");

    assert!(matches!(
        err,
        VerifyError::Serialization(SerKind::Telemetry)
    ));

    assert_snapshot!(
        "header_rejects_telemetry_offset_mismatch",
        hex_bytes(&header_bytes(&mutated_bytes))
    );
}

#[test]
fn header_rejects_telemetry_flag_mismatch() {
    let fixture = FailMatrixFixture::new();
    let Some(mutated_bytes) = mismatch_telemetry_flag(&fixture.proof_bytes()) else {
        eprintln!("fixture does not expose telemetry; skipping test");
        return;
    };

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
    .expect_err("telemetry flag mismatch must error");

    assert!(matches!(
        err,
        VerifyError::Serialization(SerKind::TraceCommitment)
    ));

    assert_snapshot!(
        "header_rejects_telemetry_flag_mismatch",
        hex_bytes(&header_bytes(&mutated_bytes))
    );
}
