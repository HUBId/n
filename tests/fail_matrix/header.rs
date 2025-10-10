use insta::assert_snapshot;
use rpp_stark::config::ProofKind as ConfigProofKind;
use rpp_stark::proof::types::VerifyError;
use rpp_stark::proof::verifier::verify_proof_bytes;
use rpp_stark::utils::serialization::ProofBytes;
use std::convert::TryInto;

use super::{
    flip_header_version, flip_param_digest_byte, flip_public_digest_byte, FailMatrixFixture,
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
    let slice = bytes.as_slice();
    let mut cursor = 0usize;
    cursor += 2; // version
    cursor += 1; // kind
    cursor += 32; // params hash
    cursor += 32; // air spec id

    let public_len = u32::from_le_bytes(
        slice[cursor..cursor + 4]
            .try_into()
            .expect("public length slice"),
    ) as usize;
    cursor += 4;
    cursor += public_len; // public inputs bytes

    cursor += 32; // public digest
    cursor += 32; // trace commitment digest

    let composition_flag = slice[cursor];
    cursor += 1;
    if composition_flag == 1 {
        cursor += 32; // composition digest
    }

    cursor += 4; // merkle length
    cursor += 4; // fri length
    cursor += 4; // openings length

    let telemetry_flag = slice[cursor];
    cursor += 1;
    if telemetry_flag == 1 {
        cursor += 4; // telemetry length prefix
    }

    slice[..cursor].to_vec()
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
