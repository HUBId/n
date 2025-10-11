use insta::assert_snapshot;
use rpp_stark::config::ProofKind as ConfigProofKind;
use rpp_stark::proof::types::VerifyError;
use rpp_stark::proof::verifier::verify_proof_bytes;
use rpp_stark::utils::serialization::ProofBytes;
use std::convert::TryInto;

use super::{
    mismatch_telemetry_body_length, mismatch_telemetry_header_length,
    mismatch_telemetry_integrity_digest, FailMatrixFixture,
};

fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{:02x}", byte)).collect()
}

fn telemetry_frame_bytes(bytes: &ProofBytes) -> Option<Vec<u8>> {
    let slice = bytes.as_slice();
    let mut cursor = 0usize;
    cursor += 2; // version
    cursor += 32; // params hash
    cursor += 32; // public digest
    cursor += 32; // trace commitment digest

    let binding_len = u32::from_le_bytes(
        slice[cursor..cursor + 4]
            .try_into()
            .expect("binding length slice"),
    ) as usize;
    cursor += 4 + binding_len;

    let openings_offset = u32::from_le_bytes(
        slice[cursor..cursor + 4]
            .try_into()
            .expect("openings offset slice"),
    ) as usize;
    cursor += 4;
    let openings_len = u32::from_le_bytes(
        slice[cursor..cursor + 4]
            .try_into()
            .expect("openings length slice"),
    ) as usize;
    cursor += 4;

    let fri_offset = u32::from_le_bytes(
        slice[cursor..cursor + 4]
            .try_into()
            .expect("fri offset slice"),
    ) as usize;
    cursor += 4;
    let _fri_len = u32::from_le_bytes(
        slice[cursor..cursor + 4]
            .try_into()
            .expect("fri length slice"),
    ) as usize;
    cursor += 4;

    let telemetry_flag = slice[cursor];
    cursor += 1;
    if telemetry_flag == 0 {
        return None;
    }

    let telemetry_offset = u32::from_le_bytes(
        slice[cursor..cursor + 4]
            .try_into()
            .expect("telemetry offset slice"),
    ) as usize;
    cursor += 4;
    let telemetry_len = u32::from_le_bytes(
        slice[cursor..cursor + 4]
            .try_into()
            .expect("telemetry length slice"),
    ) as usize;
    cursor += 4;

    let payload_start = cursor;

    debug_assert_eq!(openings_offset, 0);
    debug_assert_eq!(fri_offset, openings_len);

    let start = payload_start + telemetry_offset;
    let end = start + telemetry_len;
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

    let report = verify_proof_bytes(
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

    let report = verify_proof_bytes(
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

    let report = verify_proof_bytes(
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
