//! Deterministic verifier implementation.
//!
//! The verifier performs structural checks over the proof header before any
//! expensive cryptographic work. Header parsing is intentionally lightweight so
//! callers can surface format issues without decoding the full payload.

use crate::config::{ProofKind as ConfigProofKind, ProofSystemConfig, VerifierContext};
use crate::proof::public_inputs::PublicInputs;
use crate::proof::ser::{
    compute_public_digest, deserialize_proof_header, encode_proof_kind, map_public_to_config_kind,
    serialize_public_inputs,
};
use crate::proof::types::{VerifyError, VerifyReport, PROOF_VERSION};
use crate::utils::serialization::ProofBytes;

/// Verifies a serialized proof against the provided configuration and context.
pub fn verify(
    declared_kind: ConfigProofKind,
    public_inputs: &PublicInputs<'_>,
    proof_bytes: &ProofBytes,
    config: &ProofSystemConfig,
    context: &VerifierContext,
) -> Result<VerifyReport, VerifyError> {
    if (config.proof_version.0 as u16) != PROOF_VERSION {
        return Err(VerifyError::VersionMismatch {
            expected: PROOF_VERSION,
            actual: config.proof_version.0 as u16,
        });
    }

    if config.param_digest != context.param_digest {
        return Err(VerifyError::ParamsHashMismatch);
    }

    let expected_kind = map_public_to_config_kind(public_inputs.kind());
    if declared_kind != expected_kind {
        return Err(VerifyError::UnknownProofKind(encode_proof_kind(
            declared_kind,
        )));
    }

    let total_len = proof_bytes.as_slice().len();
    let mut report = VerifyReport {
        params_ok: false,
        public_ok: false,
        merkle_ok: false,
        fri_ok: false,
        composition_ok: false,
        total_bytes: total_len as u64,
        proof: None,
        error: None,
    };

    let header = match deserialize_proof_header(proof_bytes.as_slice()) {
        Ok(header) => header,
        Err(error) => {
            report.error = Some(error);
            return Ok(report);
        }
    };

    if header.version != PROOF_VERSION {
        report.error = Some(VerifyError::VersionMismatch {
            expected: PROOF_VERSION,
            actual: header.version,
        });
        return Ok(report);
    }

    let max_bytes = context.limits.max_proof_size_bytes as usize;
    if total_len > max_bytes {
        let max_kb = ((max_bytes as u64 + 1023) / 1024).min(u32::MAX as u64) as u32;
        let got_kb = ((total_len as u64 + 1023) / 1024).min(u32::MAX as u64) as u32;
        report.error = Some(VerifyError::ProofTooLarge { max_kb, got_kb });
        return Ok(report);
    }

    let canonical_public_inputs = match serialize_public_inputs(public_inputs) {
        Ok(bytes) => bytes,
        Err(error) => {
            report.error = Some(VerifyError::from(error));
            return Ok(report);
        }
    };

    let expected_digest = compute_public_digest(&canonical_public_inputs);
    if expected_digest == header.public_digest {
        report.public_ok = true;
    } else {
        report.error = Some(VerifyError::PublicDigestMismatch);
        return Ok(report);
    }

    let params_bytes = header.params_hash;
    if params_bytes == *config.param_digest.as_bytes()
        && params_bytes == *context.param_digest.as_bytes()
    {
        report.params_ok = true;
    } else {
        report.error = Some(VerifyError::ParamsHashMismatch);
        return Ok(report);
    }

    let telemetry_len = header.telemetry_len.unwrap_or(0);
    let declared_payload_len = match header
        .openings_len
        .checked_add(header.fri_len)
        .and_then(|sum| sum.checked_add(telemetry_len))
    {
        Some(value) => value,
        None => {
            report.error = Some(VerifyError::BodyLengthMismatch {
                declared: u32::MAX,
                actual: u32::MAX,
            });
            return Ok(report);
        }
    };

    let available_payload = proof_bytes
        .as_slice()
        .len()
        .saturating_sub(header.payload_offset);
    if available_payload != declared_payload_len {
        let declared = declared_payload_len.min(u32::MAX as usize) as u32;
        let actual = available_payload.min(u32::MAX as usize) as u32;
        report.error = Some(VerifyError::BodyLengthMismatch { declared, actual });
        return Ok(report);
    }

    Ok(report)
}

pub fn verify_proof_bytes(
    declared_kind: ConfigProofKind,
    public_inputs: &PublicInputs<'_>,
    proof_bytes: &ProofBytes,
    config: &ProofSystemConfig,
    context: &VerifierContext,
) -> Result<VerifyReport, VerifyError> {
    verify(declared_kind, public_inputs, proof_bytes, config, context)
}
