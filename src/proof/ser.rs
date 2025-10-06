//! Serialization helpers for the proof envelope.
//!
//! This module currently exposes the public function signatures required by the
//! documentation crate. Implementations are intentionally left as `todo!()` so
//! integrators can fill in the actual byte-level layout when wiring the proving
//! pipeline.

use crate::config::ProofKind;
use crate::proof::public_inputs::{ProofKind as PublicProofKind, PublicInputs};
use crate::proof::types::{Openings, OutOfDomainOpening, Proof, Telemetry, VerifyError};

/// Serialization failure surfaced while encoding a structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SerError {
    /// Input ended before the expected number of bytes were read.
    UnexpectedEnd {
        kind: super::types::SerKind,
        field: &'static str,
    },
    /// A length prefix exceeded the configured bounds or remaining buffer.
    InvalidLength {
        kind: super::types::SerKind,
        field: &'static str,
    },
    /// Encountered an unexpected discriminant or mismatching digest.
    InvalidValue {
        kind: super::types::SerKind,
        field: &'static str,
    },
}

impl SerError {
    /// Helper for signalling unexpected end-of-buffer conditions.
    pub fn unexpected_end(kind: super::types::SerKind, field: &'static str) -> Self {
        SerError::UnexpectedEnd { kind, field }
    }

    /// Helper for signalling invalid length prefixes.
    pub fn invalid_length(kind: super::types::SerKind, field: &'static str) -> Self {
        SerError::InvalidLength { kind, field }
    }

    /// Helper for signalling invalid discriminants.
    pub fn invalid_value(kind: super::types::SerKind, field: &'static str) -> Self {
        SerError::InvalidValue { kind, field }
    }
}

/// Computes the commitment digest over the commitment bundle.
pub fn compute_commitment_digest(
    _trace_cap: &[u8; 32],
    _composition_cap: &[u8; 32],
    _fri_layers: &[[u8; 32]],
) -> [u8; 32] {
    todo!("compute_commitment_digest is not implemented yet")
}

/// Computes the integrity digest over the header bytes and body payload.
pub fn compute_integrity_digest(_header_bytes: &[u8], _body_payload: &[u8]) -> [u8; 32] {
    todo!("compute_integrity_digest is not implemented yet")
}

/// Serialises the public inputs using the canonical layout.
pub fn serialize_public_inputs(_inputs: &PublicInputs<'_>) -> Vec<u8> {
    todo!("serialize_public_inputs is not implemented yet")
}

/// Maps a public proof kind to the configuration proof kind enumeration.
pub fn map_public_to_config_kind(_kind: PublicProofKind) -> ProofKind {
    todo!("map_public_to_config_kind is not implemented yet")
}

/// Serialises a [`Proof`] into its canonical byte representation.
pub fn serialize_proof(_proof: &Proof) -> Result<Vec<u8>, SerError> {
    todo!("serialize_proof is not implemented yet")
}

/// Deserialises a proof from its canonical representation.
pub fn deserialize_proof(_bytes: &[u8]) -> Result<Proof, VerifyError> {
    todo!("deserialize_proof is not implemented yet")
}

/// Serialises an [`Openings`] payload.
pub fn serialize_openings(_openings: &Openings) -> Vec<u8> {
    todo!("serialize_openings is not implemented yet")
}

/// Serialises a single out-of-domain opening entry.
pub fn serialize_out_of_domain_opening(_opening: &OutOfDomainOpening) -> Vec<u8> {
    todo!("serialize_out_of_domain_opening is not implemented yet")
}

/// Deserialises a single out-of-domain opening entry.
pub fn deserialize_out_of_domain_opening(_bytes: &[u8]) -> Result<OutOfDomainOpening, VerifyError> {
    todo!("deserialize_out_of_domain_opening is not implemented yet")
}

/// Serialises the proof header given the already encoded payload bytes.
pub fn serialize_proof_header(_proof: &Proof, _payload: &[u8]) -> Vec<u8> {
    todo!("serialize_proof_header is not implemented yet")
}

/// Serialises the proof payload body.
pub fn serialize_proof_payload(_proof: &Proof) -> Vec<u8> {
    todo!("serialize_proof_payload is not implemented yet")
}

/// Serialises the telemetry frame into bytes.
pub fn serialize_telemetry(_telemetry: &Telemetry) -> Vec<u8> {
    todo!("serialize_telemetry is not implemented yet")
}

/// Deserialises the telemetry frame from bytes.
pub fn deserialize_telemetry(_bytes: &[u8]) -> Result<Telemetry, VerifyError> {
    todo!("deserialize_telemetry is not implemented yet")
}
