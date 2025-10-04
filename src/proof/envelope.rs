//! Proof envelope describing versioning and integrity layout.
//!
//! The envelope is the canonical container that wraps every proof byte stream
//! produced by the system. It ensures that verifiers can reason about the
//! version, the declared proof kind, the length of both header and body, and
//! the integrity digest without parsing custom metadata formats.

use crate::proof::public_inputs::ProofKind;
use crate::utils::serialization::DigestBytes;

/// Maximum allowed size for a proof including envelope metadata.
pub const MAX_PROOF_SIZE_BYTES: usize = 32 * 1024 * 1024;

/// Enumerates the current envelope format versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvelopeVersion {
    /// Initial format using fixed width little endian counters.
    V1,
}

/// Header written ahead of the proof body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofEnvelopeHeader {
    /// Version of the envelope layout.
    pub version: EnvelopeVersion,
    /// Declared proof kind. Mirrors the header layout chosen for the
    /// public inputs.
    pub kind: ProofKind,
    /// Length of the serialized header segment that follows this struct.
    pub header_length: u32,
    /// Length of the serialized body.
    pub body_length: u32,
    /// Digest binding the header and body for integrity checks.
    pub integrity_digest: DigestBytes,
}

impl ProofEnvelopeHeader {
    /// Returns the total declared payload length (header + body).
    pub fn total_payload_length(&self) -> u64 {
        self.header_length as u64 + self.body_length as u64
    }
}

/// Envelope containing header metadata and the proof body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofEnvelope {
    /// Structured metadata describing the proof stream.
    pub header: ProofEnvelopeHeader,
    /// Raw proof bytes following the header.
    pub body: Vec<u8>,
}

impl ProofEnvelope {
    /// Creates a new envelope and performs basic boundary documentation.
    pub fn new(header: ProofEnvelopeHeader, body: Vec<u8>) -> Self {
        debug_assert!(body.len() <= MAX_PROOF_SIZE_BYTES);
        Self { header, body }
    }
}
