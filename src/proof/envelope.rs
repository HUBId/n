//! Proof envelope assembly helpers.
//!
//! The builder exposed by this module mirrors the specification but intentionally
//! leaves all logic unimplemented. This allows downstream implementers to wire in
//! real serialization once the proving components are available.

pub use crate::proof::ser::{
    compute_commitment_digest, compute_integrity_digest, deserialize_proof, serialize_proof,
    serialize_proof_header, serialize_proof_payload, serialize_public_inputs,
};
use crate::proof::types::{MerkleProofBundle, Openings, Proof, Telemetry, VerifyError};

/// Result emitted by [`ProofBuilder::build`].
#[derive(Debug, Clone)]
pub struct BuiltProof {
    /// Fully assembled proof container.
    pub proof: Proof,
    /// Serialized header bytes.
    pub header_bytes: Vec<u8>,
    /// Serialized payload bytes.
    pub payload_bytes: Vec<u8>,
}

impl BuiltProof {
    /// Consumes the built proof and returns the contained [`Proof`].
    pub fn into_proof(self) -> Proof {
        self.proof
    }
}

/// Skeleton builder for proof envelopes.
#[derive(Debug, Clone)]
pub struct ProofBuilder {
    proof: Option<Proof>,
    merkle: Option<MerkleProofBundle>,
    openings: Option<Openings>,
    telemetry: Option<Telemetry>,
}

impl ProofBuilder {
    /// Creates a new builder instance.
    pub fn new() -> Self {
        Self {
            proof: None,
            merkle: None,
            openings: None,
            telemetry: None,
        }
    }

    /// Attaches the partially constructed proof container.
    pub fn with_proof(mut self, proof: Proof) -> Self {
        self.proof = Some(proof);
        self
    }

    /// Injects the Merkle bundle into the builder.
    pub fn with_merkle(mut self, merkle: MerkleProofBundle) -> Self {
        self.merkle = Some(merkle);
        self
    }

    /// Injects the openings payload into the builder.
    pub fn with_openings(mut self, openings: Openings) -> Self {
        self.openings = Some(openings);
        self
    }

    /// Injects the telemetry frame into the builder.
    pub fn with_telemetry(mut self, telemetry: Telemetry) -> Self {
        self.telemetry = Some(telemetry);
        self
    }

    /// Finalises the builder and returns a [`BuiltProof`].
    pub fn build(self) -> Result<BuiltProof, VerifyError> {
        let proof = self
            .proof
            .ok_or_else(|| VerifyError::Serialization(super::types::SerKind::Proof))?;
        let header_bytes = serialize_proof_header(&proof, &[]);
        let payload_bytes = serialize_proof_payload(&proof);
        Ok(BuiltProof {
            proof,
            header_bytes,
            payload_bytes,
        })
    }
}

impl Proof {
    /// Serialises the proof into bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        serialize_proof(self).expect("proof serialization not implemented")
    }

    /// Deserialises a proof from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, VerifyError> {
        deserialize_proof(bytes)
    }

    /// Serialises the proof header given the payload bytes.
    pub fn serialize_header(&self, payload: &[u8]) -> Vec<u8> {
        serialize_proof_header(self, payload)
    }

    /// Serialises the proof payload body.
    pub fn serialize_payload(&self) -> Vec<u8> {
        serialize_proof_payload(self)
    }
}
