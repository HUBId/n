//! Serialization helpers for the proof envelope.
//!
//! The routines in this module encapsulate the canonical byte-level contracts
//! shared by the prover and verifier. They intentionally expose pure helpers so
//! the layout documented by [`super::types::Proof`] can be reused across the
//! crate without reimplementing framing logic.

use crate::config::ProofKind;
use crate::fri::FriProof;
use crate::hash::Hasher;
use crate::proof::public_inputs::{
    AggregationHeaderV1, ExecutionHeaderV1, ProofKind as PublicProofKind, PublicInputVersion,
    PublicInputs, RecursionHeaderV1, VrfHeaderV1,
};
use crate::proof::types::VerifyError;

/// Computes the commitment digest over core, auxiliary and FRI layer roots.
pub fn compute_commitment_digest(
    core_root: &[u8; 32],
    aux_root: &[u8; 32],
    fri_layer_roots: &[[u8; 32]],
) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(core_root);
    hasher.update(aux_root);
    for root in fri_layer_roots {
        hasher.update(root);
    }
    *hasher.finalize().as_bytes()
}

/// Computes the integrity digest over the header bytes and body payload.
pub fn compute_integrity_digest(header_bytes: &[u8], body_payload: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(header_bytes);
    hasher.update(body_payload);
    *hasher.finalize().as_bytes()
}

/// Serialises the public inputs using the canonical layout.
pub fn serialize_public_inputs(inputs: &PublicInputs<'_>) -> Vec<u8> {
    fn version_byte(version: PublicInputVersion) -> u8 {
        match version {
            PublicInputVersion::V1 => 1,
        }
    }

    match inputs {
        PublicInputs::Execution { header, body } => {
            let ExecutionHeaderV1 {
                version,
                program_digest,
                trace_length,
                trace_width,
            } = header;
            let mut buffer = Vec::new();
            buffer.push(version_byte(*version));
            buffer.extend_from_slice(&program_digest.bytes);
            buffer.extend_from_slice(&trace_length.to_le_bytes());
            buffer.extend_from_slice(&trace_width.to_le_bytes());
            buffer.extend_from_slice(&(body.len() as u32).to_le_bytes());
            buffer.extend_from_slice(body);
            buffer
        }
        PublicInputs::Aggregation { header, body } => {
            let AggregationHeaderV1 {
                version,
                circuit_digest,
                leaf_count,
                root_digest,
            } = header;
            let mut buffer = Vec::new();
            buffer.push(version_byte(*version));
            buffer.extend_from_slice(&circuit_digest.bytes);
            buffer.extend_from_slice(&leaf_count.to_le_bytes());
            buffer.extend_from_slice(&root_digest.bytes);
            buffer.extend_from_slice(&(body.len() as u32).to_le_bytes());
            buffer.extend_from_slice(body);
            buffer
        }
        PublicInputs::Recursion { header, body } => {
            let RecursionHeaderV1 {
                version,
                depth,
                boundary_digest,
                recursion_seed,
            } = header;
            let mut buffer = Vec::new();
            buffer.push(version_byte(*version));
            buffer.push(*depth);
            buffer.extend_from_slice(&boundary_digest.bytes);
            buffer.extend_from_slice(&recursion_seed.bytes);
            buffer.extend_from_slice(&(body.len() as u32).to_le_bytes());
            buffer.extend_from_slice(body);
            buffer
        }
        PublicInputs::Vrf { header, body } => {
            let VrfHeaderV1 {
                version,
                public_key_commit,
                prf_param_digest,
                rlwe_param_id,
                vrf_param_id,
                transcript_version_id,
                field_id,
                context_digest,
            } = header;
            let mut buffer = Vec::new();
            buffer.push(version_byte(*version));
            buffer.extend_from_slice(&public_key_commit.bytes);
            buffer.extend_from_slice(&prf_param_digest.bytes);
            buffer.extend_from_slice(rlwe_param_id.as_bytes());
            buffer.extend_from_slice(vrf_param_id.as_bytes());
            let tv = transcript_version_id.clone().bytes();
            buffer.extend_from_slice(&tv.bytes);
            buffer.extend_from_slice(&field_id.to_le_bytes());
            buffer.extend_from_slice(&context_digest.bytes);
            buffer.extend_from_slice(&(body.len() as u32).to_le_bytes());
            buffer.extend_from_slice(body);
            buffer
        }
    }
}

/// Maps a public-input proof kind to the global configuration ordering.
pub fn map_public_to_config_kind(kind: PublicProofKind) -> ProofKind {
    use crate::proof::public_inputs::ProofKind as PublicKind;
    match kind {
        PublicKind::Execution => ProofKind::Tx,
        PublicKind::Aggregation => ProofKind::Aggregation,
        PublicKind::Recursion => ProofKind::State,
        PublicKind::VrfPostQuantum => ProofKind::VRF,
    }
}

pub(crate) fn encode_proof_kind(kind: ProofKind) -> u8 {
    match kind {
        ProofKind::Tx => 0,
        ProofKind::State => 1,
        ProofKind::Pruning => 2,
        ProofKind::Uptime => 3,
        ProofKind::Consensus => 4,
        ProofKind::Identity => 5,
        ProofKind::Aggregation => 6,
        ProofKind::VRF => 7,
    }
}

pub(crate) fn decode_proof_kind(byte: u8) -> Result<ProofKind, VerifyError> {
    Ok(match byte {
        0 => ProofKind::Tx,
        1 => ProofKind::State,
        2 => ProofKind::Pruning,
        3 => ProofKind::Uptime,
        4 => ProofKind::Consensus,
        5 => ProofKind::Identity,
        6 => ProofKind::Aggregation,
        7 => ProofKind::VRF,
        other => return Err(VerifyError::UnknownProofKind(other)),
    })
}

pub(crate) fn serialize_fri_proof(proof: &FriProof) -> Vec<u8> {
    proof
        .to_bytes()
        .expect("FRI proofs embedded in envelopes must be valid")
}

pub(crate) fn deserialize_fri_proof(bytes: &[u8]) -> Result<FriProof, VerifyError> {
    FriProof::from_bytes(bytes).map_err(|_| VerifyError::InvalidFriSection("fri_proof".to_string()))
}
