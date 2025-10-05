//! Proof envelope implementation and serialization helpers.
//!
//! The module implements the canonical byte layout mandated by the
//! specification.  Both prover and verifier share this code to ensure that the
//! same length prefixes, digests and field orderings are used throughout the
//! pipeline.

use std::convert::TryInto;

use crate::config::{AirSpecId, ParamDigest, ProofKind};
use crate::field::prime_field::{CanonicalSerialize, FieldDeserializeError};
use crate::field::FieldElement;
use crate::fri::types::{FriProof, FriQuery, FriQueryLayer, FriSecurityLevel};
use crate::hash::merkle::{MerkleIndex, MerklePathElement};
use crate::hash::Hasher;
use crate::proof::public_inputs::{
    AggregationHeaderV1, ExecutionHeaderV1, PublicInputVersion, PublicInputs, RecursionHeaderV1,
    VrfHeaderV1,
};
use crate::utils::serialization::DigestBytes;

/// Canonical proof version implemented by this crate.
pub const PROOF_VERSION: u8 = 1;

/// Errors surfaced while decoding or encoding an envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvelopeError {
    /// The proof version encoded in the header is not supported.
    UnsupportedVersion(u8),
    /// The proof kind byte does not match the canonical ordering.
    UnknownProofKind(u8),
    /// Declared header length does not match the observed byte count.
    HeaderLengthMismatch { declared: u32, actual: u32 },
    /// Declared body length does not match the observed byte count.
    BodyLengthMismatch { declared: u32, actual: u32 },
    /// The buffer ended prematurely while parsing a section.
    UnexpectedEndOfBuffer(&'static str),
    /// Integrity digest recomputed from the payload disagreed with the header.
    IntegrityDigestMismatch,
    /// The FRI section contained invalid structure.
    InvalidFriSection(&'static str),
    /// Encountered a non-canonical field element while decoding.
    NonCanonicalFieldElement,
}

/// Complete proof envelope grouping header and body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofEnvelope {
    /// Header component (version, kind, parameter digest and commitments).
    pub header: ProofEnvelopeHeader,
    /// Body component (commitments, openings and FRI proof).
    pub body: ProofEnvelopeBody,
}

impl ProofEnvelope {
    /// Serialises the envelope into a byte vector using the canonical layout.
    pub fn to_bytes(&self) -> Vec<u8> {
        let header_bytes = self.header.serialize(&self.body);
        let payload = self.body.serialize_payload();
        let integrity = compute_integrity_digest(&header_bytes, &payload);

        let mut bytes = Vec::with_capacity(
            header_bytes.len() + payload.len() + DigestBytes::default().bytes.len(),
        );
        bytes.extend_from_slice(&header_bytes);
        bytes.extend_from_slice(&payload);
        bytes.extend_from_slice(&integrity);
        bytes
    }

    /// Parses an envelope from a byte slice, validating all length prefixes and
    /// integrity digests along the way.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EnvelopeError> {
        let mut cursor = Cursor::new(bytes);

        let proof_version = cursor.read_u8()?;
        if proof_version != PROOF_VERSION {
            return Err(EnvelopeError::UnsupportedVersion(proof_version));
        }

        let kind_byte = cursor.read_u8()?;
        let proof_kind = decode_proof_kind(kind_byte)?;

        let param_digest = ParamDigest(DigestBytes {
            bytes: cursor.read_digest()?,
        });
        let air_spec_id = AirSpecId(DigestBytes {
            bytes: cursor.read_digest()?,
        });

        let public_input_len = cursor.read_u32()? as usize;
        let public_inputs = cursor.read_vec(public_input_len)?;
        let commitment_digest = DigestBytes {
            bytes: cursor.read_digest()?,
        };

        let header_length = cursor.read_u32()?;
        let body_length = cursor.read_u32()?;

        let header_bytes_consumed = cursor.offset();
        let expected_header_length = (2 + 32 + 32 + 4 + public_input_len + 32 + 4 + 4) as u32;
        if expected_header_length != header_length {
            return Err(EnvelopeError::HeaderLengthMismatch {
                declared: header_length,
                actual: expected_header_length,
            });
        }
        if header_bytes_consumed as u32 != header_length {
            return Err(EnvelopeError::HeaderLengthMismatch {
                declared: header_length,
                actual: header_bytes_consumed as u32,
            });
        }

        if body_length < DigestBytes::default().bytes.len() as u32 {
            return Err(EnvelopeError::BodyLengthMismatch {
                declared: body_length,
                actual: body_length,
            });
        }

        let body_bytes = cursor.read_vec(body_length as usize)?;
        if cursor.remaining() != 0 {
            return Err(EnvelopeError::UnexpectedEndOfBuffer(
                "trailing_header_bytes",
            ));
        }

        if body_bytes.len() != body_length as usize {
            return Err(EnvelopeError::BodyLengthMismatch {
                declared: body_length,
                actual: body_bytes.len() as u32,
            });
        }

        if body_bytes.len() < DigestBytes::default().bytes.len() {
            return Err(EnvelopeError::BodyLengthMismatch {
                declared: body_length,
                actual: body_bytes.len() as u32,
            });
        }

        let (payload, integrity_bytes) = body_bytes.split_at(body_bytes.len() - 32);
        let integrity_digest: [u8; 32] = integrity_bytes.try_into().unwrap();

        let mut payload_cursor = Cursor::new(payload);
        let core_root = payload_cursor.read_digest()?;
        let aux_root = payload_cursor.read_digest()?;
        let fri_layer_count = payload_cursor.read_u32()? as usize;
        let mut fri_layer_roots = Vec::with_capacity(fri_layer_count);
        for _ in 0..fri_layer_count {
            fri_layer_roots.push(payload_cursor.read_digest()?);
        }

        let ood_count = payload_cursor.read_u32()? as usize;
        let mut ood_openings = Vec::with_capacity(ood_count);
        for _ in 0..ood_count {
            let block_len = payload_cursor.read_u32()? as usize;
            let block_bytes = payload_cursor.read_vec(block_len)?;
            let opening = OutOfDomainOpening::deserialize(&block_bytes)?;
            ood_openings.push(opening);
        }

        let fri_section_len = payload_cursor.read_u32()? as usize;
        let fri_section = payload_cursor.read_vec(fri_section_len)?;
        let fri_proof = deserialize_fri_proof(&fri_section)?;

        let fri_parameters = FriParametersMirror {
            fold: payload_cursor.read_u8()?,
            cap_degree: payload_cursor.read_u16()?,
            cap_size: payload_cursor.read_u32()?,
            query_budget: payload_cursor.read_u16()?,
        };

        if payload_cursor.remaining() != 0 {
            return Err(EnvelopeError::UnexpectedEndOfBuffer("body_padding"));
        }

        let header = ProofEnvelopeHeader {
            proof_version,
            proof_kind,
            param_digest,
            air_spec_id,
            public_inputs,
            commitment_digest,
            header_length,
            body_length,
        };

        let mut body = ProofEnvelopeBody {
            core_root,
            aux_root,
            fri_layer_roots,
            ood_openings,
            fri_proof,
            fri_parameters,
            integrity_digest: DigestBytes {
                bytes: integrity_digest,
            },
        };

        let header_bytes = header.serialize(&body);
        let payload = body.serialize_payload();
        let computed_integrity = compute_integrity_digest(&header_bytes, &payload);
        if computed_integrity != integrity_digest {
            return Err(EnvelopeError::IntegrityDigestMismatch);
        }

        // Preserve the canonical integrity digest in the body before returning.
        body.integrity_digest = DigestBytes {
            bytes: integrity_digest,
        };

        Ok(Self { header, body })
    }
}

/// Envelope header storing metadata and public inputs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofEnvelopeHeader {
    /// Proof version encoded in the header (currently `1`).
    pub proof_version: u8,
    /// Canonical proof kind.
    pub proof_kind: ProofKind,
    /// Parameter digest binding configuration knobs.
    pub param_digest: ParamDigest,
    /// AIR specification identifier for the proof kind.
    pub air_spec_id: AirSpecId,
    /// Canonical public input encoding.
    pub public_inputs: Vec<u8>,
    /// Digest binding commitments prior to parsing the body.
    pub commitment_digest: DigestBytes,
    /// Declared header length (mainly for sanity checks).
    pub header_length: u32,
    /// Declared body length (includes integrity digest).
    pub body_length: u32,
}

impl ProofEnvelopeHeader {
    pub(crate) fn serialize(&self, body: &ProofEnvelopeBody) -> Vec<u8> {
        let payload = body.serialize_payload();
        let body_length = (payload.len() + 32) as u32;

        let header_length = (2 + 32 + 32 + 4 + self.public_inputs.len() + 32 + 4 + 4) as u32;

        let mut buffer = Vec::with_capacity(header_length as usize);
        buffer.push(self.proof_version);
        buffer.push(encode_proof_kind(self.proof_kind));
        buffer.extend_from_slice(&self.param_digest.0.bytes);
        let air_spec = self.air_spec_id.clone().bytes();
        buffer.extend_from_slice(&air_spec.bytes);
        buffer.extend_from_slice(&(self.public_inputs.len() as u32).to_le_bytes());
        buffer.extend_from_slice(&self.public_inputs);
        buffer.extend_from_slice(&self.commitment_digest.bytes);
        buffer.extend_from_slice(&header_length.to_le_bytes());
        buffer.extend_from_slice(&body_length.to_le_bytes());
        buffer
    }
}

/// Envelope body storing commitments, openings and the FRI proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofEnvelopeBody {
    /// Core commitment root.
    pub core_root: [u8; 32],
    /// Auxiliary commitment root (zero if absent).
    pub aux_root: [u8; 32],
    /// FRI layer roots.
    pub fri_layer_roots: Vec<[u8; 32]>,
    /// Out-of-domain openings.
    pub ood_openings: Vec<OutOfDomainOpening>,
    /// FRI proof payload.
    pub fri_proof: FriProof,
    /// Optional mirror of the FRI parameters.
    pub fri_parameters: FriParametersMirror,
    /// Integrity digest stored at the end of the body.
    pub integrity_digest: DigestBytes,
}

impl ProofEnvelopeBody {
    pub(crate) fn serialize_payload(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&self.core_root);
        buffer.extend_from_slice(&self.aux_root);
        buffer.extend_from_slice(&(self.fri_layer_roots.len() as u32).to_le_bytes());
        for root in &self.fri_layer_roots {
            buffer.extend_from_slice(root);
        }

        buffer.extend_from_slice(&(self.ood_openings.len() as u32).to_le_bytes());
        for opening in &self.ood_openings {
            let encoded = opening.serialize();
            buffer.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
            buffer.extend_from_slice(&encoded);
        }

        let fri_bytes = serialize_fri_proof(&self.fri_proof);
        buffer.extend_from_slice(&(fri_bytes.len() as u32).to_le_bytes());
        buffer.extend_from_slice(&fri_bytes);

        buffer.push(self.fri_parameters.fold);
        buffer.extend_from_slice(&self.fri_parameters.cap_degree.to_le_bytes());
        buffer.extend_from_slice(&self.fri_parameters.cap_size.to_le_bytes());
        buffer.extend_from_slice(&self.fri_parameters.query_budget.to_le_bytes());
        buffer
    }
}

/// Mirror of the FRI parameters stored inside the envelope body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FriParametersMirror {
    /// Folding factor (fixed to four in the current implementation).
    pub fold: u8,
    /// Degree of the cap polynomial.
    pub cap_degree: u16,
    /// Size of the cap commitment.
    pub cap_size: u32,
    /// Query budget.
    pub query_budget: u16,
}

impl Default for FriParametersMirror {
    fn default() -> Self {
        Self {
            fold: 4,
            cap_degree: 0,
            cap_size: 0,
            query_budget: 0,
        }
    }
}

/// Out-of-domain opening description.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutOfDomainOpening {
    /// OOD evaluation point.
    pub point: [u8; 32],
    /// Core trace evaluations at that point.
    pub core_values: Vec<[u8; 32]>,
    /// Auxiliary evaluations.
    pub aux_values: Vec<[u8; 32]>,
    /// Composition polynomial evaluation.
    pub composition_value: [u8; 32],
}

impl OutOfDomainOpening {
    pub(crate) fn serialize(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&self.point);
        buffer.extend_from_slice(&(self.core_values.len() as u32).to_le_bytes());
        for value in &self.core_values {
            buffer.extend_from_slice(value);
        }
        buffer.extend_from_slice(&(self.aux_values.len() as u32).to_le_bytes());
        for value in &self.aux_values {
            buffer.extend_from_slice(value);
        }
        buffer.extend_from_slice(&self.composition_value);
        buffer
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, EnvelopeError> {
        let mut cursor = Cursor::new(bytes);
        let point = cursor.read_digest()?;
        let core_len = cursor.read_u32()? as usize;
        let mut core_values = Vec::with_capacity(core_len);
        for _ in 0..core_len {
            core_values.push(cursor.read_digest()?);
        }
        let aux_len = cursor.read_u32()? as usize;
        let mut aux_values = Vec::with_capacity(aux_len);
        for _ in 0..aux_len {
            aux_values.push(cursor.read_digest()?);
        }
        let composition_value = cursor.read_digest()?;
        if cursor.remaining() != 0 {
            return Err(EnvelopeError::UnexpectedEndOfBuffer("ood_padding"));
        }
        Ok(Self {
            point,
            core_values,
            aux_values,
            composition_value,
        })
    }
}

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
pub fn map_public_to_config_kind(kind: crate::proof::public_inputs::ProofKind) -> ProofKind {
    use crate::proof::public_inputs::ProofKind as PublicKind;
    match kind {
        PublicKind::Execution => ProofKind::Tx,
        PublicKind::Aggregation => ProofKind::Aggregation,
        PublicKind::Recursion => ProofKind::State,
        PublicKind::VrfPostQuantum => ProofKind::VRF,
    }
}

fn encode_proof_kind(kind: ProofKind) -> u8 {
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

fn decode_proof_kind(byte: u8) -> Result<ProofKind, EnvelopeError> {
    Ok(match byte {
        0 => ProofKind::Tx,
        1 => ProofKind::State,
        2 => ProofKind::Pruning,
        3 => ProofKind::Uptime,
        4 => ProofKind::Consensus,
        5 => ProofKind::Identity,
        6 => ProofKind::Aggregation,
        7 => ProofKind::VRF,
        other => return Err(EnvelopeError::UnknownProofKind(other)),
    })
}

fn serialize_fri_proof(proof: &FriProof) -> Vec<u8> {
    let mut buffer = Vec::new();
    buffer.push(match proof.security_level {
        FriSecurityLevel::Standard => 0,
        FriSecurityLevel::HiSec => 1,
        FriSecurityLevel::Throughput => 2,
    });
    buffer.extend_from_slice(&(proof.initial_domain_size as u32).to_le_bytes());
    buffer.extend_from_slice(&(proof.layer_roots.len() as u32).to_le_bytes());
    for root in &proof.layer_roots {
        buffer.extend_from_slice(root);
    }
    buffer.extend_from_slice(&(proof.final_polynomial.len() as u32).to_le_bytes());
    for value in &proof.final_polynomial {
        buffer.extend_from_slice(&field_to_bytes(*value));
    }
    buffer.extend_from_slice(&proof.final_polynomial_digest);
    buffer.extend_from_slice(&(proof.queries.len() as u32).to_le_bytes());
    for query in &proof.queries {
        buffer.extend_from_slice(&(query.position as u64).to_le_bytes());
        buffer.extend_from_slice(&(query.layers.len() as u32).to_le_bytes());
        for layer in &query.layers {
            buffer.extend_from_slice(&field_to_bytes(layer.value));
            buffer.extend_from_slice(&(layer.path.len() as u32).to_le_bytes());
            for element in &layer.path {
                buffer.push(element.index.0);
                for sibling in &element.siblings {
                    buffer.extend_from_slice(sibling);
                }
            }
        }
        buffer.extend_from_slice(&field_to_bytes(query.final_value));
    }
    buffer
}

fn deserialize_fri_proof(bytes: &[u8]) -> Result<FriProof, EnvelopeError> {
    let mut cursor = Cursor::new(bytes);
    let security_level = match cursor.read_u8()? {
        0 => FriSecurityLevel::Standard,
        1 => FriSecurityLevel::HiSec,
        2 => FriSecurityLevel::Throughput,
        _ => return Err(EnvelopeError::InvalidFriSection("security_level")),
    };
    let initial_domain_size = cursor.read_u32()? as usize;
    let layer_count = cursor.read_u32()? as usize;
    let mut layer_roots = Vec::with_capacity(layer_count);
    for _ in 0..layer_count {
        layer_roots.push(cursor.read_digest()?);
    }
    let final_len = cursor.read_u32()? as usize;
    let mut final_polynomial = Vec::with_capacity(final_len);
    for _ in 0..final_len {
        final_polynomial.push(field_from_bytes(cursor.read_digest()?)?);
    }
    let final_polynomial_digest = cursor.read_digest()?;
    let query_len = cursor.read_u32()? as usize;
    let mut queries = Vec::with_capacity(query_len);
    for _ in 0..query_len {
        let position = cursor.read_u64()? as usize;
        let layer_len = cursor.read_u32()? as usize;
        let mut layers = Vec::with_capacity(layer_len);
        for _ in 0..layer_len {
            let value = field_from_bytes(cursor.read_digest()?)?;
            let path_len = cursor.read_u32()? as usize;
            let mut path = Vec::with_capacity(path_len);
            for _ in 0..path_len {
                let index = cursor.read_u8()?;
                let mut siblings = [[0u8; 32]; 3];
                for sibling in siblings.iter_mut() {
                    *sibling = cursor.read_digest()?;
                }
                path.push(MerklePathElement {
                    index: MerkleIndex(index),
                    siblings,
                });
            }
            layers.push(FriQueryLayer { value, path });
        }
        let final_value = field_from_bytes(cursor.read_digest()?)?;
        queries.push(FriQuery {
            position,
            layers,
            final_value,
        });
    }

    if cursor.remaining() != 0 {
        return Err(EnvelopeError::InvalidFriSection("trailing_bytes"));
    }

    Ok(FriProof {
        security_level,
        initial_domain_size,
        layer_roots,
        final_polynomial,
        final_polynomial_digest,
        queries,
    })
}

fn field_to_bytes(value: FieldElement) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[..8].copy_from_slice(&value.0.to_le_bytes());
    out
}

fn field_from_bytes(bytes: [u8; 32]) -> Result<FieldElement, EnvelopeError> {
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[..8]);
    FieldElement::from_bytes(&buf).map_err(|FieldDeserializeError::FieldDeserializeNonCanonical| {
        EnvelopeError::NonCanonicalFieldElement
    })
}

/// Thin cursor helper used by the serializer/deserializer.
struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.offset)
    }

    fn offset(&self) -> usize {
        self.offset
    }

    fn read_u8(&mut self) -> Result<u8, EnvelopeError> {
        if self.remaining() < 1 {
            return Err(EnvelopeError::UnexpectedEndOfBuffer("u8"));
        }
        let value = self.bytes[self.offset];
        self.offset += 1;
        Ok(value)
    }

    fn read_u16(&mut self) -> Result<u16, EnvelopeError> {
        let bytes = self.read_fixed::<2>()?;
        Ok(u16::from_le_bytes(bytes))
    }

    fn read_u32(&mut self) -> Result<u32, EnvelopeError> {
        let bytes = self.read_fixed::<4>()?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn read_u64(&mut self) -> Result<u64, EnvelopeError> {
        let bytes = self.read_fixed::<8>()?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn read_vec(&mut self, len: usize) -> Result<Vec<u8>, EnvelopeError> {
        if self.remaining() < len {
            return Err(EnvelopeError::UnexpectedEndOfBuffer("vec"));
        }
        let slice = &self.bytes[self.offset..self.offset + len];
        self.offset += len;
        Ok(slice.to_vec())
    }

    fn read_digest(&mut self) -> Result<[u8; 32], EnvelopeError> {
        self.read_fixed::<32>()
    }

    fn read_fixed<const N: usize>(&mut self) -> Result<[u8; N], EnvelopeError> {
        if self.remaining() < N {
            return Err(EnvelopeError::UnexpectedEndOfBuffer("fixed"));
        }
        let mut out = [0u8; N];
        out.copy_from_slice(&self.bytes[self.offset..self.offset + N]);
        self.offset += N;
        Ok(out)
    }
}

impl Default for DigestBytes {
    fn default() -> Self {
        Self { bytes: [0u8; 32] }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        build_prover_context, compute_param_digest, ChunkingPolicy, ParamDigest, ProofKind,
        ProofSystemConfig, ThreadPoolProfile, COMMON_IDENTIFIERS, PROFILE_STANDARD_CONFIG,
        PROOF_VERSION_V1,
    };
    use crate::field::FieldElement;
    use crate::fri::types::FriSecurityLevel;
    use crate::proof::prover::build_envelope as build_proof_envelope;
    use crate::proof::public_inputs::{ExecutionHeaderV1, PublicInputVersion, PublicInputs};
    use crate::utils::serialization::{DigestBytes, WitnessBlob};

    fn sample_fri_proof() -> FriProof {
        let evaluations: Vec<FieldElement> =
            (0..1024).map(|i| FieldElement(i as u64 + 1)).collect();
        let seed = [7u8; 32];
        FriProof::prove(FriSecurityLevel::Standard, seed, &evaluations).expect("fri proof")
    }

    fn build_sample_envelope() -> ProofEnvelope {
        let fri_proof = sample_fri_proof();
        let fri_layer_roots = fri_proof.layer_roots.clone();
        let core_root = fri_layer_roots.first().copied().unwrap_or([0u8; 32]);
        let aux_root = [1u8; 32];
        let commitment_digest = compute_commitment_digest(&core_root, &aux_root, &fri_layer_roots);

        let header = ExecutionHeaderV1 {
            version: PublicInputVersion::V1,
            program_digest: DigestBytes { bytes: [2u8; 32] },
            trace_length: 1024,
            trace_width: 16,
        };
        let body_bytes: Vec<u8> = Vec::new();
        let public_inputs = PublicInputs::Execution {
            header: header.clone(),
            body: &body_bytes,
        };
        let public_input_bytes = serialize_public_inputs(&public_inputs);

        let mut body = ProofEnvelopeBody {
            core_root,
            aux_root,
            fri_layer_roots,
            ood_openings: Vec::new(),
            fri_parameters: FriParametersMirror {
                fold: 4,
                cap_degree: 256,
                cap_size: fri_proof.final_polynomial.len() as u32,
                query_budget: FriSecurityLevel::Standard.query_budget() as u16,
            },
            fri_proof,
            integrity_digest: DigestBytes::default(),
        };

        let payload = body.serialize_payload();
        let body_length = (payload.len() + 32) as u32;
        let header_length = (2 + 32 + 32 + 4 + public_input_bytes.len() + 32 + 4 + 4) as u32;

        let header = ProofEnvelopeHeader {
            proof_version: PROOF_VERSION,
            proof_kind: ProofKind::Tx,
            param_digest: ParamDigest(DigestBytes { bytes: [3u8; 32] }),
            air_spec_id: AirSpecId(DigestBytes { bytes: [4u8; 32] }),
            public_inputs: public_input_bytes,
            commitment_digest: DigestBytes {
                bytes: commitment_digest,
            },
            header_length,
            body_length,
        };

        let header_bytes = header.serialize(&body);
        let integrity = compute_integrity_digest(&header_bytes, &payload);
        body.integrity_digest = DigestBytes { bytes: integrity };

        ProofEnvelope { header, body }
    }

    fn witness_blob(len: usize) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(4 + len * 8);
        bytes.extend_from_slice(&(len as u32).to_le_bytes());
        for i in 0..len {
            bytes.extend_from_slice(&(i as u64 + 1).to_le_bytes());
        }
        bytes
    }

    #[test]
    fn proof_envelope_serialization_is_deterministic() {
        let envelope_a = build_sample_envelope();
        let envelope_b = build_sample_envelope();
        assert_eq!(envelope_a.to_bytes(), envelope_b.to_bytes());
    }

    #[test]
    fn proof_envelope_roundtrip_preserves_structure() {
        let envelope = build_sample_envelope();
        let bytes = envelope.to_bytes();
        let decoded = ProofEnvelope::from_bytes(&bytes).expect("roundtrip");
        assert_eq!(decoded, envelope);
    }

    #[test]
    fn proof_envelope_detects_integrity_mismatch() {
        let envelope = build_sample_envelope();
        let mut bytes = envelope.to_bytes();
        let last = bytes.last_mut().expect("non-empty proof");
        *last ^= 0x01;
        let err = ProofEnvelope::from_bytes(&bytes).expect_err("integrity mismatch");
        assert_eq!(err, EnvelopeError::IntegrityDigestMismatch);
    }

    #[test]
    fn prover_pipeline_produces_identical_proof_bytes() {
        let profile = PROFILE_STANDARD_CONFIG.clone();
        let common = COMMON_IDENTIFIERS.clone();
        let param_digest = compute_param_digest(&profile, &common);
        let config = ProofSystemConfig {
            proof_version: PROOF_VERSION_V1,
            profile: profile.clone(),
            param_digest: param_digest.clone(),
        };
        let prover_context = build_prover_context(
            &profile,
            &common,
            &param_digest,
            ThreadPoolProfile::SingleThread,
            ChunkingPolicy {
                min_chunk_items: 64,
                max_chunk_items: 256,
                stride: 1,
            },
        );

        let body_bytes: Vec<u8> = Vec::new();
        let header = ExecutionHeaderV1 {
            version: PublicInputVersion::V1,
            program_digest: DigestBytes { bytes: [5u8; 32] },
            trace_length: 1024,
            trace_width: 16,
        };
        let public_inputs = PublicInputs::Execution {
            header: header.clone(),
            body: &body_bytes,
        };

        let witness_bytes = witness_blob(1024);
        let envelope_a = build_proof_envelope(
            &public_inputs,
            WitnessBlob {
                bytes: &witness_bytes,
            },
            &config,
            &prover_context,
        )
        .expect("first envelope");
        let envelope_b = build_proof_envelope(
            &public_inputs,
            WitnessBlob {
                bytes: &witness_bytes,
            },
            &config,
            &prover_context,
        )
        .expect("second envelope");

        assert_eq!(envelope_a.to_bytes(), envelope_b.to_bytes());
    }
}
