//! Serialization helpers for the proof envelope.
//!
//! The routines in this module encapsulate the canonical byte-level contracts
//! shared by the prover and verifier. They intentionally expose pure helpers so
//! the layout documented by [`super::types::Proof`] can be reused across the
//! crate without reimplementing framing logic.

use std::convert::TryInto;

use crate::config::{AirSpecId, ParamDigest, ProofKind};
use crate::fri::FriProof;
use crate::hash::Hasher;
use crate::proof::public_inputs::{
    AggregationHeaderV1, ExecutionHeaderV1, ProofKind as PublicProofKind, PublicInputVersion,
    PublicInputs, RecursionHeaderV1, VrfHeaderV1,
};
use crate::proof::types::{
    FriParametersMirror, MerkleProofBundle, Openings, OutOfDomainOpening, Proof, Telemetry,
    VerifyError, PROOF_VERSION,
};
use crate::utils::serialization::DigestBytes;

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

/// Serialises a [`Proof`] into the canonical envelope layout.
pub fn serialize_proof(proof: &Proof) -> Vec<u8> {
    let payload = serialize_proof_payload(proof);
    let header_bytes = serialize_proof_header(proof, &payload);
    let integrity = compute_integrity_digest(&header_bytes, &payload);

    let mut bytes =
        Vec::with_capacity(header_bytes.len() + payload.len() + DigestBytes::default().bytes.len());
    bytes.extend_from_slice(&header_bytes);
    bytes.extend_from_slice(&payload);
    bytes.extend_from_slice(&integrity);
    bytes
}

/// Deserialises a [`Proof`] from its canonical byte layout.
pub fn deserialize_proof(bytes: &[u8]) -> Result<Proof, VerifyError> {
    let mut cursor = Cursor::new(bytes);

    let proof_version = cursor.read_u16()?;
    if proof_version != PROOF_VERSION {
        return Err(VerifyError::UnsupportedVersion(proof_version));
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
    let expected_header_length = (3 + 32 + 32 + 4 + public_input_len + 32 + 4 + 4) as u32;
    if expected_header_length != header_length {
        return Err(VerifyError::HeaderLengthMismatch {
            declared: header_length,
            actual: expected_header_length,
        });
    }
    if header_bytes_consumed as u32 != header_length {
        return Err(VerifyError::HeaderLengthMismatch {
            declared: header_length,
            actual: header_bytes_consumed as u32,
        });
    }

    if body_length < DigestBytes::default().bytes.len() as u32 {
        return Err(VerifyError::BodyLengthMismatch {
            declared: body_length,
            actual: body_length,
        });
    }

    let body_bytes = cursor.read_vec(body_length as usize)?;
    if cursor.remaining() != 0 {
        return Err(VerifyError::UnexpectedEndOfBuffer(
            "trailing_header_bytes".to_string(),
        ));
    }

    if body_bytes.len() != body_length as usize {
        return Err(VerifyError::BodyLengthMismatch {
            declared: body_length,
            actual: body_bytes.len() as u32,
        });
    }

    if body_bytes.len() < DigestBytes::default().bytes.len() {
        return Err(VerifyError::BodyLengthMismatch {
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
        let opening = deserialize_out_of_domain_opening(&block_bytes)?;
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
        return Err(VerifyError::UnexpectedEndOfBuffer(
            "body_padding".to_string(),
        ));
    }

    let merkle = MerkleProofBundle {
        core_root,
        aux_root,
        fri_layer_roots,
    };

    let openings = Openings {
        out_of_domain: ood_openings,
    };

    let telemetry = Telemetry {
        header_length,
        body_length,
        fri_parameters,
        integrity_digest: DigestBytes {
            bytes: integrity_digest,
        },
    };

    let mut proof = Proof {
        version: proof_version,
        kind: proof_kind,
        param_digest,
        air_spec_id,
        public_inputs,
        commitment_digest,
        merkle,
        openings,
        fri_proof,
        telemetry,
    };

    let payload = serialize_proof_payload(&proof);
    let header_bytes = serialize_proof_header(&proof, &payload);
    let computed_integrity = compute_integrity_digest(&header_bytes, &payload);
    if computed_integrity != integrity_digest {
        return Err(VerifyError::IntegrityDigestMismatch);
    }

    proof.telemetry.integrity_digest = DigestBytes {
        bytes: integrity_digest,
    };

    Ok(proof)
}

/// Serialises the proof header given the payload bytes.
pub fn serialize_proof_header(proof: &Proof, payload: &[u8]) -> Vec<u8> {
    let body_length = (payload.len() + 32) as u32;
    let header_length = (3 + 32 + 32 + 4 + proof.public_inputs.len() + 32 + 4 + 4) as u32;

    let mut buffer = Vec::with_capacity(header_length as usize);
    buffer.extend_from_slice(&proof.version.to_le_bytes());
    buffer.push(encode_proof_kind(proof.kind));
    buffer.extend_from_slice(&proof.param_digest.0.bytes);
    let air_spec = proof.air_spec_id.clone().bytes();
    buffer.extend_from_slice(&air_spec.bytes);
    buffer.extend_from_slice(&(proof.public_inputs.len() as u32).to_le_bytes());
    buffer.extend_from_slice(&proof.public_inputs);
    buffer.extend_from_slice(&proof.commitment_digest.bytes);
    buffer.extend_from_slice(&header_length.to_le_bytes());
    buffer.extend_from_slice(&body_length.to_le_bytes());
    buffer
}

/// Serialises the proof payload (body) without the integrity digest.
pub fn serialize_proof_payload(proof: &Proof) -> Vec<u8> {
    let mut buffer = Vec::new();
    buffer.extend_from_slice(&proof.merkle.core_root);
    buffer.extend_from_slice(&proof.merkle.aux_root);
    buffer.extend_from_slice(&(proof.merkle.fri_layer_roots.len() as u32).to_le_bytes());
    for root in &proof.merkle.fri_layer_roots {
        buffer.extend_from_slice(root);
    }

    buffer.extend_from_slice(&(proof.openings.out_of_domain.len() as u32).to_le_bytes());
    for opening in &proof.openings.out_of_domain {
        let encoded = serialize_out_of_domain_opening(opening);
        buffer.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
        buffer.extend_from_slice(&encoded);
    }

    let fri_bytes = serialize_fri_proof(&proof.fri_proof);
    buffer.extend_from_slice(&(fri_bytes.len() as u32).to_le_bytes());
    buffer.extend_from_slice(&fri_bytes);

    buffer.push(proof.telemetry.fri_parameters.fold);
    buffer.extend_from_slice(&proof.telemetry.fri_parameters.cap_degree.to_le_bytes());
    buffer.extend_from_slice(&proof.telemetry.fri_parameters.cap_size.to_le_bytes());
    buffer.extend_from_slice(&proof.telemetry.fri_parameters.query_budget.to_le_bytes());
    buffer
}

/// Serialises the out-of-domain opening container.
pub fn serialize_openings(openings: &Openings) -> Vec<u8> {
    let mut buffer = Vec::new();
    buffer.extend_from_slice(&(openings.out_of_domain.len() as u32).to_le_bytes());
    for opening in &openings.out_of_domain {
        let encoded = serialize_out_of_domain_opening(opening);
        buffer.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
        buffer.extend_from_slice(&encoded);
    }
    buffer
}

/// Serialises a single out-of-domain opening block.
pub fn serialize_out_of_domain_opening(opening: &OutOfDomainOpening) -> Vec<u8> {
    let mut buffer = Vec::new();
    buffer.extend_from_slice(&opening.point);
    buffer.extend_from_slice(&(opening.core_values.len() as u32).to_le_bytes());
    for value in &opening.core_values {
        buffer.extend_from_slice(value);
    }
    buffer.extend_from_slice(&(opening.aux_values.len() as u32).to_le_bytes());
    for value in &opening.aux_values {
        buffer.extend_from_slice(value);
    }
    buffer.extend_from_slice(&opening.composition_value);
    buffer
}

/// Deserialises an out-of-domain opening block.
pub fn deserialize_out_of_domain_opening(bytes: &[u8]) -> Result<OutOfDomainOpening, VerifyError> {
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
        return Err(VerifyError::UnexpectedEndOfBuffer(
            "ood_padding".to_string(),
        ));
    }
    Ok(OutOfDomainOpening {
        point,
        core_values,
        aux_values,
        composition_value,
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

    fn read_u8(&mut self) -> Result<u8, VerifyError> {
        if self.remaining() < 1 {
            return Err(VerifyError::UnexpectedEndOfBuffer("u8".to_string()));
        }
        let value = self.bytes[self.offset];
        self.offset += 1;
        Ok(value)
    }

    fn read_u16(&mut self) -> Result<u16, VerifyError> {
        let bytes = self.read_fixed::<2>()?;
        Ok(u16::from_le_bytes(bytes))
    }

    fn read_u32(&mut self) -> Result<u32, VerifyError> {
        let bytes = self.read_fixed::<4>()?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn read_vec(&mut self, len: usize) -> Result<Vec<u8>, VerifyError> {
        if self.remaining() < len {
            return Err(VerifyError::UnexpectedEndOfBuffer("vec".to_string()));
        }
        let slice = &self.bytes[self.offset..self.offset + len];
        self.offset += len;
        Ok(slice.to_vec())
    }

    fn read_digest(&mut self) -> Result<[u8; 32], VerifyError> {
        self.read_fixed::<32>()
    }

    fn read_fixed<const N: usize>(&mut self) -> Result<[u8; N], VerifyError> {
        if self.remaining() < N {
            return Err(VerifyError::UnexpectedEndOfBuffer("fixed".to_string()));
        }
        let mut out = [0u8; N];
        out.copy_from_slice(&self.bytes[self.offset..self.offset + N]);
        self.offset += N;
        Ok(out)
    }
}
