//! Serialization helpers for the proof envelope.
//!
//! The routines in this module encapsulate the canonical byte-level contracts
//! shared by the prover and verifier. They intentionally expose pure helpers so
//! the layout documented by [`super::types::Proof`] can be reused across the
//! crate without reimplementing framing logic.

use crate::config::{AirSpecId, ParamDigest, ProofKind};
use crate::fri::FriProof;
use crate::hash::Hasher;
use crate::proof::public_inputs::{
    AggregationHeaderV1, ExecutionHeaderV1, ProofKind as PublicProofKind, PublicInputVersion,
    PublicInputs, RecursionHeaderV1, VrfHeaderV1,
};
use crate::proof::types::{
    FriParametersMirror, MerkleProofBundle, Openings, OutOfDomainOpening, Proof, SerKind,
    Telemetry, VerifyError, PROOF_VERSION,
};
use crate::utils::serialization::DigestBytes;

const DIGEST_SIZE: usize = 32;

/// Serialization failure surfaced while encoding a structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SerError {
    /// Input ended before the expected number of bytes were read.
    UnexpectedEnd { kind: SerKind, field: &'static str },
    /// A length prefix exceeded the configured bounds or remaining buffer.
    InvalidLength { kind: SerKind, field: &'static str },
    /// Encountered an unexpected discriminant or mismatching digest.
    InvalidValue { kind: SerKind, field: &'static str },
}

impl SerError {
    fn unexpected_end(kind: SerKind, field: &'static str) -> Self {
        SerError::UnexpectedEnd { kind, field }
    }

    fn invalid_length(kind: SerKind, field: &'static str) -> Self {
        SerError::InvalidLength { kind, field }
    }

    fn invalid_value(kind: SerKind, field: &'static str) -> Self {
        SerError::InvalidValue { kind, field }
    }
}

fn map_ser_error(err: SerError) -> VerifyError {
    VerifyError::Serialization(match err {
        SerError::UnexpectedEnd { kind, .. }
        | SerError::InvalidLength { kind, .. }
        | SerError::InvalidValue { kind, .. } => kind,
    })
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

fn decode_proof_kind_ser(byte: u8) -> Result<ProofKind, SerError> {
    decode_proof_kind(byte).map_err(|_| SerError::invalid_value(SerKind::Telemetry, "proof_kind"))
}

pub(crate) fn serialize_fri_proof(proof: &FriProof) -> Vec<u8> {
    proof
        .to_bytes()
        .expect("FRI proofs embedded in envelopes must be valid")
}

pub(crate) fn deserialize_fri_proof(bytes: &[u8]) -> Result<FriProof, VerifyError> {
    FriProof::from_bytes(bytes).map_err(|_| VerifyError::Serialization(SerKind::Fri))
}

fn compute_public_digest(bytes: &[u8]) -> [u8; DIGEST_SIZE] {
    let mut hasher = Hasher::new();
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

fn ensure_u32(value: usize, kind: SerKind, field: &'static str) -> Result<u32, SerError> {
    u32::try_from(value).map_err(|_| SerError::invalid_length(kind, field))
}

/// Serialises a [`Proof`] into the canonical envelope layout.
pub fn serialize_proof(proof: &Proof) -> Result<Vec<u8>, SerError> {
    let mut out = Vec::new();
    out.extend_from_slice(&proof.version.to_le_bytes());
    out.extend_from_slice(&proof.param_digest.0.bytes);

    let public_digest = compute_public_digest(&proof.public_inputs);
    out.extend_from_slice(&public_digest);

    let merkle_bytes = serialize_merkle_bundle(&proof.merkle)?;
    out.extend_from_slice(
        &ensure_u32(merkle_bytes.len(), SerKind::TraceCommitment, "len")?.to_le_bytes(),
    );
    out.extend_from_slice(&merkle_bytes);

    let has_composition = proof.commitment_digest.bytes != [0u8; DIGEST_SIZE];
    out.push(if has_composition { 1 } else { 0 });
    if has_composition {
        out.extend_from_slice(&proof.commitment_digest.bytes);
    }

    let fri_bytes = serialize_fri_proof(&proof.fri_proof);
    out.extend_from_slice(&ensure_u32(fri_bytes.len(), SerKind::Fri, "len")?.to_le_bytes());
    out.extend_from_slice(&fri_bytes);

    let openings_bytes = encode_openings(&proof.openings)?;
    out.extend_from_slice(
        &ensure_u32(openings_bytes.len(), SerKind::Openings, "len")?.to_le_bytes(),
    );
    out.extend_from_slice(&openings_bytes);

    out.push(1); // telemetry always present in the documentation layer.
    let telemetry_bytes = serialize_telemetry_frame(proof)?;
    out.extend_from_slice(
        &ensure_u32(telemetry_bytes.len(), SerKind::Telemetry, "len")?.to_le_bytes(),
    );
    out.extend_from_slice(&telemetry_bytes);

    Ok(out)
}

/// Deserialises a [`Proof`] from its canonical byte layout.
pub fn deserialize_proof(bytes: &[u8]) -> Result<Proof, VerifyError> {
    let mut cursor = Cursor::new(bytes);

    let version = cursor
        .read_u16(SerKind::Proof, "version")
        .map_err(map_ser_error)?;
    if version != PROOF_VERSION {
        return Err(VerifyError::VersionMismatch {
            expected: PROOF_VERSION,
            actual: version,
        });
    }

    let param_digest = ParamDigest(DigestBytes {
        bytes: cursor
            .read_digest(SerKind::Proof, "param_digest")
            .map_err(map_ser_error)?,
    });

    let public_digest = cursor
        .read_digest(SerKind::PublicInputs, "public_digest")
        .map_err(map_ser_error)?;

    let merkle_len = cursor
        .read_u32(SerKind::TraceCommitment, "len")
        .map_err(map_ser_error)? as usize;
    let merkle_bytes = cursor
        .read_vec(SerKind::TraceCommitment, "bytes", merkle_len)
        .map_err(map_ser_error)?;
    let merkle = deserialize_merkle_bundle(&merkle_bytes).map_err(map_ser_error)?;

    let has_comp = cursor
        .read_u8(SerKind::CompositionCommitment, "flag")
        .map_err(map_ser_error)?;
    let commitment_digest = match has_comp {
        0 => DigestBytes::default(),
        1 => DigestBytes {
            bytes: cursor
                .read_digest(SerKind::CompositionCommitment, "digest")
                .map_err(map_ser_error)?,
        },
        _ => return Err(VerifyError::Serialization(SerKind::CompositionCommitment)),
    };

    let fri_len = cursor
        .read_u32(SerKind::Fri, "len")
        .map_err(map_ser_error)? as usize;
    let fri_bytes = cursor
        .read_vec(SerKind::Fri, "bytes", fri_len)
        .map_err(map_ser_error)?;
    let fri_proof =
        deserialize_fri_proof(&fri_bytes).map_err(|_| VerifyError::Serialization(SerKind::Fri))?;

    let openings_len = cursor
        .read_u32(SerKind::Openings, "len")
        .map_err(map_ser_error)? as usize;
    let openings_bytes = cursor
        .read_vec(SerKind::Openings, "bytes", openings_len)
        .map_err(map_ser_error)?;
    let openings = deserialize_openings(&openings_bytes).map_err(map_ser_error)?;

    let has_telemetry = cursor
        .read_u8(SerKind::Telemetry, "flag")
        .map_err(map_ser_error)?;
    let telemetry_data = if has_telemetry == 1 {
        let telemetry_len = cursor
            .read_u32(SerKind::Telemetry, "len")
            .map_err(map_ser_error)? as usize;
        let telemetry_bytes = cursor
            .read_vec(SerKind::Telemetry, "bytes", telemetry_len)
            .map_err(map_ser_error)?;
        deserialize_telemetry_frame(&telemetry_bytes, public_digest).map_err(map_ser_error)?
    } else {
        return Err(VerifyError::Serialization(SerKind::Telemetry));
    };

    if cursor.remaining() != 0 {
        return Err(VerifyError::Serialization(SerKind::Proof));
    }

    Ok(Proof {
        version,
        kind: telemetry_data.kind,
        param_digest,
        air_spec_id: telemetry_data.air_spec_id,
        public_inputs: telemetry_data.public_inputs,
        commitment_digest,
        merkle,
        openings,
        fri_proof,
        telemetry: telemetry_data.telemetry,
    })
}

struct TelemetryDecodeResult {
    telemetry: Telemetry,
    kind: ProofKind,
    air_spec_id: AirSpecId,
    public_inputs: Vec<u8>,
}

fn serialize_merkle_bundle(bundle: &MerkleProofBundle) -> Result<Vec<u8>, SerError> {
    let mut out = Vec::new();
    out.extend_from_slice(&bundle.core_root);
    out.extend_from_slice(&bundle.aux_root);
    out.extend_from_slice(
        &ensure_u32(
            bundle.fri_layer_roots.len(),
            SerKind::TraceCommitment,
            "fri_roots",
        )?
        .to_le_bytes(),
    );
    for root in &bundle.fri_layer_roots {
        out.extend_from_slice(root);
    }
    Ok(out)
}

fn deserialize_merkle_bundle(bytes: &[u8]) -> Result<MerkleProofBundle, SerError> {
    let mut cursor = Cursor::new(bytes);
    let core_root = cursor.read_digest(SerKind::TraceCommitment, "core_root")?;
    let aux_root = cursor.read_digest(SerKind::TraceCommitment, "aux_root")?;
    let layer_count = cursor.read_u32(SerKind::TraceCommitment, "fri_roots")? as usize;
    let mut fri_layer_roots = Vec::with_capacity(layer_count);
    for _ in 0..layer_count {
        fri_layer_roots.push(cursor.read_digest(SerKind::TraceCommitment, "fri_root")?);
    }
    if cursor.remaining() != 0 {
        return Err(SerError::invalid_length(
            SerKind::TraceCommitment,
            "trailing_bytes",
        ));
    }
    Ok(MerkleProofBundle {
        core_root,
        aux_root,
        fri_layer_roots,
    })
}

fn encode_openings(openings: &Openings) -> Result<Vec<u8>, SerError> {
    let mut buffer = Vec::new();
    buffer.extend_from_slice(
        &ensure_u32(openings.out_of_domain.len(), SerKind::Openings, "ood_len")?.to_le_bytes(),
    );
    for opening in &openings.out_of_domain {
        let encoded = serialize_out_of_domain_opening(opening);
        buffer.extend_from_slice(
            &ensure_u32(encoded.len(), SerKind::Openings, "ood_block")?.to_le_bytes(),
        );
        buffer.extend_from_slice(&encoded);
    }
    Ok(buffer)
}

fn deserialize_openings(bytes: &[u8]) -> Result<Openings, SerError> {
    let mut cursor = Cursor::new(bytes);
    let count = cursor.read_u32(SerKind::Openings, "ood_len")? as usize;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let block_len = cursor.read_u32(SerKind::Openings, "ood_block")? as usize;
        let block = cursor.read_vec(SerKind::Openings, "ood_bytes", block_len)?;
        let opening = deserialize_out_of_domain_opening_inner(&block)?;
        out.push(opening);
    }
    if cursor.remaining() != 0 {
        return Err(SerError::invalid_length(
            SerKind::Openings,
            "trailing_bytes",
        ));
    }
    Ok(Openings { out_of_domain: out })
}

fn serialize_telemetry_frame(proof: &Proof) -> Result<Vec<u8>, SerError> {
    let mut out = Vec::new();
    out.extend_from_slice(&proof.telemetry.header_length.to_le_bytes());
    out.extend_from_slice(&proof.telemetry.body_length.to_le_bytes());
    out.push(proof.telemetry.fri_parameters.fold);
    out.extend_from_slice(&proof.telemetry.fri_parameters.cap_degree.to_le_bytes());
    out.extend_from_slice(&proof.telemetry.fri_parameters.cap_size.to_le_bytes());
    out.extend_from_slice(&proof.telemetry.fri_parameters.query_budget.to_le_bytes());
    out.extend_from_slice(&proof.telemetry.integrity_digest.bytes);
    out.push(encode_proof_kind(proof.kind));
    let air_spec_bytes = proof.air_spec_id.clone().bytes();
    out.extend_from_slice(&air_spec_bytes.bytes);
    out.extend_from_slice(
        &ensure_u32(proof.public_inputs.len(), SerKind::PublicInputs, "len")?.to_le_bytes(),
    );
    out.extend_from_slice(&proof.public_inputs);
    Ok(out)
}

fn deserialize_telemetry_frame(
    bytes: &[u8],
    public_digest: [u8; DIGEST_SIZE],
) -> Result<TelemetryDecodeResult, SerError> {
    let mut cursor = Cursor::new(bytes);
    let header_length = cursor.read_u32(SerKind::Telemetry, "header_length")?;
    let body_length = cursor.read_u32(SerKind::Telemetry, "body_length")?;
    let fold = cursor.read_u8(SerKind::Telemetry, "fri.fold")?;
    let cap_degree = cursor.read_u16(SerKind::Telemetry, "fri.cap_degree")?;
    let cap_size = cursor.read_u32(SerKind::Telemetry, "fri.cap_size")?;
    let query_budget = cursor.read_u16(SerKind::Telemetry, "fri.query_budget")?;
    let integrity_digest = cursor.read_digest(SerKind::Telemetry, "integrity_digest")?;
    let kind_byte = cursor.read_u8(SerKind::Telemetry, "proof_kind")?;
    let kind = decode_proof_kind_ser(kind_byte)?;
    let air_spec_id = AirSpecId(DigestBytes {
        bytes: cursor.read_digest(SerKind::Telemetry, "air_spec_id")?,
    });
    let public_len = cursor.read_u32(SerKind::PublicInputs, "len")? as usize;
    let public_inputs = cursor.read_vec(SerKind::PublicInputs, "bytes", public_len)?;
    if cursor.remaining() != 0 {
        return Err(SerError::invalid_length(
            SerKind::Telemetry,
            "trailing_bytes",
        ));
    }
    if compute_public_digest(&public_inputs) != public_digest {
        return Err(SerError::invalid_value(
            SerKind::PublicInputs,
            "digest_mismatch",
        ));
    }

    Ok(TelemetryDecodeResult {
        telemetry: Telemetry {
            header_length,
            body_length,
            fri_parameters: FriParametersMirror {
                fold,
                cap_degree,
                cap_size,
                query_budget,
            },
            integrity_digest: DigestBytes {
                bytes: integrity_digest,
            },
        },
        kind,
        air_spec_id,
        public_inputs,
    })
}

/// Serialises the out-of-domain opening container.
pub fn serialize_openings(openings: &Openings) -> Vec<u8> {
    encode_openings(openings).expect("openings serialization should fit u32 lengths")
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

fn deserialize_out_of_domain_opening_inner(bytes: &[u8]) -> Result<OutOfDomainOpening, SerError> {
    let mut cursor = Cursor::new(bytes);
    let point = cursor.read_digest(SerKind::Openings, "point")?;
    let core_len = cursor.read_u32(SerKind::Openings, "core_len")? as usize;
    let mut core_values = Vec::with_capacity(core_len);
    for _ in 0..core_len {
        core_values.push(cursor.read_digest(SerKind::Openings, "core_value")?);
    }
    let aux_len = cursor.read_u32(SerKind::Openings, "aux_len")? as usize;
    let mut aux_values = Vec::with_capacity(aux_len);
    for _ in 0..aux_len {
        aux_values.push(cursor.read_digest(SerKind::Openings, "aux_value")?);
    }
    let composition_value = cursor.read_digest(SerKind::Openings, "composition_value")?;
    if cursor.remaining() != 0 {
        return Err(SerError::invalid_length(
            SerKind::Openings,
            "trailing_bytes",
        ));
    }
    Ok(OutOfDomainOpening {
        point,
        core_values,
        aux_values,
        composition_value,
    })
}

/// Deserialises an out-of-domain opening block.
pub fn deserialize_out_of_domain_opening(bytes: &[u8]) -> Result<OutOfDomainOpening, VerifyError> {
    deserialize_out_of_domain_opening_inner(bytes).map_err(map_ser_error)
}

/// Serialises the proof header given the payload bytes.
pub fn serialize_proof_header(proof: &Proof, payload: &[u8]) -> Vec<u8> {
    let body_length = (payload.len() + DIGEST_SIZE) as u32;
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

    fn read_u8(&mut self, kind: SerKind, field: &'static str) -> Result<u8, SerError> {
        if self.remaining() < 1 {
            return Err(SerError::unexpected_end(kind, field));
        }
        let value = self.bytes[self.offset];
        self.offset += 1;
        Ok(value)
    }

    fn read_u16(&mut self, kind: SerKind, field: &'static str) -> Result<u16, SerError> {
        if self.remaining() < 2 {
            return Err(SerError::unexpected_end(kind, field));
        }
        let mut buf = [0u8; 2];
        buf.copy_from_slice(&self.bytes[self.offset..self.offset + 2]);
        self.offset += 2;
        Ok(u16::from_le_bytes(buf))
    }

    fn read_u32(&mut self, kind: SerKind, field: &'static str) -> Result<u32, SerError> {
        if self.remaining() < 4 {
            return Err(SerError::unexpected_end(kind, field));
        }
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&self.bytes[self.offset..self.offset + 4]);
        self.offset += 4;
        Ok(u32::from_le_bytes(buf))
    }

    fn read_vec(
        &mut self,
        kind: SerKind,
        field: &'static str,
        len: usize,
    ) -> Result<Vec<u8>, SerError> {
        if self.remaining() < len {
            return Err(SerError::unexpected_end(kind, field));
        }
        let slice = &self.bytes[self.offset..self.offset + len];
        self.offset += len;
        Ok(slice.to_vec())
    }

    fn read_digest(
        &mut self,
        kind: SerKind,
        field: &'static str,
    ) -> Result<[u8; DIGEST_SIZE], SerError> {
        if self.remaining() < DIGEST_SIZE {
            return Err(SerError::unexpected_end(kind, field));
        }
        let mut out = [0u8; DIGEST_SIZE];
        out.copy_from_slice(&self.bytes[self.offset..self.offset + DIGEST_SIZE]);
        self.offset += DIGEST_SIZE;
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ParamDigest as ConfigParamDigest, ProofKind};
    use crate::field::FieldElement;
    use crate::fri::{FriProof, FriSecurityLevel};
    use crate::proof::public_inputs::{ExecutionHeaderV1, PublicInputVersion, PublicInputs};
    use crate::utils::serialization::DigestBytes;

    fn sample_fri_proof() -> FriProof {
        let evaluations: Vec<FieldElement> = (0..64).map(|i| FieldElement(i as u64 + 1)).collect();
        let seed = [7u8; 32];
        FriProof::prove(FriSecurityLevel::Standard, seed, &evaluations).expect("fri proof")
    }

    fn build_sample_proof() -> Proof {
        let fri_proof = sample_fri_proof();
        let fri_layer_roots = fri_proof.layer_roots.clone();
        let core_root = fri_layer_roots.first().copied().unwrap_or([0u8; 32]);
        let aux_root = [1u8; 32];
        let commitment_digest = compute_commitment_digest(&core_root, &aux_root, &fri_layer_roots);

        let header = ExecutionHeaderV1 {
            version: PublicInputVersion::V1,
            program_digest: DigestBytes { bytes: [2u8; 32] },
            trace_length: 64,
            trace_width: 4,
        };
        let body_bytes: Vec<u8> = vec![1, 2, 3, 4];
        let public_inputs = PublicInputs::Execution {
            header: header.clone(),
            body: &body_bytes,
        };
        let public_input_bytes = serialize_public_inputs(&public_inputs);

        let merkle = MerkleProofBundle {
            core_root,
            aux_root,
            fri_layer_roots,
        };
        let openings = Openings {
            out_of_domain: vec![OutOfDomainOpening {
                point: [3u8; 32],
                core_values: vec![[4u8; 32]],
                aux_values: Vec::new(),
                composition_value: [5u8; 32],
            }],
        };
        let mut proof = Proof {
            version: PROOF_VERSION,
            kind: ProofKind::Tx,
            param_digest: ConfigParamDigest(DigestBytes { bytes: [6u8; 32] }),
            air_spec_id: crate::config::AirSpecId(DigestBytes { bytes: [7u8; 32] }),
            public_inputs: public_input_bytes,
            commitment_digest: DigestBytes {
                bytes: commitment_digest,
            },
            merkle,
            openings,
            fri_proof,
            telemetry: Telemetry {
                header_length: 0,
                body_length: 0,
                fri_parameters: FriParametersMirror {
                    fold: 2,
                    cap_degree: 0,
                    cap_size: 0,
                    query_budget: 0,
                },
                integrity_digest: DigestBytes::default(),
            },
        };

        // Populate telemetry with deterministic values.
        let payload = crate::proof::ser::serialize_proof_payload(&proof);
        let header_bytes = crate::proof::ser::serialize_proof_header(&proof, &payload);
        let integrity = compute_integrity_digest(&header_bytes, &payload);
        proof.telemetry.header_length = header_bytes.len() as u32;
        proof.telemetry.body_length = (payload.len() + 32) as u32;
        proof.telemetry.integrity_digest = DigestBytes { bytes: integrity };

        proof
    }

    #[test]
    fn proof_round_trip() {
        let proof = build_sample_proof();
        let bytes = serialize_proof(&proof).expect("serialize proof");
        let decoded = deserialize_proof(&bytes).expect("decode proof");
        assert_eq!(proof, decoded);
    }

    #[test]
    fn serialization_layout_matches_contract() {
        let proof = build_sample_proof();
        let bytes = serialize_proof(&proof).expect("serialize proof");
        let mut cursor = Cursor::new(&bytes);
        assert_eq!(
            cursor.read_u16(SerKind::Proof, "version").unwrap(),
            PROOF_VERSION
        );
        cursor.read_digest(SerKind::Proof, "param_digest").unwrap();
        cursor
            .read_digest(SerKind::PublicInputs, "public_digest")
            .unwrap();
        let merkle_len = cursor.read_u32(SerKind::TraceCommitment, "len").unwrap() as usize;
        cursor
            .read_vec(SerKind::TraceCommitment, "bytes", merkle_len)
            .unwrap();
        assert_eq!(
            cursor
                .read_u8(SerKind::CompositionCommitment, "flag")
                .unwrap(),
            1
        );
        cursor
            .read_digest(SerKind::CompositionCommitment, "digest")
            .unwrap();
        let fri_len = cursor.read_u32(SerKind::Fri, "len").unwrap() as usize;
        cursor.read_vec(SerKind::Fri, "bytes", fri_len).unwrap();
        let openings_len = cursor.read_u32(SerKind::Openings, "len").unwrap() as usize;
        cursor
            .read_vec(SerKind::Openings, "bytes", openings_len)
            .unwrap();
        assert_eq!(cursor.read_u8(SerKind::Telemetry, "flag").unwrap(), 1);
        let telemetry_len = cursor.read_u32(SerKind::Telemetry, "len").unwrap() as usize;
        cursor
            .read_vec(SerKind::Telemetry, "bytes", telemetry_len)
            .unwrap();
        assert_eq!(cursor.remaining(), 0);
    }

    #[test]
    fn deserialize_rejects_truncated_payload() {
        let proof = build_sample_proof();
        let mut bytes = serialize_proof(&proof).expect("serialize proof");
        bytes.pop();
        let err = deserialize_proof(&bytes).expect_err("should fail");
        match err {
            VerifyError::Serialization(SerKind::Telemetry) => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }
}
