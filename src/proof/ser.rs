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
    CompositionBinding, CompositionOpenings, FriHandle, FriParametersMirror,
    MerkleAuthenticationPath, MerklePathNode, MerkleProofBundle, MerkleSection, Openings,
    OpeningsDescriptor, OutOfDomainOpening, Proof, Telemetry, TelemetryOption, TraceOpenings,
    VerifyError, PROOF_VERSION,
};
use crate::ser::{
    ensure_consumed, ensure_u32, read_digest, read_u16, read_u32, read_u8, write_bytes,
    write_digest, write_u16, write_u32, write_u8, ByteReader, SerError, SerKind, DIGEST_SIZE,
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
pub fn serialize_public_inputs(inputs: &PublicInputs<'_>) -> Result<Vec<u8>, SerError> {
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
            write_u8(&mut buffer, version_byte(*version));
            write_digest(&mut buffer, &program_digest.bytes);
            write_u32(&mut buffer, *trace_length);
            write_u32(&mut buffer, *trace_width);
            let body_len = ensure_u32(body.len(), SerKind::PublicInputs, "len")?;
            write_u32(&mut buffer, body_len);
            write_bytes(&mut buffer, body);
            Ok(buffer)
        }
        PublicInputs::Aggregation { header, body } => {
            let AggregationHeaderV1 {
                version,
                circuit_digest,
                leaf_count,
                root_digest,
            } = header;
            let mut buffer = Vec::new();
            write_u8(&mut buffer, version_byte(*version));
            write_digest(&mut buffer, &circuit_digest.bytes);
            write_u32(&mut buffer, *leaf_count);
            write_digest(&mut buffer, &root_digest.bytes);
            let body_len = ensure_u32(body.len(), SerKind::PublicInputs, "len")?;
            write_u32(&mut buffer, body_len);
            write_bytes(&mut buffer, body);
            Ok(buffer)
        }
        PublicInputs::Recursion { header, body } => {
            let RecursionHeaderV1 {
                version,
                depth,
                boundary_digest,
                recursion_seed,
            } = header;
            let mut buffer = Vec::new();
            write_u8(&mut buffer, version_byte(*version));
            write_u8(&mut buffer, *depth);
            write_digest(&mut buffer, &boundary_digest.bytes);
            write_digest(&mut buffer, &recursion_seed.bytes);
            let body_len = ensure_u32(body.len(), SerKind::PublicInputs, "len")?;
            write_u32(&mut buffer, body_len);
            write_bytes(&mut buffer, body);
            Ok(buffer)
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
            write_u8(&mut buffer, version_byte(*version));
            write_digest(&mut buffer, &public_key_commit.bytes);
            write_digest(&mut buffer, &prf_param_digest.bytes);
            write_bytes(&mut buffer, rlwe_param_id.as_bytes());
            write_bytes(&mut buffer, vrf_param_id.as_bytes());
            let tv = transcript_version_id.clone().bytes();
            write_digest(&mut buffer, &tv.bytes);
            write_u16(&mut buffer, field_id.0);
            write_digest(&mut buffer, &context_digest.bytes);
            let body_len = ensure_u32(body.len(), SerKind::PublicInputs, "len")?;
            write_u32(&mut buffer, body_len);
            write_bytes(&mut buffer, body);
            Ok(buffer)
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

pub(crate) fn serialize_fri_proof(proof: &FriProof) -> Result<Vec<u8>, SerError> {
    proof
        .to_bytes()
        .map_err(|_| SerError::invalid_value(SerKind::Fri, "fri_proof"))
}

pub(crate) fn deserialize_fri_proof(bytes: &[u8]) -> Result<FriProof, VerifyError> {
    FriProof::from_bytes(bytes).map_err(|_| VerifyError::Serialization(SerKind::Fri))
}

pub fn compute_public_digest(bytes: &[u8]) -> [u8; DIGEST_SIZE] {
    let mut hasher = Hasher::new();
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

/// Serialises a [`Proof`] into the canonical envelope layout.
pub fn serialize_proof(proof: &Proof) -> Result<Vec<u8>, SerError> {
    let expected_public = compute_public_digest(proof.public_inputs());
    if proof.public_digest().bytes != expected_public {
        return Err(SerError::invalid_value(
            SerKind::PublicInputs,
            "digest_mismatch",
        ));
    }

    if proof.trace_commit().bytes != proof.merkle().core_root {
        return Err(SerError::invalid_value(
            SerKind::TraceCommitment,
            "trace_root_mismatch",
        ));
    }

    match (proof.composition_commit(), proof.openings().composition()) {
        (Some(commit), Some(_)) => {
            if commit.bytes != proof.merkle().aux_root {
                return Err(SerError::invalid_value(
                    SerKind::CompositionCommitment,
                    "composition_root_mismatch",
                ));
            }
        }
        (Some(_), None) => {
            return Err(SerError::invalid_value(
                SerKind::CompositionCommitment,
                "commit_without_openings",
            ));
        }
        (None, Some(_)) => {
            return Err(SerError::invalid_value(
                SerKind::CompositionCommitment,
                "openings_without_commit",
            ));
        }
        (None, None) => {
            if proof.merkle().aux_root != [0u8; 32] {
                return Err(SerError::invalid_value(
                    SerKind::CompositionCommitment,
                    "aux_root_without_commit",
                ));
            }
        }
    }

    let merkle_bytes = serialize_merkle_bundle(proof.merkle())?;
    let fri_bytes = serialize_fri_proof(proof.fri_proof())?;
    let openings_bytes = serialize_openings(proof.openings())?;
    let telemetry_bytes = if proof.has_telemetry() {
        Some(serialize_telemetry_frame(proof.telemetry())?)
    } else {
        None
    };

    let header = serialize_proof_header_from_lengths(
        proof,
        merkle_bytes.len(),
        fri_bytes.len(),
        openings_bytes.len(),
        telemetry_bytes.as_ref().map(|bytes| bytes.len()),
    )?;

    let payload_capacity = merkle_bytes.len()
        + fri_bytes.len()
        + openings_bytes.len()
        + telemetry_bytes.as_ref().map_or(0, |bytes| bytes.len());

    let mut out = Vec::with_capacity(header.len() + payload_capacity);
    out.extend_from_slice(&header);
    out.extend_from_slice(&merkle_bytes);
    out.extend_from_slice(&fri_bytes);
    out.extend_from_slice(&openings_bytes);
    if let Some(bytes) = telemetry_bytes {
        out.extend_from_slice(&bytes);
    }

    Ok(out)
}

fn serialize_proof_header_from_lengths(
    proof: &Proof,
    merkle_len: usize,
    fri_len: usize,
    openings_len: usize,
    telemetry_len: Option<usize>,
) -> Result<Vec<u8>, SerError> {
    let mut buffer = Vec::new();
    write_u16(&mut buffer, proof.version());
    write_u8(&mut buffer, encode_proof_kind(*proof.kind()));
    write_digest(&mut buffer, &proof.param_digest().0.bytes);
    let air_spec_bytes = proof.air_spec_id().clone().bytes();
    write_digest(&mut buffer, &air_spec_bytes.bytes);

    let public_len = ensure_u32(proof.public_inputs().len(), SerKind::PublicInputs, "len")?;
    write_u32(&mut buffer, public_len);
    write_bytes(&mut buffer, proof.public_inputs());

    write_digest(&mut buffer, &proof.public_digest().bytes);
    write_digest(&mut buffer, &proof.trace_commit().bytes);
    match proof.composition_commit() {
        Some(digest) => {
            write_u8(&mut buffer, 1);
            write_digest(&mut buffer, &digest.bytes);
        }
        None => write_u8(&mut buffer, 0),
    }

    let merkle_len = ensure_u32(merkle_len, SerKind::TraceCommitment, "len")?;
    write_u32(&mut buffer, merkle_len);
    let fri_len = ensure_u32(fri_len, SerKind::Fri, "len")?;
    write_u32(&mut buffer, fri_len);
    let openings_len = ensure_u32(openings_len, SerKind::Openings, "len")?;
    write_u32(&mut buffer, openings_len);

    write_u8(&mut buffer, if proof.has_telemetry() { 1 } else { 0 });

    if proof.has_telemetry() {
        let telemetry_len = telemetry_len.ok_or_else(|| {
            SerError::invalid_value(SerKind::Telemetry, "missing_telemetry_bytes")
        })?;
        let telemetry_len = ensure_u32(telemetry_len, SerKind::Telemetry, "len")?;
        write_u32(&mut buffer, telemetry_len);
    }

    Ok(buffer)
}

/// Deserialises a [`Proof`] from its canonical byte layout.
pub fn deserialize_proof(bytes: &[u8]) -> Result<Proof, VerifyError> {
    let mut cursor = ByteReader::new(bytes);

    let version = read_u16(&mut cursor, SerKind::Proof, "version").map_err(VerifyError::from)?;
    if version != PROOF_VERSION {
        return Err(VerifyError::VersionMismatch {
            expected: PROOF_VERSION,
            actual: version,
        });
    }

    let kind_byte = read_u8(&mut cursor, SerKind::Proof, "kind").map_err(VerifyError::from)?;
    let kind = decode_proof_kind(kind_byte)?;

    let param_digest = ParamDigest(DigestBytes {
        bytes: read_digest(&mut cursor, SerKind::Proof, "param_digest")
            .map_err(VerifyError::from)?,
    });

    let air_spec_id = AirSpecId(DigestBytes {
        bytes: read_digest(&mut cursor, SerKind::Proof, "air_spec_id")
            .map_err(VerifyError::from)?,
    });

    let public_len =
        read_u32(&mut cursor, SerKind::PublicInputs, "len").map_err(VerifyError::from)? as usize;
    let public_inputs = cursor
        .read_vec(SerKind::PublicInputs, "bytes", public_len)
        .map_err(VerifyError::from)?;
    let public_digest_bytes =
        read_digest(&mut cursor, SerKind::PublicInputs, "digest").map_err(VerifyError::from)?;

    let trace_commit = DigestBytes {
        bytes: read_digest(&mut cursor, SerKind::TraceCommitment, "trace_commit")
            .map_err(VerifyError::from)?,
    };

    let composition_commit = match read_u8(&mut cursor, SerKind::CompositionCommitment, "flag")
        .map_err(VerifyError::from)?
    {
        0 => None,
        1 => Some(DigestBytes {
            bytes: read_digest(&mut cursor, SerKind::CompositionCommitment, "digest")
                .map_err(VerifyError::from)?,
        }),
        _ => return Err(VerifyError::Serialization(SerKind::CompositionCommitment)),
    };

    let merkle_len =
        read_u32(&mut cursor, SerKind::TraceCommitment, "len").map_err(VerifyError::from)? as usize;
    let fri_len = read_u32(&mut cursor, SerKind::Fri, "len").map_err(VerifyError::from)? as usize;
    let openings_len =
        read_u32(&mut cursor, SerKind::Openings, "len").map_err(VerifyError::from)? as usize;

    let has_telemetry =
        match read_u8(&mut cursor, SerKind::Telemetry, "flag").map_err(VerifyError::from)? {
            0 => false,
            1 => true,
            _ => return Err(VerifyError::Serialization(SerKind::Telemetry)),
        };

    let telemetry_len = if has_telemetry {
        Some(read_u32(&mut cursor, SerKind::Telemetry, "len").map_err(VerifyError::from)? as usize)
    } else {
        None
    };

    let merkle_bytes = cursor
        .read_vec(SerKind::TraceCommitment, "bytes", merkle_len)
        .map_err(VerifyError::from)?;
    let merkle = deserialize_merkle_bundle(&merkle_bytes).map_err(VerifyError::from)?;

    let fri_bytes = cursor
        .read_vec(SerKind::Fri, "bytes", fri_len)
        .map_err(VerifyError::from)?;
    let fri_proof =
        deserialize_fri_proof(&fri_bytes).map_err(|_| VerifyError::Serialization(SerKind::Fri))?;

    let openings_bytes = cursor
        .read_vec(SerKind::Openings, "bytes", openings_len)
        .map_err(VerifyError::from)?;
    let openings = deserialize_openings(&openings_bytes).map_err(VerifyError::from)?;

    let telemetry = if let Some(len) = telemetry_len {
        let telemetry_bytes = cursor
            .read_vec(SerKind::Telemetry, "bytes", len)
            .map_err(VerifyError::from)?;
        deserialize_telemetry_frame(&telemetry_bytes).map_err(VerifyError::from)?
    } else {
        Telemetry::default()
    };

    ensure_consumed(&cursor, SerKind::Proof).map_err(VerifyError::from)?;

    if compute_public_digest(&public_inputs) != public_digest_bytes {
        return Err(VerifyError::PublicDigestMismatch);
    }

    if trace_commit.bytes != merkle.core_root {
        return Err(VerifyError::RootMismatch {
            section: MerkleSection::TraceCommit,
        });
    }

    match (&composition_commit, openings.composition()) {
        (Some(commit), Some(_)) => {
            if commit.bytes != merkle.aux_root {
                return Err(VerifyError::RootMismatch {
                    section: MerkleSection::CompositionCommit,
                });
            }
        }
        (Some(_), None) => {
            return Err(VerifyError::CompositionInconsistent {
                reason: "missing_composition_openings".to_string(),
            });
        }
        (None, Some(_)) => {
            return Err(VerifyError::CompositionInconsistent {
                reason: "missing_composition_commit".to_string(),
            });
        }
        (None, None) => {
            if merkle.aux_root != [0u8; 32] {
                return Err(VerifyError::RootMismatch {
                    section: MerkleSection::CompositionCommit,
                });
            }
        }
    }

    let public_digest = DigestBytes {
        bytes: public_digest_bytes,
    };
    let binding = CompositionBinding::new(kind, air_spec_id, public_inputs, composition_commit);
    let openings_descriptor = OpeningsDescriptor::new(merkle, openings);
    let fri_handle = FriHandle::new(fri_proof);
    let telemetry_option = TelemetryOption::new(has_telemetry, telemetry);

    Ok(Proof::from_parts(
        version,
        param_digest,
        public_digest,
        trace_commit,
        binding,
        openings_descriptor,
        fri_handle,
        telemetry_option,
    ))
}

fn serialize_merkle_bundle(bundle: &MerkleProofBundle) -> Result<Vec<u8>, SerError> {
    let mut out = Vec::new();
    write_digest(&mut out, &bundle.core_root);
    write_digest(&mut out, &bundle.aux_root);
    let layer_count = ensure_u32(
        bundle.fri_layer_roots.len(),
        SerKind::TraceCommitment,
        "fri_roots",
    )?;
    write_u32(&mut out, layer_count);
    for root in &bundle.fri_layer_roots {
        write_digest(&mut out, root);
    }
    Ok(out)
}

fn deserialize_merkle_bundle(bytes: &[u8]) -> Result<MerkleProofBundle, SerError> {
    let mut cursor = ByteReader::new(bytes);
    let core_root = read_digest(&mut cursor, SerKind::TraceCommitment, "core_root")?;
    let aux_root = read_digest(&mut cursor, SerKind::TraceCommitment, "aux_root")?;
    let layer_count = read_u32(&mut cursor, SerKind::TraceCommitment, "fri_roots")? as usize;
    let mut fri_layer_roots = Vec::with_capacity(layer_count);
    for _ in 0..layer_count {
        fri_layer_roots.push(read_digest(
            &mut cursor,
            SerKind::TraceCommitment,
            "fri_root",
        )?);
    }
    ensure_consumed(&cursor, SerKind::TraceCommitment)?;
    Ok(MerkleProofBundle {
        core_root,
        aux_root,
        fri_layer_roots,
    })
}

fn encode_openings(openings: &Openings) -> Result<Vec<u8>, SerError> {
    let mut buffer = Vec::new();
    encode_merkle_openings(
        &mut buffer,
        openings.trace().indices(),
        openings.trace().leaves(),
        openings.trace().paths(),
    )?;
    match openings.composition() {
        Some(section) => {
            write_u8(&mut buffer, 1);
            encode_merkle_openings(
                &mut buffer,
                section.indices(),
                section.leaves(),
                section.paths(),
            )?;
        }
        None => write_u8(&mut buffer, 0),
    }

    let count = ensure_u32(openings.out_of_domain().len(), SerKind::Openings, "ood_len")?;
    write_u32(&mut buffer, count);
    for opening in openings.out_of_domain() {
        let encoded = serialize_out_of_domain_opening(opening)?;
        let encoded_len = ensure_u32(encoded.len(), SerKind::Openings, "ood_block")?;
        write_u32(&mut buffer, encoded_len);
        write_bytes(&mut buffer, &encoded);
    }
    Ok(buffer)
}

fn deserialize_openings(bytes: &[u8]) -> Result<Openings, SerError> {
    let mut cursor = ByteReader::new(bytes);
    let (trace_indices, trace_leaves, trace_paths) = decode_merkle_openings(&mut cursor)?;
    let trace = TraceOpenings {
        indices: trace_indices,
        leaves: trace_leaves,
        paths: trace_paths,
    };
    let has_composition = read_u8(&mut cursor, SerKind::Openings, "composition_flag")?;
    let composition = match has_composition {
        0 => None,
        1 => {
            let (indices, leaves, paths) = decode_merkle_openings(&mut cursor)?;
            Some(CompositionOpenings {
                indices,
                leaves,
                paths,
            })
        }
        _ => {
            return Err(SerError::invalid_value(
                SerKind::Openings,
                "composition_flag",
            ))
        }
    };

    let count = read_u32(&mut cursor, SerKind::Openings, "ood_len")? as usize;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let block_len = read_u32(&mut cursor, SerKind::Openings, "ood_block")? as usize;
        let block = cursor.read_vec(SerKind::Openings, "ood_bytes", block_len)?;
        let opening = deserialize_out_of_domain_opening_inner(&block)?;
        out.push(opening);
    }
    ensure_consumed(&cursor, SerKind::Openings)?;
    Ok(Openings {
        trace,
        composition,
        out_of_domain: out,
    })
}

fn serialize_telemetry_frame(telemetry: &Telemetry) -> Result<Vec<u8>, SerError> {
    let mut out = Vec::new();
    write_u32(&mut out, telemetry.header_length());
    write_u32(&mut out, telemetry.body_length());
    write_u8(&mut out, telemetry.fri_parameters().fold);
    write_u16(&mut out, telemetry.fri_parameters().cap_degree);
    write_u32(&mut out, telemetry.fri_parameters().cap_size);
    write_u16(&mut out, telemetry.fri_parameters().query_budget);
    write_digest(&mut out, &telemetry.integrity_digest().bytes);
    Ok(out)
}

fn deserialize_telemetry_frame(bytes: &[u8]) -> Result<Telemetry, SerError> {
    let mut cursor = ByteReader::new(bytes);
    let header_length = read_u32(&mut cursor, SerKind::Telemetry, "header_length")?;
    let body_length = read_u32(&mut cursor, SerKind::Telemetry, "body_length")?;
    let fold = read_u8(&mut cursor, SerKind::Telemetry, "fri.fold")?;
    let cap_degree = read_u16(&mut cursor, SerKind::Telemetry, "fri.cap_degree")?;
    let cap_size = read_u32(&mut cursor, SerKind::Telemetry, "fri.cap_size")?;
    let query_budget = read_u16(&mut cursor, SerKind::Telemetry, "fri.query_budget")?;
    let integrity_digest = read_digest(&mut cursor, SerKind::Telemetry, "integrity_digest")?;
    ensure_consumed(&cursor, SerKind::Telemetry)?;
    Ok(Telemetry {
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
    })
}

/// Serialises the out-of-domain opening container.
pub fn serialize_openings(openings: &Openings) -> Result<Vec<u8>, SerError> {
    encode_openings(openings)
}

/// Serialises a single out-of-domain opening block.
pub fn serialize_out_of_domain_opening(opening: &OutOfDomainOpening) -> Result<Vec<u8>, SerError> {
    let mut buffer = Vec::new();
    write_digest(&mut buffer, &opening.point);
    let core_len = ensure_u32(opening.core_values.len(), SerKind::Openings, "core_len")?;
    write_u32(&mut buffer, core_len);
    for value in &opening.core_values {
        write_digest(&mut buffer, value);
    }
    let aux_len = ensure_u32(opening.aux_values.len(), SerKind::Openings, "aux_len")?;
    write_u32(&mut buffer, aux_len);
    for value in &opening.aux_values {
        write_digest(&mut buffer, value);
    }
    write_digest(&mut buffer, &opening.composition_value);
    Ok(buffer)
}

fn deserialize_out_of_domain_opening_inner(bytes: &[u8]) -> Result<OutOfDomainOpening, SerError> {
    let mut cursor = ByteReader::new(bytes);
    let point = read_digest(&mut cursor, SerKind::Openings, "point")?;
    let core_len = read_u32(&mut cursor, SerKind::Openings, "core_len")? as usize;
    let mut core_values = Vec::with_capacity(core_len);
    for _ in 0..core_len {
        core_values.push(read_digest(&mut cursor, SerKind::Openings, "core_value")?);
    }
    let aux_len = read_u32(&mut cursor, SerKind::Openings, "aux_len")? as usize;
    let mut aux_values = Vec::with_capacity(aux_len);
    for _ in 0..aux_len {
        aux_values.push(read_digest(&mut cursor, SerKind::Openings, "aux_value")?);
    }
    let composition_value = read_digest(&mut cursor, SerKind::Openings, "composition_value")?;
    ensure_consumed(&cursor, SerKind::Openings)?;
    Ok(OutOfDomainOpening {
        point,
        core_values,
        aux_values,
        composition_value,
    })
}

fn encode_merkle_openings(
    buffer: &mut Vec<u8>,
    indices: &[u32],
    leaves: &[Vec<u8>],
    paths: &[MerkleAuthenticationPath],
) -> Result<(), SerError> {
    let indices_len = ensure_u32(indices.len(), SerKind::Openings, "indices_len")?;
    write_u32(buffer, indices_len);
    for index in indices {
        write_u32(buffer, *index);
    }

    let leaves_len = ensure_u32(leaves.len(), SerKind::Openings, "leaves_len")?;
    write_u32(buffer, leaves_len);
    for leaf in leaves {
        let leaf_len = ensure_u32(leaf.len(), SerKind::Openings, "leaf_len")?;
        write_u32(buffer, leaf_len);
        write_bytes(buffer, leaf);
    }

    let paths_len = ensure_u32(paths.len(), SerKind::Openings, "paths_len")?;
    write_u32(buffer, paths_len);
    for path in paths {
        let nodes_len = ensure_u32(path.nodes.len(), SerKind::Openings, "path_len")?;
        write_u32(buffer, nodes_len);
        for node in &path.nodes {
            let MerklePathNode { index, sibling } = node;
            write_u8(buffer, *index);
            write_digest(buffer, sibling);
        }
    }
    Ok(())
}

type DecodedMerkleOpenings = (Vec<u32>, Vec<Vec<u8>>, Vec<MerkleAuthenticationPath>);

fn decode_merkle_openings(cursor: &mut ByteReader<'_>) -> Result<DecodedMerkleOpenings, SerError> {
    let indices_len = read_u32(cursor, SerKind::Openings, "indices_len")? as usize;
    let mut indices = Vec::with_capacity(indices_len);
    for _ in 0..indices_len {
        indices.push(read_u32(cursor, SerKind::Openings, "index")?);
    }

    let leaves_len = read_u32(cursor, SerKind::Openings, "leaves_len")? as usize;
    let mut leaves = Vec::with_capacity(leaves_len);
    for _ in 0..leaves_len {
        let leaf_len = read_u32(cursor, SerKind::Openings, "leaf_len")? as usize;
        let bytes = cursor.read_vec(SerKind::Openings, "leaf_bytes", leaf_len)?;
        leaves.push(bytes);
    }

    let paths_len = read_u32(cursor, SerKind::Openings, "paths_len")? as usize;
    let mut paths = Vec::with_capacity(paths_len);
    for _ in 0..paths_len {
        let nodes_len = read_u32(cursor, SerKind::Openings, "path_len")? as usize;
        let mut nodes = Vec::with_capacity(nodes_len);
        for _ in 0..nodes_len {
            let index = read_u8(cursor, SerKind::Openings, "path_index")?;
            let sibling = read_digest(cursor, SerKind::Openings, "path_sibling")?;
            nodes.push(MerklePathNode { index, sibling });
        }
        paths.push(MerkleAuthenticationPath { nodes });
    }

    Ok((indices, leaves, paths))
}

/// Deserialises an out-of-domain opening block.
pub fn deserialize_out_of_domain_opening(bytes: &[u8]) -> Result<OutOfDomainOpening, VerifyError> {
    deserialize_out_of_domain_opening_inner(bytes).map_err(VerifyError::from)
}

/// Serialises the proof header given the payload bytes.
pub fn serialize_proof_header(proof: &Proof, payload: &[u8]) -> Result<Vec<u8>, SerError> {
    let merkle_len = serialize_merkle_bundle(proof.merkle())?.len();
    let fri_len = serialize_fri_proof(proof.fri_proof())?.len();
    let openings_len = serialize_openings(proof.openings())?.len();
    let telemetry_len = if proof.has_telemetry() {
        Some(serialize_telemetry_frame(proof.telemetry())?.len())
    } else {
        None
    };

    let telemetry_total = telemetry_len.as_ref().copied().unwrap_or(0);
    let expected_total = merkle_len + fri_len + openings_len + telemetry_total;
    if payload.len() != expected_total {
        return Err(SerError::invalid_value(
            SerKind::Proof,
            "payload_length_mismatch",
        ));
    }

    serialize_proof_header_from_lengths(proof, merkle_len, fri_len, openings_len, telemetry_len)
}

/// Serialises the proof payload (body) without the integrity digest.
pub fn serialize_proof_payload(proof: &Proof) -> Result<Vec<u8>, SerError> {
    let merkle_bytes = serialize_merkle_bundle(proof.merkle())?;
    let fri_bytes = serialize_fri_proof(proof.fri_proof())?;
    let openings_bytes = serialize_openings(proof.openings())?;
    let telemetry_bytes = if proof.has_telemetry() {
        Some(serialize_telemetry_frame(proof.telemetry())?)
    } else {
        None
    };

    let capacity = merkle_bytes.len()
        + fri_bytes.len()
        + openings_bytes.len()
        + telemetry_bytes.as_ref().map_or(0, |bytes| bytes.len());
    let mut buffer = Vec::with_capacity(capacity);
    buffer.extend_from_slice(&merkle_bytes);
    buffer.extend_from_slice(&fri_bytes);
    buffer.extend_from_slice(&openings_bytes);
    if let Some(bytes) = telemetry_bytes {
        buffer.extend_from_slice(&bytes);
    }
    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ParamDigest as ConfigParamDigest, ProofKind, PROFILE_STANDARD_CONFIG};
    use crate::field::FieldElement;
    use crate::fri::{FriProof, FriSecurityLevel};
    use crate::proof::params::canonical_stark_params;
    use crate::proof::public_inputs::{ExecutionHeaderV1, PublicInputVersion, PublicInputs};
    use crate::proof::types::{
        CompositionBinding, CompositionOpenings, FriHandle, MerkleAuthenticationPath,
        MerklePathNode, OpeningsDescriptor, TelemetryOption, TraceOpenings,
    };
    use crate::utils::serialization::DigestBytes;

    fn sample_fri_proof() -> FriProof {
        let evaluations: Vec<FieldElement> = (0..64).map(|i| FieldElement(i as u64 + 1)).collect();
        let seed = [7u8; 32];
        let params = canonical_stark_params(&PROFILE_STANDARD_CONFIG);
        FriProof::prove_with_params(FriSecurityLevel::Standard, seed, &evaluations, &params)
            .expect("fri proof")
    }

    fn build_sample_proof() -> Proof {
        let fri_proof = sample_fri_proof();
        let fri_layer_roots = fri_proof.layer_roots.clone();
        let core_root = fri_layer_roots.first().copied().unwrap_or([0u8; 32]);
        let aux_root = [1u8; 32];
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
        let public_input_bytes =
            serialize_public_inputs(&public_inputs).expect("public inputs serialization");
        let public_digest = compute_public_digest(&public_input_bytes);

        let merkle = MerkleProofBundle {
            core_root,
            aux_root,
            fri_layer_roots,
        };
        let trace = TraceOpenings {
            indices: vec![0, 1],
            leaves: vec![vec![0xaa, 0xbb], vec![0xcc]],
            paths: vec![
                MerkleAuthenticationPath {
                    nodes: vec![MerklePathNode {
                        index: 0,
                        sibling: [0x11u8; 32],
                    }],
                },
                MerkleAuthenticationPath {
                    nodes: vec![MerklePathNode {
                        index: 1,
                        sibling: [0x22u8; 32],
                    }],
                },
            ],
        };
        let composition = Some(CompositionOpenings {
            indices: vec![0],
            leaves: vec![vec![0xdd, 0xee]],
            paths: vec![MerkleAuthenticationPath { nodes: Vec::new() }],
        });
        let openings = Openings {
            trace,
            composition,
            out_of_domain: vec![OutOfDomainOpening {
                point: [3u8; 32],
                core_values: vec![[4u8; 32]],
                aux_values: Vec::new(),
                composition_value: [5u8; 32],
            }],
        };
        let binding = CompositionBinding::new(
            ProofKind::Tx,
            crate::config::AirSpecId(DigestBytes { bytes: [7u8; 32] }),
            public_input_bytes,
            Some(DigestBytes { bytes: aux_root }),
        );
        let openings_descriptor = OpeningsDescriptor::new(merkle, openings);
        let fri_handle = FriHandle::new(fri_proof);
        let telemetry = Telemetry {
            header_length: 0,
            body_length: 0,
            fri_parameters: FriParametersMirror {
                fold: 2,
                cap_degree: 0,
                cap_size: 0,
                query_budget: 0,
            },
            integrity_digest: DigestBytes::default(),
        };
        let telemetry_option = TelemetryOption::new(true, telemetry);
        let mut proof = Proof::from_parts(
            PROOF_VERSION,
            ConfigParamDigest(DigestBytes { bytes: [6u8; 32] }),
            DigestBytes {
                bytes: public_digest,
            },
            DigestBytes { bytes: core_root },
            binding,
            openings_descriptor,
            fri_handle,
            telemetry_option,
        );

        // Populate telemetry with deterministic values.
        let payload = crate::proof::ser::serialize_proof_payload(&proof)
            .expect("proof payload serialization");
        let header_bytes = crate::proof::ser::serialize_proof_header(&proof, &payload)
            .expect("proof header serialization");
        let integrity = compute_integrity_digest(&header_bytes, &payload);
        let telemetry = proof.telemetry_mut();
        telemetry.set_header_length(header_bytes.len() as u32);
        telemetry.set_body_length((payload.len() + 32) as u32);
        telemetry.set_integrity_digest(DigestBytes { bytes: integrity });

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
        let mut cursor = ByteReader::new(&bytes);
        assert_eq!(
            read_u16(&mut cursor, SerKind::Proof, "version").unwrap(),
            PROOF_VERSION
        );
        assert_eq!(
            read_u8(&mut cursor, SerKind::Proof, "kind").unwrap(),
            super::encode_proof_kind(*proof.kind())
        );
        read_digest(&mut cursor, SerKind::Proof, "param_digest").unwrap();
        read_digest(&mut cursor, SerKind::Proof, "air_spec_id").unwrap();
        let public_len = read_u32(&mut cursor, SerKind::PublicInputs, "len").unwrap() as usize;
        let public_bytes = cursor
            .read_vec(SerKind::PublicInputs, "public_inputs", public_len)
            .unwrap();
        assert_eq!(public_bytes.as_slice(), proof.public_inputs());
        read_digest(&mut cursor, SerKind::PublicInputs, "public_digest").unwrap();
        read_digest(&mut cursor, SerKind::TraceCommitment, "trace_commit").unwrap();
        assert_eq!(
            read_u8(&mut cursor, SerKind::CompositionCommitment, "flag").unwrap(),
            1
        );
        read_digest(
            &mut cursor,
            SerKind::CompositionCommitment,
            "composition_commit",
        )
        .unwrap();
        let merkle_len = read_u32(&mut cursor, SerKind::TraceCommitment, "len").unwrap() as usize;
        let fri_len = read_u32(&mut cursor, SerKind::Fri, "len").unwrap() as usize;
        let openings_len = read_u32(&mut cursor, SerKind::Openings, "len").unwrap() as usize;
        let has_telemetry = read_u8(&mut cursor, SerKind::Telemetry, "flag").unwrap();
        let telemetry_len = if has_telemetry == 1 {
            read_u32(&mut cursor, SerKind::Telemetry, "len").unwrap() as usize
        } else {
            0
        };

        cursor
            .read_vec(SerKind::TraceCommitment, "merkle_bytes", merkle_len)
            .unwrap();
        cursor.read_vec(SerKind::Fri, "fri_bytes", fri_len).unwrap();
        cursor
            .read_vec(SerKind::Openings, "openings_bytes", openings_len)
            .unwrap();
        if has_telemetry == 1 {
            cursor
                .read_vec(SerKind::Telemetry, "telemetry_bytes", telemetry_len)
                .unwrap();
        }
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
