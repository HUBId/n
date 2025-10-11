//! Serialization helpers for the proof envelope.
//!
//! The routines in this module encapsulate the canonical byte-level contracts
//! shared by the prover and verifier. Proof envelopes are split into a header
//! followed by a payload:
//!
//! ```text
//! +----------------------+----------------------------------------------+
//! | Header               | Payload                                      |
//! +======================+==============================================+
//! | version (u16)        | openings descriptor bytes                    |
//! | params hash (32B)    | fri handle bytes                             |
//! | public digest (32B)  | telemetry bytes (present flag gated)         |
//! | trace commit (32B)   |                                              |
//! | binding len (u32)    |                                              |
//! | binding bytes        |                                              |
//! | openings len (u32)   |                                              |
//! | fri len (u32)        |                                              |
//! | telemetry flag (u8)  |                                              |
//! | telemetry len? (u32) |                                              |
//! +----------------------+----------------------------------------------+
//! ```
//!
//! `binding bytes` encode the [`CompositionBinding`] wrapper documenting the
//! proof kind, AIR specification identifier, public input payload and optional
//! composition commitment. The payload starts with the serialized
//! [`OpeningsDescriptor`], continues with the [`FriHandle`] encoding and ends
//! with the telemetry frame when the [`TelemetryOption`] advertises telemetry
//! data. All helpers operate exclusively through these wrapper APIs so callers
//! preserve the integrity checks enforced by the handles.

use crate::config::{ParamDigest, ProofKind};
use crate::hash::Hasher;
use crate::proof::public_inputs::{
    AggregationHeaderV1, ExecutionHeaderV1, ProofKind as PublicProofKind, PublicInputVersion,
    PublicInputs, RecursionHeaderV1, VrfHeaderV1,
};
use crate::proof::types::{
    CompositionBinding, FriHandle, MerkleSection, Openings, OpeningsDescriptor, OutOfDomainOpening,
    Proof, TelemetryOption, VerifyError, PROOF_VERSION,
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
pub fn compute_public_digest(bytes: &[u8]) -> [u8; DIGEST_SIZE] {
    let mut hasher = Hasher::new();
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

fn binding_public_digest_matches(binding: &CompositionBinding, digest: &DigestBytes) -> bool {
    compute_public_digest(binding.public_inputs()) == digest.bytes
}

fn trace_commit_matches(trace_commit: &DigestBytes, openings: &OpeningsDescriptor) -> bool {
    trace_commit.bytes == *openings.merkle().core_root()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CompositionConsistencyIssue {
    CommitWithoutOpenings,
    OpeningsWithoutCommit,
    RootMismatch,
    UnexpectedAuxRoot,
}

fn composition_consistency_issue(
    binding: &CompositionBinding,
    descriptor: &OpeningsDescriptor,
) -> Option<CompositionConsistencyIssue> {
    match (binding.composition_commit(), descriptor.composition()) {
        (Some(commit), Some(_)) => {
            if commit.bytes != *descriptor.merkle().aux_root() {
                Some(CompositionConsistencyIssue::RootMismatch)
            } else {
                None
            }
        }
        (Some(_), None) => Some(CompositionConsistencyIssue::CommitWithoutOpenings),
        (None, Some(_)) => Some(CompositionConsistencyIssue::OpeningsWithoutCommit),
        (None, None) => {
            if descriptor.merkle().aux_root() != &[0u8; 32] {
                Some(CompositionConsistencyIssue::UnexpectedAuxRoot)
            } else {
                None
            }
        }
    }
}

fn map_composition_issue_to_ser(issue: CompositionConsistencyIssue) -> SerError {
    match issue {
        CompositionConsistencyIssue::CommitWithoutOpenings => {
            SerError::invalid_value(SerKind::CompositionCommitment, "commit_without_openings")
        }
        CompositionConsistencyIssue::OpeningsWithoutCommit => {
            SerError::invalid_value(SerKind::CompositionCommitment, "openings_without_commit")
        }
        CompositionConsistencyIssue::RootMismatch => {
            SerError::invalid_value(SerKind::CompositionCommitment, "composition_root_mismatch")
        }
        CompositionConsistencyIssue::UnexpectedAuxRoot => {
            SerError::invalid_value(SerKind::CompositionCommitment, "aux_root_without_commit")
        }
    }
}

fn map_composition_issue_to_verify(issue: CompositionConsistencyIssue) -> VerifyError {
    match issue {
        CompositionConsistencyIssue::CommitWithoutOpenings => {
            VerifyError::CompositionInconsistent {
                reason: "missing_composition_openings".to_string(),
            }
        }
        CompositionConsistencyIssue::OpeningsWithoutCommit => {
            VerifyError::CompositionInconsistent {
                reason: "missing_composition_commit".to_string(),
            }
        }
        CompositionConsistencyIssue::RootMismatch
        | CompositionConsistencyIssue::UnexpectedAuxRoot => VerifyError::RootMismatch {
            section: MerkleSection::CompositionCommit,
        },
    }
}

/// Serialises a [`Proof`] into the canonical envelope layout.
pub fn serialize_proof(proof: &Proof) -> Result<Vec<u8>, SerError> {
    let binding = proof.composition();
    let openings_descriptor = proof.openings();

    if !binding_public_digest_matches(binding, proof.public_digest()) {
        return Err(SerError::invalid_value(
            SerKind::PublicInputs,
            "digest_mismatch",
        ));
    }

    if !trace_commit_matches(proof.trace_commit(), openings_descriptor) {
        return Err(SerError::invalid_value(
            SerKind::TraceCommitment,
            "trace_root_mismatch",
        ));
    }

    if let Some(issue) = composition_consistency_issue(binding, openings_descriptor) {
        return Err(map_composition_issue_to_ser(issue));
    }

    let binding_bytes = binding.serialize_bytes()?;
    let openings_bytes = openings_descriptor.serialize_bytes()?;
    let fri_bytes = proof.fri().serialize_bytes()?;
    let telemetry_bytes = proof.telemetry().serialize_bytes()?;

    let header = serialize_proof_header_from_lengths(
        proof,
        &binding_bytes,
        openings_bytes.len(),
        fri_bytes.len(),
        telemetry_bytes.as_ref().map(|bytes| bytes.len()),
    )?;

    let payload_capacity = openings_bytes.len()
        + fri_bytes.len()
        + telemetry_bytes.as_ref().map_or(0, |bytes| bytes.len());

    let mut out = Vec::with_capacity(header.len() + payload_capacity);
    out.extend_from_slice(&header);
    out.extend_from_slice(&openings_bytes);
    out.extend_from_slice(&fri_bytes);
    if let Some(bytes) = telemetry_bytes {
        out.extend_from_slice(&bytes);
    }

    Ok(out)
}

/// Serialises the proof header given the payload bytes.
pub fn serialize_proof_header(proof: &Proof, payload: &[u8]) -> Result<Vec<u8>, SerError> {
    let binding_bytes = proof.composition().serialize_bytes()?;
    let openings_bytes = proof.openings().serialize_bytes()?;
    let fri_bytes = proof.fri().serialize_bytes()?;
    let telemetry_bytes = proof.telemetry().serialize_bytes()?;

    let telemetry_total = telemetry_bytes.as_ref().map_or(0, |bytes| bytes.len());
    let expected_total = openings_bytes.len() + fri_bytes.len() + telemetry_total;
    if payload.len() != expected_total {
        return Err(SerError::invalid_value(
            SerKind::Proof,
            "payload_length_mismatch",
        ));
    }

    serialize_proof_header_from_lengths(
        proof,
        &binding_bytes,
        openings_bytes.len(),
        fri_bytes.len(),
        telemetry_bytes.as_ref().map(|bytes| bytes.len()),
    )
}

/// Serialises the proof payload (body) without the integrity digest.
pub fn serialize_proof_payload(proof: &Proof) -> Result<Vec<u8>, SerError> {
    let openings_bytes = proof.openings().serialize_bytes()?;
    let fri_bytes = proof.fri().serialize_bytes()?;
    let telemetry_bytes = proof.telemetry().serialize_bytes()?;

    let capacity = openings_bytes.len()
        + fri_bytes.len()
        + telemetry_bytes.as_ref().map_or(0, |bytes| bytes.len());
    let mut buffer = Vec::with_capacity(capacity);
    buffer.extend_from_slice(&openings_bytes);
    buffer.extend_from_slice(&fri_bytes);
    if let Some(bytes) = telemetry_bytes {
        buffer.extend_from_slice(&bytes);
    }
    Ok(buffer)
}

fn serialize_proof_header_from_lengths(
    proof: &Proof,
    binding_bytes: &[u8],
    openings_len: usize,
    fri_len: usize,
    telemetry_len: Option<usize>,
) -> Result<Vec<u8>, SerError> {
    let mut buffer = Vec::new();
    write_u16(&mut buffer, proof.version());
    write_digest(&mut buffer, proof.params_hash().as_bytes());
    write_digest(&mut buffer, &proof.public_digest().bytes);
    write_digest(&mut buffer, &proof.trace_commit().bytes);

    let binding_len = ensure_u32(binding_bytes.len(), SerKind::Proof, "composition_len")?;
    write_u32(&mut buffer, binding_len);
    write_bytes(&mut buffer, binding_bytes);

    let openings_len = ensure_u32(openings_len, SerKind::Openings, "descriptor_len")?;
    write_u32(&mut buffer, openings_len);
    let fri_len = ensure_u32(fri_len, SerKind::Fri, "len")?;
    write_u32(&mut buffer, fri_len);

    let telemetry_present = proof.telemetry().is_present();
    write_u8(&mut buffer, if telemetry_present { 1 } else { 0 });

    if telemetry_present {
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

    let params_hash = ParamDigest(DigestBytes {
        bytes: read_digest(&mut cursor, SerKind::Proof, "params_hash")
            .map_err(VerifyError::from)?,
    });

    let public_digest_bytes = read_digest(&mut cursor, SerKind::PublicInputs, "public_digest")
        .map_err(VerifyError::from)?;

    let trace_commit = DigestBytes {
        bytes: read_digest(&mut cursor, SerKind::TraceCommitment, "trace_commit")
            .map_err(VerifyError::from)?,
    };

    let binding_len = read_u32(&mut cursor, SerKind::Proof, "composition_len")
        .map_err(VerifyError::from)? as usize;
    let binding_bytes = cursor
        .read_vec(SerKind::Proof, "composition_bytes", binding_len)
        .map_err(VerifyError::from)?;
    let binding = CompositionBinding::deserialize_bytes(&binding_bytes)?;

    let openings_len = read_u32(&mut cursor, SerKind::Openings, "descriptor_len")
        .map_err(VerifyError::from)? as usize;
    let fri_len = read_u32(&mut cursor, SerKind::Fri, "len").map_err(VerifyError::from)? as usize;

    let telemetry_present =
        match read_u8(&mut cursor, SerKind::Telemetry, "flag").map_err(VerifyError::from)? {
            0 => false,
            1 => true,
            _ => return Err(VerifyError::Serialization(SerKind::Telemetry)),
        };

    let telemetry_len = if telemetry_present {
        Some(read_u32(&mut cursor, SerKind::Telemetry, "len").map_err(VerifyError::from)? as usize)
    } else {
        None
    };

    let openings_bytes = cursor
        .read_vec(SerKind::Openings, "descriptor_bytes", openings_len)
        .map_err(VerifyError::from)?;
    let openings_descriptor = OpeningsDescriptor::deserialize_bytes(&openings_bytes)?;

    let fri_bytes = cursor
        .read_vec(SerKind::Fri, "fri_bytes", fri_len)
        .map_err(VerifyError::from)?;
    let fri_handle = FriHandle::deserialize_bytes(&fri_bytes)?;

    let telemetry_option = if let Some(len) = telemetry_len {
        let telemetry_bytes = cursor
            .read_vec(SerKind::Telemetry, "telemetry_bytes", len)
            .map_err(VerifyError::from)?;
        TelemetryOption::deserialize_bytes(telemetry_present, Some(&telemetry_bytes))?
    } else {
        TelemetryOption::deserialize_bytes(false, None)?
    };

    ensure_consumed(&cursor, SerKind::Proof).map_err(VerifyError::from)?;

    let public_digest = DigestBytes {
        bytes: public_digest_bytes,
    };

    if !binding_public_digest_matches(&binding, &public_digest) {
        return Err(VerifyError::PublicDigestMismatch);
    }

    if !trace_commit_matches(&trace_commit, &openings_descriptor) {
        return Err(VerifyError::RootMismatch {
            section: MerkleSection::TraceCommit,
        });
    }

    if let Some(issue) = composition_consistency_issue(&binding, &openings_descriptor) {
        return Err(map_composition_issue_to_verify(issue));
    }

    Ok(Proof::from_parts(
        version,
        params_hash,
        public_digest,
        trace_commit,
        binding,
        openings_descriptor,
        fri_handle,
        telemetry_option,
    ))
}

/// Serialises the out-of-domain opening container.
pub fn serialize_openings(openings: &Openings) -> Result<Vec<u8>, SerError> {
    openings.serialize_bytes()
}

/// Serialises a single out-of-domain opening block.
pub fn serialize_out_of_domain_opening(opening: &OutOfDomainOpening) -> Result<Vec<u8>, SerError> {
    opening.serialize_bytes()
}

/// Deserialises an out-of-domain opening block.
pub fn deserialize_out_of_domain_opening(bytes: &[u8]) -> Result<OutOfDomainOpening, VerifyError> {
    OutOfDomainOpening::deserialize_bytes(bytes)
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
        CompositionBinding, CompositionOpenings, FriHandle, FriParametersMirror,
        MerkleAuthenticationPath, MerklePathNode, MerkleProofBundle, OpeningsDescriptor, Telemetry,
        TelemetryOption, TraceOpenings,
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
        let telemetry = proof.telemetry_mut().frame_mut();
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
            read_digest(&mut cursor, SerKind::Proof, "params_hash").unwrap(),
            *proof.params_hash().as_bytes()
        );
        assert_eq!(
            read_digest(&mut cursor, SerKind::PublicInputs, "public_digest").unwrap(),
            proof.public_digest().bytes
        );
        assert_eq!(
            read_digest(&mut cursor, SerKind::TraceCommitment, "trace_commit").unwrap(),
            proof.trace_commit().bytes
        );
        let binding_len = read_u32(&mut cursor, SerKind::Proof, "binding_len").unwrap() as usize;
        let binding_bytes = cursor
            .read_vec(SerKind::Proof, "binding_bytes", binding_len)
            .unwrap();
        let decoded_binding =
            CompositionBinding::deserialize_bytes(&binding_bytes).expect("decode binding");
        assert_eq!(decoded_binding, proof.composition().clone());
        let openings_len =
            read_u32(&mut cursor, SerKind::Openings, "descriptor_len").unwrap() as usize;
        let fri_len = read_u32(&mut cursor, SerKind::Fri, "fri_len").unwrap() as usize;
        let has_telemetry = read_u8(&mut cursor, SerKind::Telemetry, "flag").unwrap();
        assert_eq!(
            has_telemetry,
            if proof.telemetry().has_telemetry() {
                1
            } else {
                0
            }
        );
        let telemetry_len = if has_telemetry == 1 {
            read_u32(&mut cursor, SerKind::Telemetry, "len").unwrap() as usize
        } else {
            0
        };

        let openings_bytes = cursor
            .read_vec(SerKind::Openings, "openings_bytes", openings_len)
            .unwrap();
        let decoded_descriptor =
            OpeningsDescriptor::deserialize_bytes(&openings_bytes).expect("decode openings");
        assert_eq!(decoded_descriptor, proof.openings().clone());
        let fri_bytes = cursor.read_vec(SerKind::Fri, "fri_bytes", fri_len).unwrap();
        let decoded_fri = FriHandle::deserialize_bytes(&fri_bytes).expect("decode fri");
        assert_eq!(decoded_fri, proof.fri().clone());
        if has_telemetry == 1 {
            let telemetry_bytes = cursor
                .read_vec(SerKind::Telemetry, "telemetry_bytes", telemetry_len)
                .unwrap();
            let expected = proof
                .telemetry()
                .serialize_bytes()
                .expect("serialize telemetry")
                .expect("telemetry bytes");
            assert_eq!(telemetry_len, expected.len());
            assert_eq!(telemetry_bytes, expected);
        }
        assert_eq!(cursor.remaining(), 0);
    }

    #[test]
    fn serialization_rejects_public_digest_mismatch() {
        let mut proof = build_sample_proof();
        proof.public_digest_mut().bytes[0] ^= 0xff;
        let err = serialize_proof(&proof).expect_err("should fail");
        match err {
            SerError::InvalidValue { kind, field } => {
                assert_eq!(kind, SerKind::PublicInputs);
                assert_eq!(field, "digest_mismatch");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn serialization_rejects_trace_commit_mismatch() {
        let mut proof = build_sample_proof();
        proof.trace_commit_mut().bytes[0] ^= 0x01;
        let err = serialize_proof(&proof).expect_err("should fail");
        match err {
            SerError::InvalidValue { kind, field } => {
                assert_eq!(kind, SerKind::TraceCommitment);
                assert_eq!(field, "trace_root_mismatch");
            }
            other => panic!("unexpected error: {other:?}"),
        }
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

    #[test]
    fn deserialize_rejects_public_digest_mismatch() {
        let proof = build_sample_proof();
        let mut bytes = serialize_proof(&proof).expect("serialize proof");
        let offset = 2 + 32; // version + params hash
        bytes[offset] ^= 0x01;
        let err = deserialize_proof(&bytes).expect_err("should fail");
        match err {
            VerifyError::PublicDigestMismatch => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn deserialize_rejects_trace_commit_mismatch() {
        let proof = build_sample_proof();
        let mut bytes = serialize_proof(&proof).expect("serialize proof");
        let offset = 2 + 32 + 32; // version + params hash + public digest
        bytes[offset] ^= 0x01;
        let err = deserialize_proof(&bytes).expect_err("should fail");
        match err {
            VerifyError::RootMismatch {
                section: MerkleSection::TraceCommit,
            } => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }
}
