//! Deterministic prover pipeline implementation.
//!
//! The prover builds a proof envelope by executing the following steps:
//!
//! 1. Parse the witness into a list of LDE evaluations.
//! 2. Compute the initial commitment roots and bind them to the transcript.
//! 3. Derive Fiat–Shamir challenges (α-vector, OOD points, FRI seed).
//! 4. Produce a binary FRI proof using the deterministic seed.
//! 5. Assemble the envelope header/body, compute digests and enforce size limits.

use crate::config::{
    AirSpecId, ProfileConfig, ProofKind as ConfigProofKind, ProofKindLayout, ProofSystemConfig,
    ProverContext,
};
use crate::field::FieldElement;
use crate::fri::types::{FriError, FriProof, FriSecurityLevel};
use crate::hash::Hasher;
use crate::proof::envelope::{
    compute_commitment_digest, map_public_to_config_kind, serialize_public_inputs,
    FriParametersMirror, OutOfDomainOpening, ProofEnvelope, ProofEnvelopeBody, ProofEnvelopeHeader,
    PROOF_VERSION,
};
use crate::proof::public_inputs::PublicInputs;
use crate::proof::transcript::{Transcript, TranscriptBlockContext, TranscriptHeader};
use crate::utils::serialization::{DigestBytes, WitnessBlob};

use super::errors::VerificationFailure;

const ALPHA_VECTOR_LEN: usize = 4;
const MIN_OOD_POINTS: usize = 2;

/// Errors surfaced while building a proof envelope.
#[derive(Debug)]
pub enum ProverError {
    /// The proof system configuration declared an unsupported version.
    UnsupportedProofVersion(u8),
    /// Parameter digest mismatch between configuration and prover context.
    ParamDigestMismatch,
    /// Witness blob failed to parse into field elements.
    MalformedWitness(&'static str),
    /// Failed to derive Fiat–Shamir challenges.
    Transcript(crate::proof::transcript::TranscriptError),
    /// Binary FRI prover returned an error.
    Fri(FriError),
    /// The resulting proof exceeded the configured size limit.
    ProofTooLarge { actual: usize, limit: u32 },
}

impl From<crate::proof::transcript::TranscriptError> for ProverError {
    fn from(err: crate::proof::transcript::TranscriptError) -> Self {
        ProverError::Transcript(err)
    }
}

impl From<FriError> for ProverError {
    fn from(err: FriError) -> Self {
        ProverError::Fri(err)
    }
}

/// Builds a [`ProofEnvelope`] from public inputs and witness data.
pub fn build_envelope(
    public_inputs: &PublicInputs<'_>,
    witness: WitnessBlob<'_>,
    config: &ProofSystemConfig,
    context: &ProverContext,
) -> Result<ProofEnvelope, ProverError> {
    if config.proof_version.0 != PROOF_VERSION {
        return Err(ProverError::UnsupportedProofVersion(config.proof_version.0));
    }

    if config.param_digest != context.param_digest {
        return Err(ProverError::ParamDigestMismatch);
    }

    let proof_kind = map_public_to_config_kind(public_inputs.kind());
    let air_spec_id = resolve_air_spec_id(&context.profile.air_spec_ids, proof_kind);
    let security_level = map_security_level(&context.profile);

    let evaluations = parse_witness(witness)?;
    if evaluations.is_empty() {
        return Err(ProverError::MalformedWitness("empty_evaluations"));
    }

    // Preliminary FRI run to extract the core root (independent of the seed).
    let dummy_seed = [0u8; 32];
    let preliminary_proof = FriProof::prove(security_level, dummy_seed, &evaluations)?;
    let core_root = preliminary_proof
        .layer_roots
        .first()
        .copied()
        .unwrap_or([0u8; 32]);
    let aux_root = [0u8; 32];

    let public_inputs_bytes = serialize_public_inputs(public_inputs);
    let mut transcript = Transcript::new(TranscriptHeader {
        version: context.common_ids.transcript_version_id.clone(),
        poseidon_param_id: context.profile.poseidon_param_id.clone(),
        air_spec_id: air_spec_id.clone(),
        proof_kind,
        param_digest: context.param_digest.clone(),
    })?;
    transcript.absorb_public_inputs(&public_inputs_bytes)?;
    transcript.absorb_commitment_roots(core_root, Some(aux_root))?;
    transcript.absorb_air_spec_id(air_spec_id.clone())?;
    transcript.absorb_block_context(None::<TranscriptBlockContext>)?;

    let mut challenges = transcript.finalize()?;
    let alpha_vector = challenges.draw_alpha_vector(ALPHA_VECTOR_LEN)?;
    let ood_points = challenges.draw_ood_points(MIN_OOD_POINTS)?;
    let _ood_seed = challenges.draw_ood_seed()?;

    let fri_seed = challenges.draw_fri_seed()?;
    let fri_proof = FriProof::prove(security_level, fri_seed, &evaluations)?;

    // Consume the η challenges to keep transcript counters aligned with the proof.
    for (layer_index, _) in fri_proof.layer_roots.iter().enumerate() {
        let _ = challenges.draw_fri_eta(layer_index)?;
    }
    let _query_seed = challenges.draw_query_seed()?;

    if fri_proof.layer_roots.first().copied().unwrap_or([0u8; 32]) != core_root {
        return Err(ProverError::Fri(FriError::LayerRootMismatch { layer: 0 }));
    }

    let ood_openings = derive_ood_openings(&ood_points, &alpha_vector);
    let fri_layer_roots = fri_proof.layer_roots.clone();
    let commitment_digest = compute_commitment_digest(&core_root, &aux_root, &fri_layer_roots);

    let fri_parameters = FriParametersMirror {
        fold: 2,
        cap_degree: context.profile.fri_depth_range.max as u16,
        cap_size: fri_proof.final_polynomial.len() as u32,
        query_budget: security_level.query_budget() as u16,
    };

    let mut body = ProofEnvelopeBody {
        core_root,
        aux_root,
        fri_layer_roots,
        ood_openings,
        fri_proof,
        fri_parameters,
        integrity_digest: DigestBytes::default(),
    };

    let body_payload = body.serialize_payload();
    let body_length = (body_payload.len() + 32) as u32;
    let header_length = (2 + 32 + 32 + 4 + public_inputs_bytes.len() + 32 + 4 + 4) as u32;

    let header = ProofEnvelopeHeader {
        proof_version: PROOF_VERSION,
        proof_kind,
        param_digest: context.param_digest.clone(),
        air_spec_id,
        public_inputs: public_inputs_bytes,
        commitment_digest: DigestBytes {
            bytes: commitment_digest,
        },
        header_length,
        body_length,
    };

    let header_bytes = header.serialize(&body);
    let integrity_digest =
        crate::proof::envelope::compute_integrity_digest(&header_bytes, &body_payload);
    body.integrity_digest = DigestBytes {
        bytes: integrity_digest,
    };

    let total_size = header_bytes.len() + body_payload.len() + 32;
    if total_size > context.limits.max_proof_size_bytes as usize {
        return Err(ProverError::ProofTooLarge {
            actual: total_size,
            limit: context.limits.max_proof_size_bytes,
        });
    }

    Ok(ProofEnvelope { header, body })
}

fn parse_witness(witness: WitnessBlob<'_>) -> Result<Vec<FieldElement>, ProverError> {
    if witness.bytes.len() < 4 {
        return Err(ProverError::MalformedWitness("length_prefix"));
    }
    let mut len_bytes = [0u8; 4];
    len_bytes.copy_from_slice(&witness.bytes[..4]);
    let count = u32::from_le_bytes(len_bytes) as usize;
    let expected_len = 4 + count * 8;
    if witness.bytes.len() != expected_len {
        return Err(ProverError::MalformedWitness("trace_length"));
    }

    let mut values = Vec::with_capacity(count);
    for chunk in witness.bytes[4..].chunks_exact(8) {
        let mut field_bytes = [0u8; 8];
        field_bytes.copy_from_slice(chunk);
        values.push(FieldElement(u64::from_le_bytes(field_bytes)));
    }
    Ok(values)
}

fn resolve_air_spec_id(layout: &ProofKindLayout<AirSpecId>, kind: ConfigProofKind) -> AirSpecId {
    match kind {
        ConfigProofKind::Tx => layout.tx.clone(),
        ConfigProofKind::State => layout.state.clone(),
        ConfigProofKind::Pruning => layout.pruning.clone(),
        ConfigProofKind::Uptime => layout.uptime.clone(),
        ConfigProofKind::Consensus => layout.consensus.clone(),
        ConfigProofKind::Identity => layout.identity.clone(),
        ConfigProofKind::Aggregation => layout.aggregation.clone(),
        ConfigProofKind::VRF => layout.vrf.clone(),
    }
}

fn map_security_level(profile: &ProfileConfig) -> FriSecurityLevel {
    match profile.fri_queries {
        64 => FriSecurityLevel::Standard,
        96 => FriSecurityLevel::HiSec,
        48 => FriSecurityLevel::Throughput,
        other => {
            let _ = other; // fall back to standard for unknown profiles
            FriSecurityLevel::Standard
        }
    }
}

fn derive_ood_openings(points: &[[u8; 32]], alpha_vector: &[[u8; 32]]) -> Vec<OutOfDomainOpening> {
    points
        .iter()
        .enumerate()
        .map(|(index, point)| OutOfDomainOpening {
            point: *point,
            core_values: vec![hash_ood_value(b"RPP-OOD/CORE", point, alpha_vector, index)],
            aux_values: Vec::new(),
            composition_value: hash_ood_value(b"RPP-OOD/COMP", point, alpha_vector, index),
        })
        .collect()
}

fn hash_ood_value(label: &[u8], point: &[u8; 32], alphas: &[[u8; 32]], index: usize) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(label);
    hasher.update(point);
    hasher.update(&(index as u32).to_le_bytes());
    for alpha in alphas {
        hasher.update(alpha);
    }
    *hasher.finalize().as_bytes()
}

/// Helper converting prover errors into verification failures when the prover
/// surface is reused by integration tests.
impl From<ProverError> for VerificationFailure {
    fn from(error: ProverError) -> Self {
        match error {
            ProverError::UnsupportedProofVersion(_) => VerificationFailure::ErrEnvelopeMalformed,
            ProverError::ParamDigestMismatch => VerificationFailure::ErrParamDigestMismatch,
            ProverError::MalformedWitness(_) => VerificationFailure::ErrEnvelopeMalformed,
            ProverError::Transcript(_) => VerificationFailure::ErrTranscriptOrder,
            ProverError::Fri(FriError::LayerRootMismatch { .. }) => {
                VerificationFailure::ErrFRILayerRootMismatch
            }
            ProverError::Fri(FriError::PathInvalid { .. }) => {
                VerificationFailure::ErrFRIPathInvalid
            }
            ProverError::Fri(FriError::QueryOutOfRange { .. }) => {
                VerificationFailure::ErrFRIQueryOutOfRange
            }
            ProverError::Fri(_) => VerificationFailure::ErrFRILayerRootMismatch,
            ProverError::ProofTooLarge { .. } => VerificationFailure::ErrProofTooLarge,
        }
    }
}
