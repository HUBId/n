//! Deterministic verifier implementation.
//!
//! The verifier mirrors the prover pipeline by replaying the transcript,
//! recomputing the Fiat–Shamir challenges and validating the FRI proof.  All
//! structural checks (length prefixes, digests and bounds) are performed before
//! any expensive cryptographic operation.

use crate::config::{
    ProofKind as ConfigProofKind, ProofKindLayout, ProofSystemConfig, VerifierContext,
};
use crate::field::FieldElement;
use crate::fri::types::{FriError, FriSecurityLevel};
use crate::fri::FriVerifier;
use crate::hash::Hasher;
use crate::proof::envelope::{
    compute_commitment_digest, compute_integrity_digest, map_public_to_config_kind,
    serialize_public_inputs,
};
use crate::proof::public_inputs::PublicInputs;
use crate::proof::transcript::{Transcript, TranscriptBlockContext, TranscriptHeader};
use crate::proof::types::{
    OutOfDomainOpening, Proof, PROOF_ALPHA_VECTOR_LEN, PROOF_MAX_FRI_LAYERS, PROOF_MAX_QUERY_COUNT,
    PROOF_MIN_OOD_POINTS, PROOF_TELEMETRY_MAX_CAP_DEGREE, PROOF_TELEMETRY_MAX_CAP_SIZE,
    PROOF_TELEMETRY_MAX_QUERY_BUDGET, PROOF_VERSION,
};
use crate::utils::serialization::ProofBytes;

use super::errors::VerificationFailure;

/// Verifies a serialized proof against the provided configuration and context.
pub fn verify_proof_bytes(
    declared_kind: ConfigProofKind,
    public_inputs: &PublicInputs<'_>,
    proof_bytes: &ProofBytes,
    config: &ProofSystemConfig,
    context: &VerifierContext,
) -> Result<(), VerificationFailure> {
    let prechecked = precheck_proof_bytes(
        declared_kind,
        public_inputs,
        proof_bytes,
        config,
        context,
        None,
    )?;
    execute_fri_stage(&prechecked)
}

#[derive(Debug, Clone)]
pub(crate) struct PrecheckedProof {
    pub(crate) proof: Proof,
    pub(crate) fri_seed: [u8; 32],
    pub(crate) security_level: FriSecurityLevel,
}

pub(crate) fn precheck_proof_bytes(
    declared_kind: ConfigProofKind,
    public_inputs: &PublicInputs<'_>,
    proof_bytes: &ProofBytes,
    config: &ProofSystemConfig,
    context: &VerifierContext,
    block_context: Option<&TranscriptBlockContext>,
) -> Result<PrecheckedProof, VerificationFailure> {
    if (config.proof_version.0 as u16) != PROOF_VERSION {
        return Err(VerificationFailure::ErrEnvelopeMalformed);
    }
    if config.param_digest != context.param_digest {
        return Err(VerificationFailure::ErrParamDigestMismatch);
    }

    let proof = Proof::from_bytes(proof_bytes.as_slice())
        .map_err(|_| VerificationFailure::ErrEnvelopeMalformed)?;
    validate_header(&proof, declared_kind, public_inputs, config, context)?;
    let prechecked = precheck_body(&proof, public_inputs, context, block_context)?;

    Ok(PrecheckedProof {
        proof,
        fri_seed: prechecked.fri_seed,
        security_level: prechecked.security_level,
    })
}

pub(crate) fn execute_fri_stage(proof: &PrecheckedProof) -> Result<(), VerificationFailure> {
    FriVerifier::verify(
        &proof.proof.fri_proof,
        proof.security_level,
        proof.fri_seed,
        |index| {
            proof
                .proof
                .fri_proof
                .final_polynomial
                .get(index)
                .copied()
                .unwrap_or(FieldElement::ZERO)
        },
    )
    .map_err(map_fri_error)
}

fn validate_header(
    proof: &Proof,
    declared_kind: ConfigProofKind,
    public_inputs: &PublicInputs<'_>,
    config: &ProofSystemConfig,
    context: &VerifierContext,
) -> Result<(), VerificationFailure> {
    if proof.version != PROOF_VERSION {
        return Err(VerificationFailure::ErrEnvelopeMalformed);
    }

    let expected_kind = map_public_to_config_kind(public_inputs.kind());
    if proof.kind != expected_kind || proof.kind != declared_kind {
        return Err(VerificationFailure::ErrEnvelopeMalformed);
    }

    if proof.param_digest != config.param_digest {
        return Err(VerificationFailure::ErrParamDigestMismatch);
    }
    if proof.param_digest != context.param_digest {
        return Err(VerificationFailure::ErrParamDigestMismatch);
    }

    let expected_public_inputs = serialize_public_inputs(public_inputs);
    if proof.public_inputs != expected_public_inputs {
        return Err(VerificationFailure::ErrPublicInputMismatch);
    }

    let expected_air_spec = resolve_air_spec_id(&context.profile.air_spec_ids, proof.kind);
    if proof.air_spec_id != expected_air_spec {
        return Err(VerificationFailure::ErrEnvelopeMalformed);
    }

    Ok(())
}

struct PrecheckedBody {
    fri_seed: [u8; 32],
    security_level: FriSecurityLevel,
}

fn precheck_body(
    proof: &Proof,
    public_inputs: &PublicInputs<'_>,
    context: &VerifierContext,
    block_context: Option<&TranscriptBlockContext>,
) -> Result<PrecheckedBody, VerificationFailure> {
    let payload = proof.serialize_payload();
    let expected_body_length = payload.len() as u32 + 32;
    if proof.telemetry.body_length != expected_body_length {
        return Err(VerificationFailure::ErrEnvelopeMalformed);
    }

    let commitment_digest = compute_commitment_digest(
        &proof.merkle.core_root,
        &proof.merkle.aux_root,
        &proof.merkle.fri_layer_roots,
    );
    if proof.commitment_digest.bytes != commitment_digest {
        return Err(VerificationFailure::ErrCommitmentDigestMismatch);
    }

    if proof
        .fri_proof
        .layer_roots
        .first()
        .copied()
        .unwrap_or([0u8; 32])
        != proof.merkle.core_root
    {
        return Err(VerificationFailure::ErrFRILayerRootMismatch);
    }

    if proof.merkle.fri_layer_roots != proof.fri_proof.layer_roots {
        return Err(VerificationFailure::ErrFRILayerRootMismatch);
    }

    let transcript_kind = proof.kind;
    let air_spec_id = resolve_air_spec_id(&context.profile.air_spec_ids, transcript_kind);
    let mut transcript = Transcript::new(TranscriptHeader {
        version: context.common_ids.transcript_version_id.clone(),
        poseidon_param_id: context.profile.poseidon_param_id.clone(),
        air_spec_id: air_spec_id.clone(),
        proof_kind: transcript_kind,
        param_digest: context.param_digest.clone(),
    })
    .map_err(|_| VerificationFailure::ErrTranscriptOrder)?;

    let public_inputs_bytes = serialize_public_inputs(public_inputs);
    transcript
        .absorb_public_inputs(&public_inputs_bytes)
        .map_err(|_| VerificationFailure::ErrTranscriptOrder)?;
    transcript
        .absorb_commitment_roots(proof.merkle.core_root, Some(proof.merkle.aux_root))
        .map_err(|_| VerificationFailure::ErrTranscriptOrder)?;
    transcript
        .absorb_air_spec_id(air_spec_id)
        .map_err(|_| VerificationFailure::ErrTranscriptOrder)?;
    transcript
        .absorb_block_context(block_context.cloned())
        .map_err(|_| VerificationFailure::ErrTranscriptOrder)?;

    let mut challenges = transcript
        .finalize()
        .map_err(|_| VerificationFailure::ErrTranscriptOrder)?;
    let alpha_vector = challenges
        .draw_alpha_vector(PROOF_ALPHA_VECTOR_LEN)
        .map_err(|_| VerificationFailure::ErrTranscriptOrder)?;
    let ood_points = challenges
        .draw_ood_points(PROOF_MIN_OOD_POINTS)
        .map_err(|_| VerificationFailure::ErrTranscriptOrder)?;
    let _ood_seed = challenges
        .draw_ood_seed()
        .map_err(|_| VerificationFailure::ErrTranscriptOrder)?;

    verify_ood_openings(&proof.openings.out_of_domain, &ood_points, &alpha_vector)?;

    let fri_seed = challenges
        .draw_fri_seed()
        .map_err(|_| VerificationFailure::ErrTranscriptOrder)?;
    for (layer_index, _) in proof.merkle.fri_layer_roots.iter().enumerate() {
        challenges
            .draw_fri_eta(layer_index)
            .map_err(|_| VerificationFailure::ErrTranscriptOrder)?;
    }
    challenges
        .draw_query_seed()
        .map_err(|_| VerificationFailure::ErrTranscriptOrder)?;

    let security_level = map_security_level(&context.profile);
    if proof.fri_proof.security_level != security_level {
        return Err(VerificationFailure::ErrFRILayerRootMismatch);
    }
    if proof.telemetry.fri_parameters.fold != 2
        || proof.telemetry.fri_parameters.query_budget as usize != security_level.query_budget()
    {
        return Err(VerificationFailure::ErrEnvelopeMalformed);
    }

    if proof.telemetry.fri_parameters.cap_degree > PROOF_TELEMETRY_MAX_CAP_DEGREE
        || proof.telemetry.fri_parameters.cap_size > PROOF_TELEMETRY_MAX_CAP_SIZE
        || proof.telemetry.fri_parameters.query_budget > PROOF_TELEMETRY_MAX_QUERY_BUDGET
    {
        return Err(VerificationFailure::ErrEnvelopeMalformed);
    }

    let header_bytes = proof.serialize_header(&payload);
    if proof.telemetry.header_length != header_bytes.len() as u32 {
        return Err(VerificationFailure::ErrEnvelopeMalformed);
    }

    let integrity_digest = compute_integrity_digest(&header_bytes, &payload);
    if proof.telemetry.integrity_digest.bytes != integrity_digest {
        return Err(VerificationFailure::ErrIntegrityDigestMismatch);
    }

    if proof_size_exceeds_limit(proof, context) {
        return Err(VerificationFailure::ErrProofTooLarge);
    }

    enforce_resource_limits(proof.kind, public_inputs, context, proof)?;

    Ok(PrecheckedBody {
        fri_seed,
        security_level,
    })
}

fn enforce_resource_limits(
    proof_kind: ConfigProofKind,
    public_inputs: &PublicInputs<'_>,
    context: &VerifierContext,
    proof: &Proof,
) -> Result<(), VerificationFailure> {
    if proof.fri_proof.layer_roots.len() > context.limits.max_layers as usize {
        return Err(VerificationFailure::ErrFRILayerRootMismatch);
    }

    if proof.fri_proof.layer_roots.len() > PROOF_MAX_FRI_LAYERS {
        return Err(VerificationFailure::ErrFRILayerRootMismatch);
    }

    if proof.fri_proof.queries.len() > context.limits.max_queries as usize {
        return Err(VerificationFailure::ErrFRIQueryOutOfRange);
    }

    if proof.fri_proof.queries.len() > PROOF_MAX_QUERY_COUNT {
        return Err(VerificationFailure::ErrFRIQueryOutOfRange);
    }

    enforce_trace_limits(proof_kind, public_inputs, context)
}

fn enforce_trace_limits(
    proof_kind: ConfigProofKind,
    public_inputs: &PublicInputs<'_>,
    context: &VerifierContext,
) -> Result<(), VerificationFailure> {
    let width_limit = *context.limits.per_proof_max_trace_width.get(proof_kind) as u32;
    let step_limit = *context.limits.per_proof_max_trace_steps.get(proof_kind);

    if let PublicInputs::Execution { header, .. } = public_inputs {
        if header.trace_width > width_limit {
            return Err(VerificationFailure::ErrDegreeBoundExceeded);
        }
        if header.trace_length > step_limit {
            return Err(VerificationFailure::ErrDegreeBoundExceeded);
        }
    }

    Ok(())
}

fn verify_ood_openings(
    openings: &[OutOfDomainOpening],
    points: &[[u8; 32]],
    alphas: &[[u8; 32]],
) -> Result<(), VerificationFailure> {
    if openings.len() != points.len() {
        return Err(VerificationFailure::ErrOODInvalid);
    }

    for (index, (opening, point)) in openings.iter().zip(points.iter()).enumerate() {
        let expected_core = hash_ood_value(b"RPP-OOD/CORE", point, alphas, index);
        if opening.core_values.len() != 1 || opening.core_values[0] != expected_core {
            return Err(VerificationFailure::ErrOODInvalid);
        }
        if !opening.aux_values.is_empty() {
            return Err(VerificationFailure::ErrOODInvalid);
        }
        let expected_comp = hash_ood_value(b"RPP-OOD/COMP", point, alphas, index);
        if opening.composition_value != expected_comp {
            return Err(VerificationFailure::ErrOODInvalid);
        }
    }

    Ok(())
}

fn proof_size_exceeds_limit(proof: &Proof, context: &VerifierContext) -> bool {
    let payload = proof.serialize_payload();
    let header_bytes = proof.serialize_header(&payload);
    let total = header_bytes.len() + payload.len() + 32;
    total > context.limits.max_proof_size_bytes as usize
}

fn resolve_air_spec_id(
    layout: &ProofKindLayout<crate::config::AirSpecId>,
    kind: ConfigProofKind,
) -> crate::config::AirSpecId {
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

fn map_security_level(profile: &crate::config::ProfileConfig) -> FriSecurityLevel {
    match profile.fri_queries {
        64 => FriSecurityLevel::Standard,
        96 => FriSecurityLevel::HiSec,
        48 => FriSecurityLevel::Throughput,
        _ => FriSecurityLevel::Standard,
    }
}

fn map_fri_error(error: FriError) -> VerificationFailure {
    match error {
        FriError::EmptyCodeword => VerificationFailure::ErrFRILayerRootMismatch,
        FriError::VersionMismatch { .. } => VerificationFailure::ErrFRILayerRootMismatch,
        FriError::QueryOutOfRange { .. } => VerificationFailure::ErrFRIQueryOutOfRange,
        FriError::PathInvalid { .. } => VerificationFailure::ErrFRIPathInvalid,
        FriError::LayerRootMismatch { .. } => VerificationFailure::ErrFRILayerRootMismatch,
        FriError::SecurityLevelMismatch => VerificationFailure::ErrFRILayerRootMismatch,
        FriError::QueryBudgetMismatch { .. } => VerificationFailure::ErrFRILayerRootMismatch,
        FriError::FoldingConstraintViolated { .. } => VerificationFailure::ErrFRILayerRootMismatch,
        FriError::OodsInvalid => VerificationFailure::ErrFRILayerRootMismatch,
        FriError::Serialization(_) => VerificationFailure::ErrFRIPathInvalid,
        FriError::InvalidStructure(_) => VerificationFailure::ErrFRIPathInvalid,
    }
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
