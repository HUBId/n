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
use crate::proof::public_inputs::PublicInputs;
use crate::proof::ser::{
    compute_commitment_digest, compute_integrity_digest, encode_proof_kind,
    map_public_to_config_kind, serialize_public_inputs,
};
use crate::proof::transcript::{Transcript, TranscriptBlockContext, TranscriptHeader};
use crate::proof::types::{
    FriVerifyIssue, MerkleSection, OutOfDomainOpening, Proof, VerifyError, VerifyReport,
    PROOF_ALPHA_VECTOR_LEN, PROOF_MAX_FRI_LAYERS, PROOF_MAX_QUERY_COUNT, PROOF_MIN_OOD_POINTS,
    PROOF_TELEMETRY_MAX_CAP_DEGREE, PROOF_TELEMETRY_MAX_CAP_SIZE, PROOF_TELEMETRY_MAX_QUERY_BUDGET,
    PROOF_VERSION,
};
use crate::utils::serialization::ProofBytes;

#[derive(Debug, Default, Clone, Copy)]
struct VerificationStages {
    params_ok: bool,
    public_ok: bool,
    merkle_ok: bool,
    fri_ok: bool,
    composition_ok: bool,
}

/// Verifies a serialized proof against the provided configuration and context.
pub fn verify_proof_bytes(
    declared_kind: ConfigProofKind,
    public_inputs: &PublicInputs<'_>,
    proof_bytes: &ProofBytes,
    config: &ProofSystemConfig,
    context: &VerifierContext,
) -> Result<VerifyReport, VerifyError> {
    if (config.proof_version.0 as u16) != PROOF_VERSION {
        return Err(VerifyError::VersionMismatch {
            expected: PROOF_VERSION,
            actual: config.proof_version.0 as u16,
        });
    }
    if config.param_digest != context.param_digest {
        return Err(VerifyError::ParamsHashMismatch);
    }

    let proof = Proof::from_bytes(proof_bytes.as_slice())?;
    let total_bytes = proof_bytes.as_slice().len() as u64;
    let mut stages = VerificationStages::default();
    match precheck_decoded_proof(
        proof,
        declared_kind,
        public_inputs,
        config,
        context,
        None,
        &mut stages,
    ) {
        Ok(prechecked) => match execute_fri_stage(&prechecked) {
            Ok(()) => {
                stages.fri_ok = true;
                Ok(build_report(prechecked.proof, stages, total_bytes, None))
            }
            Err(error) => Ok(build_report(
                prechecked.proof,
                stages,
                total_bytes,
                Some(error),
            )),
        },
        Err((proof, error)) => Ok(build_report(proof, stages, total_bytes, Some(error))),
    }
}

#[derive(Debug, Clone)]
pub(crate) struct PrecheckedProof {
    pub(crate) proof: Proof,
    pub(crate) fri_seed: [u8; 32],
    pub(crate) security_level: FriSecurityLevel,
}

#[allow(clippy::result_large_err)]
fn precheck_decoded_proof(
    proof: Proof,
    declared_kind: ConfigProofKind,
    public_inputs: &PublicInputs<'_>,
    config: &ProofSystemConfig,
    context: &VerifierContext,
    block_context: Option<&TranscriptBlockContext>,
    stages: &mut VerificationStages,
) -> Result<PrecheckedProof, (Proof, VerifyError)> {
    if let Err(error) = validate_header(
        &proof,
        declared_kind,
        public_inputs,
        config,
        context,
        stages,
    ) {
        return Err((proof, error));
    }
    match precheck_body(&proof, public_inputs, context, block_context, stages) {
        Ok(prechecked) => Ok(PrecheckedProof {
            proof,
            fri_seed: prechecked.fri_seed,
            security_level: prechecked.security_level,
        }),
        Err(error) => Err((proof, error)),
    }
}

#[allow(dead_code, clippy::result_large_err)]
pub(crate) fn precheck_proof_bytes(
    declared_kind: ConfigProofKind,
    public_inputs: &PublicInputs<'_>,
    proof_bytes: &ProofBytes,
    config: &ProofSystemConfig,
    context: &VerifierContext,
    block_context: Option<&TranscriptBlockContext>,
) -> Result<PrecheckedProof, VerifyError> {
    if (config.proof_version.0 as u16) != PROOF_VERSION {
        return Err(VerifyError::VersionMismatch {
            expected: PROOF_VERSION,
            actual: config.proof_version.0 as u16,
        });
    }
    if config.param_digest != context.param_digest {
        return Err(VerifyError::ParamsHashMismatch);
    }
    let proof = Proof::from_bytes(proof_bytes.as_slice())?;
    let mut stages = VerificationStages::default();
    precheck_decoded_proof(
        proof,
        declared_kind,
        public_inputs,
        config,
        context,
        block_context,
        &mut stages,
    )
    .map_err(|(_, err)| err)
}

pub(crate) fn execute_fri_stage(proof: &PrecheckedProof) -> Result<(), VerifyError> {
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
    stages: &mut VerificationStages,
) -> Result<(), VerifyError> {
    if proof.version != PROOF_VERSION {
        return Err(VerifyError::VersionMismatch {
            expected: PROOF_VERSION,
            actual: proof.version,
        });
    }

    let expected_kind = map_public_to_config_kind(public_inputs.kind());
    if proof.kind != expected_kind || proof.kind != declared_kind {
        return Err(VerifyError::UnknownProofKind(encode_proof_kind(proof.kind)));
    }

    if proof.param_digest != config.param_digest {
        return Err(VerifyError::ParamsHashMismatch);
    }
    if proof.param_digest != context.param_digest {
        return Err(VerifyError::ParamsHashMismatch);
    }

    let expected_public_inputs = serialize_public_inputs(public_inputs);
    if proof.public_inputs != expected_public_inputs {
        return Err(VerifyError::PublicInputMismatch);
    }
    stages.public_ok = true;

    let expected_air_spec = resolve_air_spec_id(&context.profile.air_spec_ids, proof.kind);
    if proof.air_spec_id != expected_air_spec {
        return Err(VerifyError::UnknownProofKind(encode_proof_kind(proof.kind)));
    }

    stages.params_ok = true;

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
    stages: &mut VerificationStages,
) -> Result<PrecheckedBody, VerifyError> {
    let payload = proof.serialize_payload();
    let expected_body_length = payload.len() as u32 + 32;
    if proof.telemetry.body_length != expected_body_length {
        return Err(VerifyError::BodyLengthMismatch {
            declared: proof.telemetry.body_length,
            actual: expected_body_length,
        });
    }

    let commitment_digest = compute_commitment_digest(
        &proof.merkle.core_root,
        &proof.merkle.aux_root,
        &proof.merkle.fri_layer_roots,
    );
    if proof.commitment_digest.bytes != commitment_digest {
        return Err(VerifyError::MerkleVerifyFailed {
            section: MerkleSection::CommitmentDigest,
        });
    }

    if proof
        .fri_proof
        .layer_roots
        .first()
        .copied()
        .unwrap_or([0u8; 32])
        != proof.merkle.core_root
    {
        return Err(VerifyError::MerkleVerifyFailed {
            section: MerkleSection::FriRoots,
        });
    }

    if proof.merkle.fri_layer_roots != proof.fri_proof.layer_roots {
        return Err(VerifyError::MerkleVerifyFailed {
            section: MerkleSection::FriRoots,
        });
    }

    stages.merkle_ok = true;

    let transcript_kind = proof.kind;
    let air_spec_id = resolve_air_spec_id(&context.profile.air_spec_ids, transcript_kind);
    let mut transcript = Transcript::new(TranscriptHeader {
        version: context.common_ids.transcript_version_id.clone(),
        poseidon_param_id: context.profile.poseidon_param_id.clone(),
        air_spec_id: air_spec_id.clone(),
        proof_kind: transcript_kind,
        param_digest: context.param_digest.clone(),
    })
    .map_err(|_| VerifyError::TranscriptOrder)?;

    let public_inputs_bytes = serialize_public_inputs(public_inputs);
    transcript
        .absorb_public_inputs(&public_inputs_bytes)
        .map_err(|_| VerifyError::TranscriptOrder)?;
    transcript
        .absorb_commitment_roots(proof.merkle.core_root, Some(proof.merkle.aux_root))
        .map_err(|_| VerifyError::TranscriptOrder)?;
    transcript
        .absorb_air_spec_id(air_spec_id)
        .map_err(|_| VerifyError::TranscriptOrder)?;
    transcript
        .absorb_block_context(block_context.cloned())
        .map_err(|_| VerifyError::TranscriptOrder)?;

    let mut challenges = transcript
        .finalize()
        .map_err(|_| VerifyError::TranscriptOrder)?;
    let alpha_vector = challenges
        .draw_alpha_vector(PROOF_ALPHA_VECTOR_LEN)
        .map_err(|_| VerifyError::TranscriptOrder)?;
    let ood_points = challenges
        .draw_ood_points(PROOF_MIN_OOD_POINTS)
        .map_err(|_| VerifyError::TranscriptOrder)?;
    let _ood_seed = challenges
        .draw_ood_seed()
        .map_err(|_| VerifyError::TranscriptOrder)?;

    verify_ood_openings(&proof.openings.out_of_domain, &ood_points, &alpha_vector)?;
    stages.composition_ok = true;

    let fri_seed = challenges
        .draw_fri_seed()
        .map_err(|_| VerifyError::TranscriptOrder)?;
    for (layer_index, _) in proof.merkle.fri_layer_roots.iter().enumerate() {
        challenges
            .draw_fri_eta(layer_index)
            .map_err(|_| VerifyError::TranscriptOrder)?;
    }
    challenges
        .draw_query_seed()
        .map_err(|_| VerifyError::TranscriptOrder)?;

    let security_level = map_security_level(&context.profile);
    if proof.fri_proof.security_level != security_level {
        return Err(VerifyError::FriVerifyFailed {
            issue: FriVerifyIssue::SecurityLevelMismatch,
        });
    }
    if proof.telemetry.fri_parameters.fold != 2
        || proof.telemetry.fri_parameters.query_budget as usize != security_level.query_budget()
    {
        return Err(VerifyError::InvalidFriSection("telemetry".to_string()));
    }

    if proof.telemetry.fri_parameters.cap_degree > PROOF_TELEMETRY_MAX_CAP_DEGREE
        || proof.telemetry.fri_parameters.cap_size > PROOF_TELEMETRY_MAX_CAP_SIZE
        || proof.telemetry.fri_parameters.query_budget > PROOF_TELEMETRY_MAX_QUERY_BUDGET
    {
        return Err(VerifyError::InvalidFriSection("telemetry".to_string()));
    }

    let header_bytes = proof.serialize_header(&payload);
    if proof.telemetry.header_length != header_bytes.len() as u32 {
        return Err(VerifyError::HeaderLengthMismatch {
            declared: proof.telemetry.header_length,
            actual: header_bytes.len() as u32,
        });
    }

    let integrity_digest = compute_integrity_digest(&header_bytes, &payload);
    if proof.telemetry.integrity_digest.bytes != integrity_digest {
        return Err(VerifyError::IntegrityDigestMismatch);
    }

    if proof_size_exceeds_limit(proof, context) {
        return Err(VerifyError::ProofTooLarge);
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
) -> Result<(), VerifyError> {
    if proof.fri_proof.layer_roots.len() > context.limits.max_layers as usize {
        return Err(VerifyError::FriVerifyFailed {
            issue: FriVerifyIssue::LayerBudgetExceeded,
        });
    }

    if proof.fri_proof.layer_roots.len() > PROOF_MAX_FRI_LAYERS {
        return Err(VerifyError::FriVerifyFailed {
            issue: FriVerifyIssue::LayerBudgetExceeded,
        });
    }

    if proof.fri_proof.queries.len() > context.limits.max_queries as usize {
        return Err(VerifyError::FriVerifyFailed {
            issue: FriVerifyIssue::QueryOutOfRange,
        });
    }

    if proof.fri_proof.queries.len() > PROOF_MAX_QUERY_COUNT {
        return Err(VerifyError::FriVerifyFailed {
            issue: FriVerifyIssue::QueryOutOfRange,
        });
    }

    enforce_trace_limits(proof_kind, public_inputs, context)
}

fn enforce_trace_limits(
    proof_kind: ConfigProofKind,
    public_inputs: &PublicInputs<'_>,
    context: &VerifierContext,
) -> Result<(), VerifyError> {
    let width_limit = *context.limits.per_proof_max_trace_width.get(proof_kind) as u32;
    let step_limit = *context.limits.per_proof_max_trace_steps.get(proof_kind);

    if let PublicInputs::Execution { header, .. } = public_inputs {
        if header.trace_width > width_limit {
            return Err(VerifyError::DegreeBoundExceeded);
        }
        if header.trace_length > step_limit {
            return Err(VerifyError::DegreeBoundExceeded);
        }
    }

    Ok(())
}

fn verify_ood_openings(
    openings: &[OutOfDomainOpening],
    points: &[[u8; 32]],
    alphas: &[[u8; 32]],
) -> Result<(), VerifyError> {
    if openings.len() != points.len() {
        return Err(VerifyError::OutOfDomainInvalid);
    }

    for (index, (opening, point)) in openings.iter().zip(points.iter()).enumerate() {
        let expected_core = hash_ood_value(b"RPP-OOD/CORE", point, alphas, index);
        if opening.core_values.len() != 1 || opening.core_values[0] != expected_core {
            return Err(VerifyError::OutOfDomainInvalid);
        }
        if !opening.aux_values.is_empty() {
            return Err(VerifyError::OutOfDomainInvalid);
        }
        let expected_comp = hash_ood_value(b"RPP-OOD/COMP", point, alphas, index);
        if opening.composition_value != expected_comp {
            return Err(VerifyError::OutOfDomainInvalid);
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

fn build_report(
    proof: Proof,
    stages: VerificationStages,
    total_bytes: u64,
    error: Option<VerifyError>,
) -> VerifyReport {
    VerifyReport {
        proof,
        params_ok: stages.params_ok,
        public_ok: stages.public_ok,
        merkle_ok: stages.merkle_ok,
        fri_ok: stages.fri_ok,
        composition_ok: stages.composition_ok,
        total_bytes,
        error,
    }
}

fn map_fri_error(error: FriError) -> VerifyError {
    match error {
        FriError::EmptyCodeword => VerifyError::FriVerifyFailed {
            issue: FriVerifyIssue::EmptyCodeword,
        },
        FriError::VersionMismatch { .. } => VerifyError::FriVerifyFailed {
            issue: FriVerifyIssue::VersionMismatch,
        },
        FriError::QueryOutOfRange { .. } => VerifyError::FriVerifyFailed {
            issue: FriVerifyIssue::QueryOutOfRange,
        },
        FriError::PathInvalid { .. } => VerifyError::MerkleVerifyFailed {
            section: MerkleSection::FriPath,
        },
        FriError::LayerRootMismatch { .. } => VerifyError::FriVerifyFailed {
            issue: FriVerifyIssue::LayerMismatch,
        },
        FriError::SecurityLevelMismatch => VerifyError::FriVerifyFailed {
            issue: FriVerifyIssue::SecurityLevelMismatch,
        },
        FriError::QueryBudgetMismatch { .. } => VerifyError::FriVerifyFailed {
            issue: FriVerifyIssue::QueryBudgetMismatch,
        },
        FriError::FoldingConstraintViolated { .. } => VerifyError::FriVerifyFailed {
            issue: FriVerifyIssue::FoldingConstraint,
        },
        FriError::OodsInvalid => VerifyError::FriVerifyFailed {
            issue: FriVerifyIssue::OodsInvalid,
        },
        FriError::Serialization(_) => VerifyError::MerkleVerifyFailed {
            section: MerkleSection::FriPath,
        },
        FriError::InvalidStructure(_) => VerifyError::MerkleVerifyFailed {
            section: MerkleSection::FriPath,
        },
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
