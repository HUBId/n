//! Deterministic verifier implementation.
//!
//! The verifier mirrors the prover pipeline by replaying the transcript,
//! recomputing the Fiat–Shamir challenges and validating the FRI proof.  All
//! structural checks (length prefixes, digests and bounds) are performed before
//! any expensive cryptographic operation.

use crate::config::{
    ProofKind as ConfigProofKind, ProofKindLayout, ProofSystemConfig, VerifierContext,
    MERKLE_SCHEME_ID_BLAKE3_2ARY_V1,
};
use crate::field::prime_field::CanonicalSerialize;
use crate::field::FieldElement;
use crate::fri::types::{FriError, FriSecurityLevel};
use crate::fri::FriVerifier;
use crate::merkle::traits::MerkleHasher;
use crate::merkle::verify_proof as verify_merkle_proof;
use crate::merkle::{
    DeterministicMerkleHasher, Digest as MerkleDigest, Leaf, MerkleProof, ProofNode,
};
use crate::proof::params::canonical_stark_params;
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
use core::convert::TryInto;

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
    match precheck_body(
        &proof,
        public_inputs,
        config,
        context,
        block_context,
        stages,
    ) {
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
    config: &ProofSystemConfig,
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
    let _alpha_vector = challenges
        .draw_alpha_vector(PROOF_ALPHA_VECTOR_LEN)
        .map_err(|_| VerifyError::TranscriptOrder)?;
    let _ood_points = challenges
        .draw_ood_points(PROOF_MIN_OOD_POINTS)
        .map_err(|_| VerifyError::TranscriptOrder)?;
    let _ood_seed = challenges
        .draw_ood_seed()
        .map_err(|_| VerifyError::TranscriptOrder)?;

    ensure_merkle_scheme(config, context)?;
    let stark_params = canonical_stark_params();

    let trace_values = verify_trace_commitment(
        &stark_params,
        &proof.merkle.core_root,
        &proof.openings.trace,
    )?;

    let composition_openings = proof
        .openings
        .composition
        .as_ref()
        .ok_or(VerifyError::EmptyOpenings)?;
    let composition_values =
        verify_composition_commitment(&stark_params, &proof.merkle.aux_root, composition_openings)?;

    verify_composition_alignment(
        &composition_values,
        &proof.openings.trace.indices,
        &proof.fri_proof,
    )?;

    verify_ood_openings(
        &proof.openings.out_of_domain,
        &trace_values,
        &composition_values,
    )?;
    stages.composition_ok = true;

    let fri_seed = challenges
        .draw_fri_seed()
        .map_err(|_| VerifyError::TranscriptOrder)?;
    for (layer_index, _) in proof.merkle.fri_layer_roots.iter().enumerate() {
        challenges
            .draw_fri_eta(layer_index)
            .map_err(|_| VerifyError::TranscriptOrder)?;
    }
    let _ = challenges
        .draw_query_seed()
        .map_err(|_| VerifyError::TranscriptOrder)?;

    let security_level = map_security_level(&context.profile);
    validate_trace_indices(&proof.openings.trace.indices, &proof.fri_proof)?;
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

fn validate_trace_indices(
    provided: &[u32],
    fri_proof: &crate::fri::FriProof,
) -> Result<(), VerifyError> {
    let mut previous: Option<u32> = None;
    for &value in provided {
        if let Some(prev) = previous {
            if value < prev {
                return Err(VerifyError::IndicesNotSorted);
            }
            if value == prev {
                return Err(VerifyError::IndicesDuplicate);
            }
        }
        previous = Some(value);
    }

    if fri_proof.queries.len() != provided.len() {
        return Err(VerifyError::IndicesMismatch);
    }

    for (&expected, query) in provided.iter().zip(fri_proof.queries.iter()) {
        let actual: u32 = query
            .position
            .try_into()
            .map_err(|_| VerifyError::IndicesMismatch)?;
        if expected != actual {
            return Err(VerifyError::IndicesMismatch);
        }
    }

    Ok(())
}

fn ensure_merkle_scheme(
    config: &ProofSystemConfig,
    context: &VerifierContext,
) -> Result<(), VerifyError> {
    if config.profile.merkle_scheme_id != MERKLE_SCHEME_ID_BLAKE3_2ARY_V1
        || context.common_ids.merkle_scheme_id != MERKLE_SCHEME_ID_BLAKE3_2ARY_V1
    {
        return Err(VerifyError::UnsupportedMerkleScheme);
    }

    Ok(())
}

#[derive(Clone, Copy)]
enum LeafSource {
    Trace,
    Composition,
}

fn verify_trace_commitment(
    params: &crate::params::StarkParams,
    root: &[u8; 32],
    openings: &crate::proof::types::TraceOpenings,
) -> Result<Vec<FieldElement>, VerifyError> {
    verify_merkle_section(
        params,
        root,
        &openings.indices,
        &openings.leaves,
        &openings.paths,
        MerkleSection::TraceCommit,
        LeafSource::Trace,
    )
}

fn verify_composition_commitment(
    params: &crate::params::StarkParams,
    root: &[u8; 32],
    openings: &crate::proof::types::CompositionOpenings,
) -> Result<Vec<FieldElement>, VerifyError> {
    verify_merkle_section(
        params,
        root,
        &openings.indices,
        &openings.leaves,
        &openings.paths,
        MerkleSection::CompositionCommit,
        LeafSource::Composition,
    )
}

fn verify_merkle_section(
    params: &crate::params::StarkParams,
    root: &[u8; 32],
    indices: &[u32],
    leaves: &[Vec<u8>],
    paths: &[crate::proof::types::MerkleAuthenticationPath],
    section: MerkleSection,
    source: LeafSource,
) -> Result<Vec<FieldElement>, VerifyError> {
    if indices.len() != leaves.len() || indices.len() != paths.len() || indices.is_empty() {
        return Err(VerifyError::EmptyOpenings);
    }

    if params.merkle().arity != crate::params::MerkleArity::Binary {
        return Err(VerifyError::UnsupportedMerkleScheme);
    }

    if params.merkle().leaf_width != 1 {
        return Err(VerifyError::UnsupportedMerkleScheme);
    }

    let element_size = FieldElement::ZERO.to_bytes().len();
    let expected_leaf_bytes = element_size * params.merkle().leaf_width as usize;
    let root_digest = MerkleDigest::new(root.to_vec());
    let mut values = Vec::with_capacity(indices.len());

    for ((&index, leaf_bytes), path) in indices.iter().zip(leaves.iter()).zip(paths.iter()) {
        if leaf_bytes.len() != expected_leaf_bytes {
            return Err(match source {
                LeafSource::Trace => VerifyError::TraceLeafMismatch,
                LeafSource::Composition => VerifyError::CompositionLeafMismatch,
            });
        }

        let proof = MerkleProof {
            version: 1,
            arity: crate::params::MerkleArity::Binary,
            leaf_encoding: params.merkle().leaf_encoding,
            path: convert_path(path, section)?,
            indices: vec![index],
            leaf_width: params.merkle().leaf_width,
            domain_sep: params.merkle().domain_sep,
            leaf_width_bytes: leaf_bytes.len() as u32,
            digest_size: DeterministicMerkleHasher::digest_size() as u16,
        };

        let leaf = Leaf::new(leaf_bytes.clone());
        let leaves_array = [leaf];
        verify_merkle_proof::<DeterministicMerkleHasher>(
            params,
            &root_digest,
            &proof,
            &leaves_array,
        )
        .map_err(|_| VerifyError::MerkleVerifyFailed { section })?;

        let mut field_bytes = [0u8; 8];
        field_bytes.copy_from_slice(&leaf_bytes[..element_size]);
        let value = FieldElement::from_bytes(&field_bytes)
            .map_err(|_| VerifyError::NonCanonicalFieldElement)?;
        values.push(value);
    }

    Ok(values)
}

fn convert_path(
    path: &crate::proof::types::MerkleAuthenticationPath,
    section: MerkleSection,
) -> Result<Vec<ProofNode>, VerifyError> {
    if path.nodes.is_empty() {
        return Err(VerifyError::MerkleVerifyFailed { section });
    }
    let mut nodes = Vec::with_capacity(path.nodes.len());
    for node in &path.nodes {
        nodes.push(ProofNode::Arity2([MerkleDigest::new(
            node.sibling.to_vec(),
        )]));
    }
    Ok(nodes)
}

fn verify_composition_alignment(
    composition_values: &[FieldElement],
    indices: &[u32],
    fri_proof: &crate::fri::FriProof,
) -> Result<(), VerifyError> {
    if composition_values.len() != fri_proof.queries.len()
        || indices.len() != fri_proof.queries.len()
    {
        return Err(VerifyError::CompositionLeafMismatch);
    }

    for ((value, &index), query) in composition_values
        .iter()
        .zip(indices.iter())
        .zip(fri_proof.queries.iter())
    {
        if query.position != index as usize {
            return Err(VerifyError::CompositionLeafMismatch);
        }
        let first_layer = query
            .layers
            .first()
            .ok_or(VerifyError::CompositionLeafMismatch)?;
        if *value != first_layer.value {
            return Err(VerifyError::CompositionLeafMismatch);
        }
    }

    Ok(())
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
    trace_values: &[FieldElement],
    composition_values: &[FieldElement],
) -> Result<(), VerifyError> {
    if openings.is_empty() {
        return Err(VerifyError::OutOfDomainInvalid);
    }
    if trace_values.is_empty() || composition_values.is_empty() {
        return Err(VerifyError::OutOfDomainInvalid);
    }

    let trace_len = trace_values.len();
    let comp_len = composition_values.len();
    for opening in openings {
        if opening.core_values.len() != 1 {
            return Err(VerifyError::OutOfDomainInvalid);
        }
        if !opening.aux_values.is_empty() {
            return Err(VerifyError::OutOfDomainInvalid);
        }

        let comp_index = (opening.point[0] as usize) % comp_len;
        let expected_comp = composition_values[comp_index];
        let observed_comp = field_from_fixed_bytes(&opening.composition_value)?;
        if observed_comp != expected_comp {
            return Err(VerifyError::CompositionOodMismatch);
        }

        let trace_index = comp_index % trace_len;
        let expected_trace = trace_values[trace_index];
        let observed_trace = field_from_fixed_bytes(
            opening
                .core_values
                .first()
                .ok_or(VerifyError::OutOfDomainInvalid)?,
        )?;
        if observed_trace != expected_trace {
            return Err(VerifyError::TraceOodMismatch);
        }
    }

    Ok(())
}

fn field_from_fixed_bytes(bytes: &[u8; 32]) -> Result<FieldElement, VerifyError> {
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[..8]);
    FieldElement::from_bytes(&buf).map_err(|_| VerifyError::NonCanonicalFieldElement)
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
