use rpp_stark::config::{
    compute_param_digest, CommonIdentifiers, ParamDigest, ProfileConfig,
    ProofKind as ConfigProofKind, ProofSystemConfig, ResourceLimits, VerifierContext,
    COMMON_IDENTIFIERS, PROFILE_STANDARD_CONFIG, PROOF_VERSION_V1,
};
use rpp_stark::field::FieldElement;
use rpp_stark::hash::Hasher;
use rpp_stark::proof::envelope::{
    compute_commitment_digest, compute_integrity_digest, serialize_public_inputs,
};
use rpp_stark::proof::errors::VerificationFailure;
use rpp_stark::proof::public_inputs::{ExecutionHeaderV1, PublicInputVersion, PublicInputs};
use rpp_stark::proof::transcript::{Transcript, TranscriptBlockContext, TranscriptHeader};
use rpp_stark::proof::types::{
    FriParametersMirror, MerkleProofBundle, Openings, OutOfDomainOpening, Proof, Telemetry,
    PROOF_ALPHA_VECTOR_LEN, PROOF_MIN_OOD_POINTS, PROOF_VERSION,
};
use rpp_stark::proof::verifier::verify_proof_bytes;
use rpp_stark::utils::serialization::{DigestBytes, ProofBytes};

use rpp_stark::fri::{FriProof, FriQueryLayerProof, FriQueryProof, FriSecurityLevel};
use rpp_stark::hash::merkle::{MerkleIndex, MerklePathElement};

#[test]
fn proof_size_limit_is_enforced() {
    let (config, context, inputs) = test_environment(|limits| {
        limits.max_proof_size_bytes = 64;
    });

    let proof_bytes = build_envelope(&config, &context, &inputs, 1, 1, 4);
    let public_inputs = inputs.as_public_inputs();

    let err = verify_proof_bytes(
        ConfigProofKind::Tx,
        &public_inputs,
        &proof_bytes,
        &config,
        &context,
    )
    .unwrap_err();

    assert_eq!(err, VerificationFailure::ErrProofTooLarge);
}

#[test]
fn fri_layer_overflow_is_rejected() {
    let (config, context, inputs) = test_environment(|limits| {
        limits.max_layers = 2;
    });

    let proof_bytes = build_envelope(&config, &context, &inputs, 3, 1, 4);
    let public_inputs = inputs.as_public_inputs();

    let err = verify_proof_bytes(
        ConfigProofKind::Tx,
        &public_inputs,
        &proof_bytes,
        &config,
        &context,
    )
    .unwrap_err();

    assert_eq!(err, VerificationFailure::ErrFRILayerRootMismatch);
}

#[test]
fn fri_query_budget_limit_is_enforced() {
    let (config, context, inputs) = test_environment(|limits| {
        limits.max_queries = 1;
    });

    let proof_bytes = build_envelope(&config, &context, &inputs, 1, 3, 4);
    let public_inputs = inputs.as_public_inputs();

    let err = verify_proof_bytes(
        ConfigProofKind::Tx,
        &public_inputs,
        &proof_bytes,
        &config,
        &context,
    )
    .unwrap_err();

    assert_eq!(err, VerificationFailure::ErrFRIQueryOutOfRange);
}

#[test]
fn trace_degree_bound_is_enforced() {
    let (_config, mut context, mut inputs) = test_environment(|limits| {
        limits.per_proof_max_trace_steps.tx = 8;
        limits.per_proof_max_trace_width.tx = 2;
    });

    inputs.header.trace_length = 16;
    inputs.header.trace_width = 4;

    // Recompute digests because the public inputs changed.
    let param_digest = recompute_digest(&context.profile, &context.common_ids);
    context.param_digest = param_digest.clone();
    context.profile = context.profile.clone();
    context.limits = context.profile.limits.clone();
    let config = ProofSystemConfig {
        proof_version: PROOF_VERSION_V1,
        profile: context.profile.clone(),
        param_digest: param_digest.clone(),
    };

    let proof_bytes = build_envelope(&config, &context, &inputs, 1, 1, 4);
    let public_inputs = inputs.as_public_inputs();

    let err = verify_proof_bytes(
        ConfigProofKind::Tx,
        &public_inputs,
        &proof_bytes,
        &config,
        &context,
    )
    .unwrap_err();

    assert_eq!(err, VerificationFailure::ErrDegreeBoundExceeded);
}

struct OwnedExecutionInputs {
    header: ExecutionHeaderV1,
    body: Vec<u8>,
}

impl OwnedExecutionInputs {
    fn new(trace_length: u32, trace_width: u32) -> Self {
        Self {
            header: ExecutionHeaderV1 {
                version: PublicInputVersion::V1,
                program_digest: DigestBytes { bytes: [0u8; 32] },
                trace_length,
                trace_width,
            },
            body: Vec::new(),
        }
    }

    fn as_public_inputs(&self) -> PublicInputs<'_> {
        PublicInputs::Execution {
            header: self.header.clone(),
            body: &self.body,
        }
    }
}

fn test_environment<F>(
    mut update_limits: F,
) -> (ProofSystemConfig, VerifierContext, OwnedExecutionInputs)
where
    F: FnMut(&mut ResourceLimits),
{
    let mut profile = PROFILE_STANDARD_CONFIG.clone();
    update_limits(&mut profile.limits);
    let common = COMMON_IDENTIFIERS.clone();
    let param_digest = recompute_digest(&profile, &common);

    let config = ProofSystemConfig {
        proof_version: PROOF_VERSION_V1,
        profile: profile.clone(),
        param_digest: param_digest.clone(),
    };

    let context = VerifierContext {
        profile: profile.clone(),
        param_digest,
        common_ids: common.clone(),
        limits: profile.limits.clone(),
        metrics: None,
    };

    (config, context, OwnedExecutionInputs::new(8, 4))
}

fn recompute_digest(profile: &ProfileConfig, common: &CommonIdentifiers) -> ParamDigest {
    compute_param_digest(profile, common)
}

fn build_envelope(
    config: &ProofSystemConfig,
    context: &VerifierContext,
    inputs: &OwnedExecutionInputs,
    layer_count: usize,
    query_count: usize,
    final_poly_len: usize,
) -> ProofBytes {
    let public_inputs = inputs.as_public_inputs();
    let public_inputs_bytes = serialize_public_inputs(&public_inputs);

    let proof_kind = ConfigProofKind::Tx;
    let air_spec_id = config.profile.air_spec_ids.tx.clone();

    let fri_layer_roots: Vec<[u8; 32]> = (0..layer_count)
        .map(|idx| {
            let mut root = [0u8; 32];
            root[0] = (idx + 1) as u8;
            root
        })
        .collect();
    let core_root = fri_layer_roots.first().copied().unwrap_or([0u8; 32]);
    let aux_root = [0x22; 32];
    let commitment_digest = compute_commitment_digest(&core_root, &aux_root, &fri_layer_roots);

    let security_level = match context.profile.fri_queries {
        96 => FriSecurityLevel::HiSec,
        48 => FriSecurityLevel::Throughput,
        _ => FriSecurityLevel::Standard,
    };

    let final_polynomial = vec![FieldElement::ZERO; final_poly_len];
    let queries = build_queries(layer_count, query_count);
    let fold_challenges = vec![FieldElement::ZERO; fri_layer_roots.len()];

    let fri_proof = FriProof::new(
        security_level,
        1024,
        fri_layer_roots.clone(),
        fold_challenges,
        final_polynomial,
        [0x33; 32],
        queries,
    )
    .expect("synthetic fri proof");

    let ood_openings =
        build_ood_openings(context, proof_kind, &public_inputs, &core_root, &aux_root);

    let merkle = MerkleProofBundle {
        core_root,
        aux_root,
        fri_layer_roots,
    };

    let telemetry = Telemetry {
        header_length: 0,
        body_length: 0,
        fri_parameters: FriParametersMirror {
            fold: 2,
            cap_degree: context.profile.fri_depth_range.max as u16,
            cap_size: final_poly_len as u32,
            query_budget: security_level.query_budget() as u16,
        },
        integrity_digest: DigestBytes::default(),
    };

    let mut proof = Proof {
        version: PROOF_VERSION,
        kind: proof_kind,
        param_digest: config.param_digest.clone(),
        air_spec_id: air_spec_id.clone(),
        public_inputs: public_inputs_bytes.clone(),
        commitment_digest: DigestBytes {
            bytes: commitment_digest,
        },
        merkle,
        openings: Openings {
            out_of_domain: ood_openings,
        },
        fri_proof,
        telemetry,
    };

    let payload = proof.serialize_payload();
    let header_bytes = proof.serialize_header(&payload);
    proof.telemetry.body_length = (payload.len() + 32) as u32;
    proof.telemetry.header_length = header_bytes.len() as u32;
    let integrity = compute_integrity_digest(&header_bytes, &payload);
    proof.telemetry.integrity_digest = DigestBytes { bytes: integrity };

    ProofBytes::new(proof.to_bytes())
}

fn build_queries(layer_count: usize, query_count: usize) -> Vec<FriQueryProof> {
    (0..query_count)
        .map(|idx| FriQueryProof {
            position: idx,
            layers: (0..layer_count)
                .map(|_| FriQueryLayerProof {
                    value: FieldElement::ZERO,
                    path: vec![MerklePathElement {
                        index: MerkleIndex(0),
                        siblings: [[0u8; 32]; 1],
                    }],
                })
                .collect(),
            final_value: FieldElement::ZERO,
        })
        .collect()
}

fn build_ood_openings(
    context: &VerifierContext,
    proof_kind: ConfigProofKind,
    public_inputs: &PublicInputs<'_>,
    core_root: &[u8; 32],
    aux_root: &[u8; 32],
) -> Vec<OutOfDomainOpening> {
    let air_spec_id = context.profile.air_spec_ids.tx.clone();
    let mut transcript = Transcript::new(TranscriptHeader {
        version: context.common_ids.transcript_version_id.clone(),
        poseidon_param_id: context.profile.poseidon_param_id.clone(),
        air_spec_id,
        proof_kind,
        param_digest: context.param_digest.clone(),
    })
    .expect("transcript");

    let public_bytes = serialize_public_inputs(public_inputs);
    transcript
        .absorb_public_inputs(&public_bytes)
        .expect("public inputs");
    transcript
        .absorb_commitment_roots(*core_root, Some(*aux_root))
        .expect("commitments");
    transcript
        .absorb_air_spec_id(context.profile.air_spec_ids.tx.clone())
        .expect("air spec id");
    transcript
        .absorb_block_context(None::<TranscriptBlockContext>)
        .expect("block ctx");

    let mut challenges = transcript.finalize().expect("finalize");
    let alphas = challenges
        .draw_alpha_vector(PROOF_ALPHA_VECTOR_LEN)
        .expect("alpha vector");
    let points = challenges
        .draw_ood_points(PROOF_MIN_OOD_POINTS)
        .expect("ood points");
    let _ = challenges.draw_ood_seed().expect("ood seed");

    points
        .iter()
        .enumerate()
        .map(|(index, point)| OutOfDomainOpening {
            point: *point,
            core_values: vec![hash_ood_value(b"RPP-OOD/CORE", point, &alphas, index)],
            aux_values: Vec::new(),
            composition_value: hash_ood_value(b"RPP-OOD/COMP", point, &alphas, index),
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
