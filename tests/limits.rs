use core::convert::TryInto;
use rpp_stark::config::{
    compute_param_digest, CommonIdentifiers, ParamDigest, ProfileConfig,
    ProofKind as ConfigProofKind, ProofSystemConfig, ResourceLimits, VerifierContext,
    COMMON_IDENTIFIERS, PROFILE_STANDARD_CONFIG, PROOF_VERSION_V1,
};
use rpp_stark::field::prime_field::CanonicalSerialize;
use rpp_stark::field::FieldElement;
use rpp_stark::hash::{hash, Blake2sXof, FiatShamirChallengeRules};
use rpp_stark::merkle::{
    CommitAux, DeterministicMerkleHasher, Leaf, MerkleArityExt, MerkleCommit, MerkleProof,
    MerkleTree, ProofNode,
};
use rpp_stark::proof::envelope::{
    compute_integrity_digest, compute_public_digest, serialize_public_inputs,
};
use rpp_stark::proof::params::canonical_stark_params;
use rpp_stark::proof::public_inputs::{ExecutionHeaderV1, PublicInputVersion, PublicInputs};
use rpp_stark::proof::transcript::{Transcript, TranscriptBlockContext, TranscriptHeader};
use rpp_stark::proof::types::{
    CompositionBinding, CompositionOpenings, FriHandle, FriParametersMirror, FriVerifyIssue,
    MerkleAuthenticationPath, MerklePathNode, MerkleProofBundle, Openings, OpeningsDescriptor,
    OutOfDomainOpening, Proof, Telemetry, TelemetryOption, TraceOpenings, VerifyError,
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

    let report = verify_proof_bytes(
        ConfigProofKind::Tx,
        &public_inputs,
        &proof_bytes,
        &config,
        &context,
    )
    .expect("verify report");

    assert!(matches!(
        report.error,
        Some(VerifyError::ProofTooLarge { .. })
    ));
}

#[test]
fn fri_layer_overflow_is_rejected() {
    let (config, context, inputs) = test_environment(|limits| {
        limits.max_layers = 2;
    });

    let proof_bytes = build_envelope(&config, &context, &inputs, 3, 1, 4);
    let public_inputs = inputs.as_public_inputs();

    let report = verify_proof_bytes(
        ConfigProofKind::Tx,
        &public_inputs,
        &proof_bytes,
        &config,
        &context,
    )
    .expect("verify report");

    assert_eq!(
        report.error,
        Some(VerifyError::FriVerifyFailed {
            issue: FriVerifyIssue::LayerBudgetExceeded,
        })
    );
}

#[test]
fn fri_query_budget_limit_is_enforced() {
    let (config, context, inputs) = test_environment(|limits| {
        limits.max_queries = 1;
    });

    let proof_bytes = build_envelope(&config, &context, &inputs, 1, 3, 4);
    let public_inputs = inputs.as_public_inputs();

    let report = verify_proof_bytes(
        ConfigProofKind::Tx,
        &public_inputs,
        &proof_bytes,
        &config,
        &context,
    )
    .expect("verify report");

    assert_eq!(
        report.error,
        Some(VerifyError::FriVerifyFailed {
            issue: FriVerifyIssue::QueryOutOfRange,
        })
    );
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

    let report = verify_proof_bytes(
        ConfigProofKind::Tx,
        &public_inputs,
        &proof_bytes,
        &config,
        &context,
    )
    .expect("verify report");

    assert_eq!(report.error, Some(VerifyError::DegreeBoundExceeded));
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
    _query_count: usize,
    final_poly_len: usize,
) -> ProofBytes {
    let public_inputs = inputs.as_public_inputs();
    let public_inputs_bytes =
        serialize_public_inputs(&public_inputs).expect("public inputs serialization");
    let public_digest = compute_public_digest(&public_inputs_bytes);

    let proof_kind = ConfigProofKind::Tx;
    let air_spec_id = config.profile.air_spec_ids.tx.clone();

    let fri_layer_roots: Vec<[u8; 32]> = (0..layer_count)
        .map(|idx| {
            let mut root = [0u8; 32];
            root[0] = (idx + 1) as u8;
            root
        })
        .collect();

    let security_level = match context.profile.fri_queries {
        96 => FriSecurityLevel::HiSec,
        48 => FriSecurityLevel::Throughput,
        _ => FriSecurityLevel::Standard,
    };

    let initial_domain_size = 1024;
    let final_polynomial = vec![FieldElement::ZERO; final_poly_len];
    let fold_challenges = vec![FieldElement::ZERO; fri_layer_roots.len()];

    let params = canonical_stark_params(&context.profile);
    let leaf_count = initial_domain_size.max(1);
    let zero_leaf = FieldElement::ZERO
        .to_bytes()
        .expect("zero is a canonical field element");
    let trace_leaves: Vec<Leaf> = (0..leaf_count)
        .map(|_| Leaf::new(zero_leaf.to_vec()))
        .collect();
    let (core_digest, core_aux) = <MerkleTree<DeterministicMerkleHasher> as MerkleCommit>::commit(
        &params,
        trace_leaves.clone().into_iter(),
    )
    .expect("trace commitment");

    let mut fri_roots = fri_layer_roots.clone();
    if fri_roots.is_empty() {
        fri_roots.push(digest_to_array(core_digest.as_bytes()));
    }

    let composition_leaves = trace_leaves.clone();
    let (aux_digest, aux_aux) = <MerkleTree<DeterministicMerkleHasher> as MerkleCommit>::commit(
        &params,
        composition_leaves.clone().into_iter(),
    )
    .expect("composition commitment");

    let core_root = digest_to_array(core_digest.as_bytes());
    let aux_root = digest_to_array(aux_digest.as_bytes());

    let (ood_openings, fri_seed) = build_ood_openings(
        context,
        proof_kind,
        &public_inputs,
        &core_root,
        &aux_root,
        &fri_layer_roots,
    );
    let final_polynomial_digest = hash_final_layer(&final_polynomial);
    let fri_query_seed =
        derive_fri_query_seed(fri_seed, &fri_layer_roots, &final_polynomial_digest);
    let trace_indices = derive_query_indices(
        fri_query_seed,
        security_level.query_budget(),
        initial_domain_size,
    );
    let queries = build_queries(layer_count, &trace_indices);
    let fri_proof = FriProof::new(
        security_level,
        initial_domain_size,
        fri_layer_roots.clone(),
        fold_challenges,
        final_polynomial,
        final_polynomial_digest,
        queries,
    )
    .expect("synthetic fri proof");

    let (trace_leaf_bytes, trace_paths) =
        build_opening_artifacts(&params, &core_aux, &trace_leaves, &trace_indices);
    let trace_openings = TraceOpenings {
        indices: trace_indices.clone(),
        leaves: trace_leaf_bytes,
        paths: trace_paths,
    };

    let (comp_leaf_bytes, comp_paths) =
        build_opening_artifacts(&params, &aux_aux, &composition_leaves, &trace_indices);
    let composition_openings = CompositionOpenings {
        indices: trace_indices.clone(),
        leaves: comp_leaf_bytes,
        paths: comp_paths,
    };

    let merkle = MerkleProofBundle {
        core_root,
        aux_root,
        fri_layer_roots: fri_roots,
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

    let public_digest = DigestBytes {
        bytes: public_digest,
    };
    let trace_commit = DigestBytes {
        bytes: merkle.core_root,
    };
    let composition_commit = Some(DigestBytes {
        bytes: merkle.aux_root,
    });
    let openings = Openings {
        trace: trace_openings,
        composition: Some(composition_openings),
        out_of_domain: ood_openings,
    };
    let binding = CompositionBinding::new(
        proof_kind,
        air_spec_id.clone(),
        public_inputs_bytes.clone(),
        composition_commit,
    );
    let openings_descriptor = OpeningsDescriptor::new(merkle, openings);
    let fri_handle = FriHandle::new(fri_proof);
    let telemetry_option = TelemetryOption::new(true, telemetry);

    let mut proof = Proof::from_parts(
        PROOF_VERSION,
        config.param_digest.clone(),
        public_digest,
        trace_commit,
        binding,
        openings_descriptor,
        fri_handle,
        telemetry_option,
    );

    let payload = proof
        .serialize_payload()
        .expect("proof payload serialization");
    let header_bytes = proof
        .serialize_header(&payload)
        .expect("proof header serialization");
    let telemetry = proof.telemetry_mut();
    telemetry.set_body_length((payload.len() + 32) as u32);
    telemetry.set_header_length(header_bytes.len() as u32);
    let integrity = compute_integrity_digest(&header_bytes, &payload);
    telemetry.set_integrity_digest(DigestBytes { bytes: integrity });

    ProofBytes::new(proof.to_bytes().expect("serialize proof"))
}

fn build_queries(layer_count: usize, indices: &[u32]) -> Vec<FriQueryProof> {
    indices
        .iter()
        .map(|&index| FriQueryProof {
            position: index as usize,
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
    layer_roots: &[[u8; 32]],
) -> (Vec<OutOfDomainOpening>, [u8; 32]) {
    let air_spec_id = context.profile.air_spec_ids.tx.clone();
    let mut transcript = Transcript::new(TranscriptHeader {
        version: context.common_ids.transcript_version_id.clone(),
        poseidon_param_id: context.profile.poseidon_param_id.clone(),
        air_spec_id,
        proof_kind,
        params_hash: context.param_digest.clone(),
    })
    .expect("transcript");

    let public_bytes = serialize_public_inputs(public_inputs).expect("public inputs serialization");
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
    let _alphas = challenges
        .draw_alpha_vector(PROOF_ALPHA_VECTOR_LEN)
        .expect("alpha vector");
    let points = challenges
        .draw_ood_points(PROOF_MIN_OOD_POINTS)
        .expect("ood points");
    let _ = challenges.draw_ood_seed().expect("ood seed");

    let zero_value = field_to_bytes(FieldElement::ZERO);
    let ood_values: Vec<OutOfDomainOpening> = points
        .iter()
        .map(|point| OutOfDomainOpening {
            point: *point,
            core_values: vec![zero_value],
            aux_values: Vec::new(),
            composition_value: zero_value,
        })
        .collect();

    let fri_seed = challenges.draw_fri_seed().expect("fri seed");
    for (layer_index, _) in layer_roots.iter().enumerate() {
        challenges
            .draw_fri_eta(layer_index)
            .expect("fri eta challenge");
    }

    (ood_values, fri_seed)
}

fn derive_query_indices(seed: [u8; 32], count: usize, domain_size: usize) -> Vec<u32> {
    if domain_size == 0 {
        return Vec::new();
    }
    let mut xof = Blake2sXof::new(&seed);
    let target = count.min(domain_size);
    let mut unique = Vec::with_capacity(target);
    let mut seen = vec![false; domain_size];
    while unique.len() < target {
        let word = xof
            .next_u64()
            .expect("deterministic query sampling must succeed");
        let position = (word % (domain_size as u64)) as usize;
        if !seen[position] {
            seen[position] = true;
            unique.push(position);
        }
    }
    unique.sort();
    unique
        .into_iter()
        .map(|idx| idx.try_into().unwrap_or(u32::MAX))
        .collect()
}

fn derive_fri_query_seed(
    fri_seed: [u8; 32],
    layer_roots: &[[u8; 32]],
    final_polynomial_digest: &[u8; 32],
) -> [u8; 32] {
    let mut state = fri_seed;

    for (layer_index, root) in layer_roots.iter().enumerate() {
        let mut payload = Vec::with_capacity(state.len() + 8 + root.len());
        payload.extend_from_slice(&state);
        payload.extend_from_slice(&(layer_index as u64).to_le_bytes());
        payload.extend_from_slice(root);
        state = hash(&payload).into();

        let label = format!("{}ETA-{layer_index}", FiatShamirChallengeRules::SALT_PREFIX);
        let mut eta_payload = Vec::with_capacity(state.len() + label.len());
        eta_payload.extend_from_slice(&state);
        eta_payload.extend_from_slice(label.as_bytes());
        let challenge: [u8; 32] = hash(&eta_payload).into();
        state = hash(&challenge).into();
    }

    let mut final_payload =
        Vec::with_capacity(state.len() + b"RPP-FS/FINAL".len() + final_polynomial_digest.len());
    final_payload.extend_from_slice(&state);
    final_payload.extend_from_slice(b"RPP-FS/FINAL");
    final_payload.extend_from_slice(final_polynomial_digest);
    state = hash(&final_payload).into();

    let mut query_payload = Vec::with_capacity(state.len() + b"RPP-FS/QUERY-SEED".len());
    query_payload.extend_from_slice(&state);
    query_payload.extend_from_slice(b"RPP-FS/QUERY-SEED");
    hash(&query_payload).into()
}

fn hash_final_layer(values: &[FieldElement]) -> [u8; 32] {
    let mut payload = Vec::with_capacity(4 + values.len() * 8);
    payload.extend_from_slice(&(values.len() as u32).to_le_bytes());
    for value in values {
        let bytes = value.to_bytes().expect("synthetic values are canonical");
        payload.extend_from_slice(&bytes);
    }
    hash(&payload).into()
}

fn build_opening_artifacts(
    params: &rpp_stark::params::StarkParams,
    aux: &CommitAux,
    leaves: &[Leaf],
    indices: &[u32],
) -> (Vec<Vec<u8>>, Vec<MerkleAuthenticationPath>) {
    let mut leaf_bytes = Vec::with_capacity(indices.len());
    let mut paths = Vec::with_capacity(indices.len());
    for &index in indices {
        let proof = MerkleTree::<DeterministicMerkleHasher>::open(params, aux, &[index])
            .expect("synthetic merkle proof");
        let bytes = leaves
            .get(index as usize)
            .map(|leaf| leaf.as_bytes().to_vec())
            .unwrap_or_else(|| {
                FieldElement::ZERO
                    .to_bytes()
                    .expect("zero is canonical")
                    .to_vec()
            });
        leaf_bytes.push(bytes);
        paths.push(convert_tree_proof(&proof, index));
    }
    (leaf_bytes, paths)
}

fn convert_tree_proof(proof: &MerkleProof, index: u32) -> MerkleAuthenticationPath {
    let mut nodes = Vec::with_capacity(proof.path().len());
    let mut current = index;
    let arity = proof.arity.as_usize() as u32;
    for node in proof.path() {
        match node {
            ProofNode::Arity2([digest]) => {
                let position = (current % arity) as u8;
                nodes.push(MerklePathNode {
                    index: position,
                    sibling: digest_to_array(digest.as_bytes()),
                });
            }
            ProofNode::Arity4(digests) => {
                let position = (current % arity) as u8;
                let branching = proof.arity.as_usize() as u8;
                let missing_positions: Vec<u8> =
                    (0..branching).filter(|pos| *pos != position).collect();
                let mut digest_iter = digests.iter();

                if let Some(first_digest) = digest_iter.next() {
                    nodes.push(MerklePathNode {
                        index: position,
                        sibling: digest_to_array(first_digest.as_bytes()),
                    });
                } else {
                    nodes.push(MerklePathNode {
                        index: position,
                        sibling: [0u8; 32],
                    });
                }

                for (pos, digest) in missing_positions.iter().skip(1).zip(digest_iter) {
                    nodes.push(MerklePathNode {
                        index: *pos,
                        sibling: digest_to_array(digest.as_bytes()),
                    });
                }
            }
        }
        if arity > 0 {
            current /= arity;
        }
    }
    MerkleAuthenticationPath { nodes }
}

fn field_to_bytes(value: FieldElement) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    let le = value.to_bytes().expect("test values should be canonical");
    bytes[..le.len()].copy_from_slice(&le);
    bytes
}

fn digest_to_array(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let len = bytes.len().min(32);
    out[..len].copy_from_slice(&bytes[..len]);
    out
}
