//! Deterministic verifier implementation.
//!
//! The verifier mirrors the prover pipeline by replaying the transcript,
//! recomputing the Fiat–Shamir challenges and validating the FRI proof.  All
//! structural checks (length prefixes, digests and bounds) are performed before
//! any expensive cryptographic operation.

use crate::config::{
    ProofKind as ConfigProofKind, ProofKindLayout, ProofSystemConfig, VerifierContext,
    MERKLE_SCHEME_ID_BLAKE3_2ARY_V1, MERKLE_SCHEME_ID_BLAKE3_4ARY_V1,
};
use crate::field::prime_field::{CanonicalSerialize, FieldElementOps};
use crate::field::FieldElement;
use crate::fri::types::{FriError, FriSecurityLevel};
use crate::fri::{field_to_bytes, hash, Blake2sXof, FriVerifier};
use crate::hash::blake3::FiatShamirChallengeRules;
use crate::merkle::traits::MerkleHasher;
use crate::merkle::verify_proof as verify_merkle_proof;
use crate::merkle::{
    DeterministicMerkleHasher, Digest as MerkleDigest, Leaf, MerkleProof, ProofNode,
};
use crate::params::{MerkleArity, StarkParams};
use crate::proof::params::canonical_stark_params;
use crate::proof::public_inputs::PublicInputs;
use crate::proof::ser::{
    compute_integrity_digest, compute_public_digest, encode_proof_kind, map_public_to_config_kind,
    serialize_public_inputs,
};
use crate::proof::transcript::{Transcript, TranscriptBlockContext, TranscriptHeader};
use crate::proof::types::{
    FriVerifyIssue, MerkleSection, OutOfDomainOpening, Proof, VerifyError, VerifyReport,
    PROOF_ALPHA_VECTOR_LEN, PROOF_MAX_FRI_LAYERS, PROOF_MAX_QUERY_COUNT, PROOF_MIN_OOD_POINTS,
    PROOF_TELEMETRY_MAX_CAP_DEGREE, PROOF_TELEMETRY_MAX_CAP_SIZE, PROOF_TELEMETRY_MAX_QUERY_BUDGET,
    PROOF_VERSION,
};
use crate::utils::serialization::{DigestBytes, ProofBytes};
use std::collections::BTreeMap;
use std::convert::TryInto;

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
    let total_len = proof_bytes.as_slice().len();
    let total_bytes = total_len as u64;
    let mut stages = VerificationStages::default();
    match precheck_decoded_proof(
        proof,
        DecodedProofEnv {
            declared_kind,
            public_inputs,
            config,
            context,
            total_bytes: total_len,
            block_context: None,
        },
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
    pub(crate) params: StarkParams,
}

struct DecodedProofEnv<'ctx, 'pi> {
    declared_kind: ConfigProofKind,
    public_inputs: &'pi PublicInputs<'pi>,
    config: &'ctx ProofSystemConfig,
    context: &'ctx VerifierContext,
    total_bytes: usize,
    block_context: Option<&'ctx TranscriptBlockContext>,
}

#[allow(clippy::result_large_err)]
fn precheck_decoded_proof(
    proof: Proof,
    env: DecodedProofEnv<'_, '_>,
    stages: &mut VerificationStages,
) -> Result<PrecheckedProof, (Proof, VerifyError)> {
    if let Err(error) = validate_header(
        &proof,
        env.declared_kind,
        env.public_inputs,
        env.config,
        env.context,
        stages,
    ) {
        return Err((proof, error));
    }
    match precheck_body(
        &proof,
        env.public_inputs,
        env.config,
        env.context,
        env.total_bytes,
        env.block_context,
        stages,
    ) {
        Ok(prechecked) => Ok(PrecheckedProof {
            proof,
            fri_seed: prechecked.fri_seed,
            security_level: prechecked.security_level,
            params: prechecked.params,
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
    let total_len = proof_bytes.as_slice().len();
    let mut stages = VerificationStages::default();
    precheck_decoded_proof(
        proof,
        DecodedProofEnv {
            declared_kind,
            public_inputs,
            config,
            context,
            total_bytes: total_len,
            block_context,
        },
        &mut stages,
    )
    .map_err(|(_, err)| err)
}

pub(crate) fn execute_fri_stage(proof: &PrecheckedProof) -> Result<(), VerifyError> {
    let fri_proof = proof.proof.fri_proof();
    FriVerifier::verify_with_params(
        fri_proof,
        proof.security_level,
        proof.fri_seed,
        &proof.params,
        |index| {
            fri_proof
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
    if proof.version() != PROOF_VERSION {
        return Err(VerifyError::VersionMismatch {
            expected: PROOF_VERSION,
            actual: proof.version(),
        });
    }

    let expected_kind = map_public_to_config_kind(public_inputs.kind());
    if *proof.composition().kind() != expected_kind || *proof.composition().kind() != declared_kind
    {
        return Err(VerifyError::UnknownProofKind(encode_proof_kind(
            *proof.composition().kind(),
        )));
    }

    if proof.params_hash() != &config.param_digest {
        return Err(VerifyError::ParamsHashMismatch);
    }
    if proof.params_hash() != &context.param_digest {
        return Err(VerifyError::ParamsHashMismatch);
    }

    let expected_public_inputs =
        serialize_public_inputs(public_inputs).map_err(VerifyError::from)?;
    if proof.composition().public_inputs() != expected_public_inputs.as_slice() {
        return Err(VerifyError::PublicInputMismatch);
    }

    let expected_digest = compute_public_digest(proof.composition().public_inputs());
    if proof.public_digest().bytes != expected_digest {
        return Err(VerifyError::PublicInputMismatch);
    }
    stages.public_ok = true;

    let expected_air_spec =
        resolve_air_spec_id(&context.profile.air_spec_ids, *proof.composition().kind());
    if proof.composition().air_spec_id() != &expected_air_spec {
        return Err(VerifyError::UnknownProofKind(encode_proof_kind(
            *proof.composition().kind(),
        )));
    }

    stages.params_ok = true;

    Ok(())
}

struct PrecheckedBody {
    fri_seed: [u8; 32],
    security_level: FriSecurityLevel,
    params: StarkParams,
}

fn precheck_body(
    proof: &Proof,
    public_inputs: &PublicInputs<'_>,
    config: &ProofSystemConfig,
    context: &VerifierContext,
    total_bytes: usize,
    block_context: Option<&TranscriptBlockContext>,
    stages: &mut VerificationStages,
) -> Result<PrecheckedBody, VerifyError> {
    if proof.trace_commit().bytes != *proof.openings().merkle().core_root() {
        return Err(VerifyError::RootMismatch {
            section: MerkleSection::TraceCommit,
        });
    }

    match (
        proof.composition().composition_commit(),
        proof.openings().composition(),
    ) {
        (Some(commit), Some(_)) => {
            if commit.bytes != *proof.openings().merkle().aux_root() {
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
            if proof.openings().merkle().aux_root() != &[0u8; 32] {
                return Err(VerifyError::RootMismatch {
                    section: MerkleSection::CompositionCommit,
                });
            }
        }
    }

    if proof.openings().merkle().fri_layer_roots() != &proof.fri().fri_proof().layer_roots {
        return Err(VerifyError::MerkleVerifyFailed {
            section: MerkleSection::FriRoots,
        });
    }

    stages.merkle_ok = true;

    let transcript_kind = *proof.composition().kind();
    let air_spec_id = resolve_air_spec_id(&context.profile.air_spec_ids, transcript_kind);
    let mut transcript = Transcript::new(TranscriptHeader {
        version: context.common_ids.transcript_version_id.clone(),
        poseidon_param_id: context.profile.poseidon_param_id.clone(),
        air_spec_id: air_spec_id.clone(),
        proof_kind: transcript_kind,
        params_hash: context.param_digest.clone(),
    })
    .map_err(|_| VerifyError::TranscriptOrder)?;

    let public_inputs_bytes = serialize_public_inputs(public_inputs).map_err(VerifyError::from)?;
    transcript
        .absorb_public_inputs(&public_inputs_bytes)
        .map_err(|_| VerifyError::TranscriptOrder)?;
    let trace_commit = proof.trace_commit().bytes;
    let composition_commit = proof
        .composition()
        .composition_commit()
        .map(|commit| commit.bytes);
    transcript
        .absorb_commitment_roots(trace_commit, composition_commit)
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

    ensure_merkle_scheme(config, context)?;
    let stark_params = canonical_stark_params(&context.profile);

    let fri_seed = challenges
        .draw_fri_seed()
        .map_err(|_| VerifyError::TranscriptOrder)?;
    for (layer_index, _) in proof
        .openings()
        .merkle()
        .fri_layer_roots()
        .iter()
        .enumerate()
    {
        challenges
            .draw_fri_eta(layer_index)
            .map_err(|_| VerifyError::TranscriptOrder)?;
    }
    let _ = challenges
        .draw_query_seed()
        .map_err(|_| VerifyError::TranscriptOrder)?;

    let query_count = stark_params.fri().queries as usize;
    let fri_query_seed = derive_fri_query_seed(fri_seed, proof.fri().fri_proof());
    let expected_indices = derive_trace_query_indices(
        fri_query_seed,
        query_count,
        proof.fri().fri_proof().initial_domain_size,
    )?;

    validate_query_indices(proof.openings().trace().indices(), &expected_indices)?;
    if let Some(composition_openings) = proof.openings().composition() {
        validate_query_indices(composition_openings.indices(), &expected_indices)?;
    }

    let trace_values = verify_trace_commitment(
        &stark_params,
        &proof.trace_commit().bytes,
        proof.openings().trace(),
    )?;

    if let Some(composition_commit) = proof.composition().composition_commit() {
        let composition_openings =
            proof
                .openings()
                .composition()
                .ok_or(VerifyError::CompositionInconsistent {
                    reason: "missing_composition_openings".to_string(),
                })?;
        let alignment_values = extract_composition_leaf_values(composition_openings.leaves())?;
        verify_composition_alignment(
            &alignment_values,
            composition_openings.leaves(),
            proof.openings().trace().indices(),
            proof.fri().fri_proof(),
        )?;

        let composition_values = verify_composition_commitment(
            &stark_params,
            &composition_commit.bytes,
            composition_openings,
        )?;

        verify_ood_openings(
            proof.openings().out_of_domain(),
            &trace_values,
            &composition_values,
            &ood_points,
            &alpha_vector,
        )?;
        stages.composition_ok = true;
    } else {
        if proof.openings().composition().is_some() {
            return Err(VerifyError::CompositionInconsistent {
                reason: "missing_composition_commit".to_string(),
            });
        }
        stages.composition_ok = true;
    }

    let security_level = map_security_level(&context.profile);
    if proof.fri().fri_proof().security_level != security_level {
        return Err(VerifyError::FriVerifyFailed {
            issue: FriVerifyIssue::SecurityLevelMismatch,
        });
    }
    if total_bytes > context.limits.max_proof_size_bytes as usize {
        let got_kb = total_bytes.div_ceil(1024) as u32;
        let max_kb = (context.limits.max_proof_size_bytes as usize).div_ceil(1024) as u32;
        return Err(VerifyError::ProofTooLarge { max_kb, got_kb });
    }

    let payload = proof.serialize_payload().map_err(VerifyError::from)?;
    let header_bytes = proof
        .serialize_header(&payload)
        .map_err(VerifyError::from)?;
    let payload_len = payload.len();
    let declared_body_length = match total_bytes.checked_sub(header_bytes.len()) {
        Some(value) => value,
        None => {
            let actual = payload_len.min(u32::MAX as usize) as u32;
            return Err(VerifyError::BodyLengthMismatch {
                declared: 0,
                actual,
            });
        }
    };

    if declared_body_length != payload_len {
        let declared = declared_body_length.min(u32::MAX as usize) as u32;
        let actual = payload_len.min(u32::MAX as usize) as u32;
        return Err(VerifyError::BodyLengthMismatch { declared, actual });
    }

    if proof.telemetry().is_present() {
        let telemetry = proof.telemetry().frame();
        let expected_body_with_digest = match payload_len.checked_add(32) {
            Some(value) => value,
            None => {
                let actual = payload_len.min(u32::MAX as usize) as u32;
                return Err(VerifyError::BodyLengthMismatch {
                    declared: telemetry.body_length(),
                    actual,
                });
            }
        };

        let expected_body_length: u32 = match expected_body_with_digest.try_into() {
            Ok(value) => value,
            Err(_) => {
                let actual = payload_len.min(u32::MAX as usize) as u32;
                return Err(VerifyError::BodyLengthMismatch {
                    declared: telemetry.body_length(),
                    actual,
                });
            }
        };

        if telemetry.body_length() != expected_body_length {
            return Err(VerifyError::BodyLengthMismatch {
                declared: telemetry.body_length(),
                actual: expected_body_length,
            });
        }

        if telemetry.fri_parameters().fold != 2
            || telemetry.fri_parameters().query_budget as usize != security_level.query_budget()
        {
            return Err(VerifyError::InvalidFriSection("telemetry".to_string()));
        }

        if telemetry.fri_parameters().cap_degree > PROOF_TELEMETRY_MAX_CAP_DEGREE
            || telemetry.fri_parameters().cap_size > PROOF_TELEMETRY_MAX_CAP_SIZE
            || telemetry.fri_parameters().query_budget > PROOF_TELEMETRY_MAX_QUERY_BUDGET
        {
            return Err(VerifyError::InvalidFriSection("telemetry".to_string()));
        }

        let expected_header_length: u32 = match header_bytes.len().try_into() {
            Ok(value) => value,
            Err(_) => {
                let actual = header_bytes.len().min(u32::MAX as usize) as u32;
                return Err(VerifyError::HeaderLengthMismatch {
                    declared: telemetry.header_length(),
                    actual,
                });
            }
        };

        if telemetry.header_length() != expected_header_length {
            return Err(VerifyError::HeaderLengthMismatch {
                declared: telemetry.header_length(),
                actual: expected_header_length,
            });
        }

        let mut canonical = proof.clone_using_parts();
        let canonical_telemetry = canonical.telemetry_mut().frame_mut();
        canonical_telemetry.set_header_length(0);
        canonical_telemetry.set_body_length(0);
        canonical_telemetry.set_integrity_digest(DigestBytes::default());
        let canonical_payload = canonical.serialize_payload().map_err(VerifyError::from)?;
        let canonical_header = canonical
            .serialize_header(&canonical_payload)
            .map_err(VerifyError::from)?;
        let integrity_digest = compute_integrity_digest(&canonical_header, &canonical_payload);
        if proof.telemetry().frame().integrity_digest().bytes != integrity_digest {
            return Err(VerifyError::IntegrityDigestMismatch);
        }
    }

    enforce_resource_limits(*proof.composition().kind(), public_inputs, context, proof)?;

    Ok(PrecheckedBody {
        fri_seed,
        security_level,
        params: stark_params,
    })
}

fn ensure_merkle_scheme(
    config: &ProofSystemConfig,
    context: &VerifierContext,
) -> Result<(), VerifyError> {
    let scheme = &config.profile.merkle_scheme_id;
    if scheme != &context.common_ids.merkle_scheme_id {
        return Err(VerifyError::UnsupportedMerkleScheme);
    }
    if scheme != &MERKLE_SCHEME_ID_BLAKE3_2ARY_V1 && scheme != &MERKLE_SCHEME_ID_BLAKE3_4ARY_V1 {
        return Err(VerifyError::UnsupportedMerkleScheme);
    }

    Ok(())
}

fn derive_fri_query_seed(fri_seed: [u8; 32], fri_proof: &crate::fri::FriProof) -> [u8; 32] {
    let mut state = fri_seed;

    for (layer_index, root) in fri_proof.layer_roots.iter().enumerate() {
        let mut payload = Vec::with_capacity(state.len() + 8 + root.len());
        payload.extend_from_slice(&state);
        payload.extend_from_slice(&(layer_index as u64).to_le_bytes());
        payload.extend_from_slice(root);
        state = hash(&payload).into();

        let label = format!(
            "{}ETA-{}",
            FiatShamirChallengeRules::SALT_PREFIX,
            layer_index
        );
        let mut eta_payload = Vec::with_capacity(state.len() + label.len());
        eta_payload.extend_from_slice(&state);
        eta_payload.extend_from_slice(label.as_bytes());
        let challenge: [u8; 32] = hash(&eta_payload).into();
        state = hash(&challenge).into();
    }

    let mut final_payload = Vec::with_capacity(state.len() + b"RPP-FS/FINAL".len() + 32);
    final_payload.extend_from_slice(&state);
    final_payload.extend_from_slice(b"RPP-FS/FINAL");
    final_payload.extend_from_slice(&fri_proof.final_polynomial_digest);
    state = hash(&final_payload).into();

    let mut query_payload = Vec::with_capacity(state.len() + b"RPP-FS/QUERY-SEED".len());
    query_payload.extend_from_slice(&state);
    query_payload.extend_from_slice(b"RPP-FS/QUERY-SEED");
    hash(&query_payload).into()
}

fn derive_trace_query_indices(
    query_seed: [u8; 32],
    query_count: usize,
    domain_size: usize,
) -> Result<Vec<u32>, VerifyError> {
    if domain_size == 0 || domain_size > u32::MAX as usize {
        return Err(VerifyError::IndicesMismatch);
    }

    let mut sampler = QueryIndexSampler::new(query_seed);
    let target = core::cmp::min(query_count, domain_size);
    let mut seen = vec![false; domain_size];
    let mut indices = Vec::with_capacity(target);

    while indices.len() < target {
        let position = sampler.challenge_usize(domain_size)?;
        if !seen[position] {
            seen[position] = true;
            indices.push(position as u32);
        }
    }

    indices.sort_unstable();
    Ok(indices)
}

fn validate_query_indices(provided: &[u32], expected: &[u32]) -> Result<(), VerifyError> {
    if provided.is_empty() {
        return Err(VerifyError::EmptyOpenings);
    }

    let mut previous = None;
    for &value in provided {
        if let Some(prev) = previous {
            if value < prev {
                return Err(VerifyError::IndicesNotSorted);
            }
            if value == prev {
                return Err(VerifyError::IndicesDuplicate { index: value });
            }
        }
        previous = Some(value);
    }

    if provided.len() != expected.len() {
        return Err(VerifyError::IndicesMismatch);
    }

    if provided != expected {
        return Err(VerifyError::IndicesMismatch);
    }

    Ok(())
}

struct QueryIndexSampler {
    xof: Blake2sXof,
}

impl QueryIndexSampler {
    fn new(seed: [u8; 32]) -> Self {
        Self {
            xof: Blake2sXof::new(&seed),
        }
    }

    fn challenge_usize(&mut self, range: usize) -> Result<usize, VerifyError> {
        debug_assert!(range > 0);
        let word = self.xof.next_u64().map_err(VerifyError::from)?;
        Ok((word % (range as u64)) as usize)
    }
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
        openings.indices(),
        openings.leaves(),
        openings.paths(),
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
        openings.indices(),
        openings.leaves(),
        openings.paths(),
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

    if params.merkle().leaf_width != 1 {
        return Err(VerifyError::UnsupportedMerkleScheme);
    }

    let element_size = FieldElement::BYTE_LENGTH;
    let expected_leaf_bytes = element_size * params.merkle().leaf_width as usize;
    let arity = params.merkle().arity;
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
            arity,
            leaf_encoding: params.merkle().leaf_encoding,
            path: convert_path(path, section, arity)?,
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
    arity: MerkleArity,
) -> Result<Vec<ProofNode>, VerifyError> {
    if path.nodes().is_empty() {
        return Err(VerifyError::MerkleVerifyFailed { section });
    }

    match arity {
        MerkleArity::Binary => {
            let mut nodes = Vec::with_capacity(path.nodes().len());
            for node in path.nodes() {
                if node.index > 1 {
                    return Err(VerifyError::MerkleVerifyFailed { section });
                }
                nodes.push(ProofNode::Arity2([MerkleDigest::new(
                    node.sibling.to_vec(),
                )]));
            }
            Ok(nodes)
        }
        MerkleArity::Quaternary => {
            let mut nodes = Vec::new();
            let branching = 4u8;
            let mut cursor = 0usize;

            while cursor < path.nodes().len() {
                let first = &path.nodes()[cursor];
                if first.index >= branching {
                    return Err(VerifyError::MerkleVerifyFailed { section });
                }

                let missing_positions: Vec<u8> =
                    (0..branching).filter(|pos| *pos != first.index).collect();
                if missing_positions.is_empty() {
                    return Err(VerifyError::MerkleVerifyFailed { section });
                }

                let additional_count = missing_positions.len().saturating_sub(1);
                let required = 1 + additional_count;
                if cursor + required > path.nodes().len() {
                    return Err(VerifyError::MerkleVerifyFailed { section });
                }

                let additional_slice = &path.nodes()[cursor + 1..cursor + required];
                let mut seen = [false; 4];
                let mut digest_map = BTreeMap::new();

                for node in additional_slice {
                    if node.index >= branching || node.index == first.index {
                        return Err(VerifyError::MerkleVerifyFailed { section });
                    }
                    if !missing_positions.contains(&node.index) {
                        return Err(VerifyError::MerkleVerifyFailed { section });
                    }
                    if seen[node.index as usize] {
                        return Err(VerifyError::MerkleVerifyFailed { section });
                    }
                    seen[node.index as usize] = true;
                    if digest_map
                        .insert(node.index, MerkleDigest::new(node.sibling.to_vec()))
                        .is_some()
                    {
                        return Err(VerifyError::MerkleVerifyFailed { section });
                    }
                }

                let leftover_position = missing_positions
                    .iter()
                    .find(|pos| !seen[**pos as usize])
                    .copied()
                    .ok_or(VerifyError::MerkleVerifyFailed { section })?;
                seen[leftover_position as usize] = true;
                if digest_map
                    .insert(leftover_position, MerkleDigest::new(first.sibling.to_vec()))
                    .is_some()
                {
                    return Err(VerifyError::MerkleVerifyFailed { section });
                }

                let mut siblings = Vec::with_capacity(missing_positions.len());
                for pos in missing_positions.iter() {
                    let digest = digest_map
                        .remove(pos)
                        .ok_or(VerifyError::MerkleVerifyFailed { section })?;
                    siblings.push(digest);
                }

                let siblings: [MerkleDigest; 3] = siblings
                    .try_into()
                    .map_err(|_| VerifyError::MerkleVerifyFailed { section })?;
                nodes.push(ProofNode::Arity4(siblings));
                cursor += required;
            }

            if nodes.is_empty() {
                return Err(VerifyError::MerkleVerifyFailed { section });
            }

            Ok(nodes)
        }
    }
}

fn extract_composition_leaf_values(leaves: &[Vec<u8>]) -> Result<Vec<FieldElement>, VerifyError> {
    let mut values = Vec::with_capacity(leaves.len());
    for leaf_bytes in leaves {
        if leaf_bytes.len() < FieldElement::BYTE_LENGTH {
            return Err(VerifyError::CompositionLeafMismatch);
        }

        let mut field_bytes = [0u8; FieldElement::BYTE_LENGTH];
        field_bytes.copy_from_slice(&leaf_bytes[..FieldElement::BYTE_LENGTH]);
        let value = FieldElement::from_bytes(&field_bytes)
            .map_err(|_| VerifyError::NonCanonicalFieldElement)?;
        values.push(value);
    }

    Ok(values)
}

fn verify_composition_alignment(
    composition_values: &[FieldElement],
    composition_leaves: &[Vec<u8>],
    indices: &[u32],
    fri_proof: &crate::fri::FriProof,
) -> Result<(), VerifyError> {
    let expected = indices.len();
    if composition_values.len() != expected
        || composition_leaves.len() != expected
        || fri_proof.queries.len() != expected
    {
        return Err(VerifyError::CompositionInconsistent {
            reason: format!(
                "fri_query_count_mismatch:indices={},values={},leaves={},fri={}",
                expected,
                composition_values.len(),
                composition_leaves.len(),
                fri_proof.queries.len()
            ),
        });
    }

    for (position, (((value, leaf_bytes), &index), query)) in composition_values
        .iter()
        .zip(composition_leaves.iter())
        .zip(indices.iter())
        .zip(fri_proof.queries.iter())
        .enumerate()
    {
        if query.position != index as usize {
            return Err(VerifyError::CompositionInconsistent {
                reason: format!(
                    "fri_index_mismatch:pos={position}:expected={},actual={}",
                    index, query.position
                ),
            });
        }
        let first_layer =
            query
                .layers
                .first()
                .ok_or_else(|| VerifyError::CompositionInconsistent {
                    reason: format!("fri_first_layer_missing:pos={position}:index={index}"),
                })?;
        let fri_bytes = field_to_bytes(&first_layer.value).map_err(|_| {
            VerifyError::CompositionInconsistent {
                reason: format!("fri_value_encoding:pos={position}:index={index}"),
            }
        })?;
        if leaf_bytes.len() < fri_bytes.len() {
            return Err(VerifyError::CompositionInconsistent {
                reason: format!(
                    "composition_leaf_truncated:pos={position}:index={index}:leaf_bytes={}",
                    leaf_bytes.len()
                ),
            });
        }
        let leaf_prefix = &leaf_bytes[..fri_bytes.len()];
        if leaf_prefix != fri_bytes.as_slice() {
            return Err(VerifyError::CompositionInconsistent {
                reason: format!("composition_leaf_bytes_mismatch:pos={position}:index={index}"),
            });
        }
        if *value != first_layer.value {
            return Err(VerifyError::CompositionInconsistent {
                reason: format!("fri_value_mismatch:pos={position}:index={index}"),
            });
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
    let fri_proof = proof.fri_proof();
    if fri_proof.layer_roots.len() > context.limits.max_layers as usize {
        return Err(VerifyError::FriVerifyFailed {
            issue: FriVerifyIssue::LayerBudgetExceeded,
        });
    }

    if fri_proof.layer_roots.len() > PROOF_MAX_FRI_LAYERS {
        return Err(VerifyError::FriVerifyFailed {
            issue: FriVerifyIssue::LayerBudgetExceeded,
        });
    }

    if fri_proof.queries.len() > context.limits.max_queries as usize {
        return Err(VerifyError::FriVerifyFailed {
            issue: FriVerifyIssue::QueryOutOfRange,
        });
    }

    if fri_proof.queries.len() > PROOF_MAX_QUERY_COUNT {
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
    points: &[[u8; 32]],
    alpha_vector: &[[u8; 32]],
) -> Result<(), VerifyError> {
    if openings.is_empty()
        || trace_values.is_empty()
        || composition_values.is_empty()
        || points.is_empty()
        || alpha_vector.is_empty()
    {
        return Err(VerifyError::OutOfDomainInvalid);
    }

    if openings.len() != points.len() {
        return Err(VerifyError::OutOfDomainInvalid);
    }

    let alphas: Vec<FieldElement> = alpha_vector
        .iter()
        .map(FieldElement::from_transcript_bytes)
        .collect();

    for (opening, point_bytes) in openings.iter().zip(points.iter()) {
        if opening.core_values.len() != 1 || !opening.aux_values.is_empty() {
            return Err(VerifyError::OutOfDomainInvalid);
        }

        if opening.point != *point_bytes {
            return Err(VerifyError::OutOfDomainInvalid);
        }

        let point = FieldElement::from_transcript_bytes(point_bytes);
        let expected_trace = evaluate_ood_samples(trace_values, &alphas, point);
        let observed_trace = field_from_fixed_bytes(
            opening
                .core_values
                .first()
                .ok_or(VerifyError::OutOfDomainInvalid)?,
        )?;
        if observed_trace != expected_trace {
            return Err(VerifyError::TraceOodMismatch);
        }

        let expected_composition = evaluate_ood_samples(composition_values, &alphas, point);
        let observed_composition = field_from_fixed_bytes(&opening.composition_value)?;
        if observed_composition != expected_composition {
            return Err(VerifyError::CompositionOodMismatch);
        }
    }

    Ok(())
}

fn evaluate_ood_samples(
    samples: &[FieldElement],
    alphas: &[FieldElement],
    point: FieldElement,
) -> FieldElement {
    if samples.is_empty() || alphas.is_empty() {
        return FieldElement::ZERO;
    }

    let mut acc = FieldElement::ZERO;
    let mut power = FieldElement::ONE;
    for (sample, alpha) in samples.iter().zip(alphas.iter().cycle()) {
        let weighted = sample.mul(alpha);
        let term = weighted.mul(&power);
        acc = acc.add(&term);
        power = power.mul(&point);
    }
    acc
}

fn field_from_fixed_bytes(bytes: &[u8; 32]) -> Result<FieldElement, VerifyError> {
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[..8]);
    FieldElement::from_bytes(&buf).map_err(|_| VerifyError::NonCanonicalFieldElement)
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
        FriError::DeterministicHash(err) => VerifyError::DeterministicHash(err),
        FriError::FieldConstraint(_) => VerifyError::FriVerifyFailed {
            issue: FriVerifyIssue::Generic,
        },
    }
}
