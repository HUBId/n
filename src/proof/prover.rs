//! Deterministic prover pipeline implementation.
//!
//! The prover builds a proof envelope by executing the following steps:
//!
//! 1. Parse the witness into a list of LDE evaluations.
//! 2. Compute the initial commitment roots and bind them to the transcript.
//! 3. Derive Fiat–Shamir challenges (α-vector, OOD points, FRI seed).
//! 4. Produce a binary FRI proof using the deterministic seed.
//! 5. Assemble the envelope header/body, compute digests and enforce size limits.

use crate::air::composition::{compose, CompositionParams, ConstraintGroup};
use crate::air::example::{LfsrAir, LfsrPublicInputs};
use crate::air::trace::{NextRowView, Trace};
use crate::air::traits::{
    Air as AirContract, BoundaryBuilder as AirBoundaryBuilder, Evaluator as AirEvaluator, PolyExpr,
    TraceBuilder as AirTraceBuilder,
};
use crate::air::types::{AirError as AirLayerError, ColIx, TraceRole, TraceSchema};
use crate::config::{
    AirSpecId, ProfileConfig, ProofKind as ConfigProofKind, ProofKindLayout, ProofSystemConfig,
    ProverContext,
};
use crate::fft::lde::{LowDegreeExtensionParameters, PROFILE_HISEC_X16, PROFILE_X8};
use crate::field::FieldElement;
use crate::fri::{FriError, FriProof, FriSecurityLevel};
use crate::merkle::{
    CommitAux, DeterministicMerkleHasher, Leaf, MerkleArityExt, MerkleCommit, MerkleError,
    MerkleProof, MerkleTree, ProofNode,
};
use crate::params::StarkParams;
use crate::proof::params::canonical_stark_params;
use crate::proof::public_inputs::PublicInputs;
use crate::proof::ser::{
    compute_commitment_digest, compute_integrity_digest, compute_public_digest,
    map_public_to_config_kind, serialize_public_inputs,
};
use crate::proof::transcript::{
    Transcript as ProofTranscript, TranscriptBlockContext, TranscriptHeader,
};
use crate::proof::types::{
    CompositionOpenings, FriParametersMirror, MerkleAuthenticationPath, MerklePathNode,
    MerkleProofBundle, Openings, OutOfDomainOpening, Proof, Telemetry, TraceOpenings,
    PROOF_ALPHA_VECTOR_LEN, PROOF_MIN_OOD_POINTS, PROOF_VERSION,
};
use crate::transcript::{Transcript as AirTranscript, TranscriptContext, TranscriptLabel};
use crate::utils::serialization::{DigestBytes, WitnessBlob};
use core::cmp::{max, min};
use core::convert::TryInto;

use crate::field::prime_field::{CanonicalSerialize, FieldDeserializeError, FieldElementOps};

use super::types::{FriVerifyIssue, MerkleSection, VerifyError};

/// Errors surfaced while building a proof envelope.
#[derive(Debug)]
pub enum ProverError {
    /// The proof system configuration declared an unsupported version.
    UnsupportedProofVersion(u16),
    /// Parameter digest mismatch between configuration and prover context.
    ParamDigestMismatch,
    /// Witness blob failed to parse into field elements.
    MalformedWitness(&'static str),
    /// Failed to derive Fiat–Shamir challenges.
    Transcript(crate::proof::transcript::TranscriptError),
    /// Binary FRI prover returned an error.
    Fri(FriError),
    /// AIR layer surface error.
    Air(AirLayerError),
    /// Merkle tree construction failed.
    Merkle(MerkleError),
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

impl From<AirLayerError> for ProverError {
    fn from(err: AirLayerError) -> Self {
        ProverError::Air(err)
    }
}

impl From<MerkleError> for ProverError {
    fn from(err: MerkleError) -> Self {
        ProverError::Merkle(err)
    }
}

/// Builds a [`Proof`] from public inputs and witness data.
pub fn build_envelope(
    public_inputs: &PublicInputs<'_>,
    witness: WitnessBlob<'_>,
    config: &ProofSystemConfig,
    context: &ProverContext,
) -> Result<Proof, ProverError> {
    let declared_version = config.proof_version.0 as u16;
    if declared_version != PROOF_VERSION {
        return Err(ProverError::UnsupportedProofVersion(declared_version));
    }

    if config.param_digest != context.param_digest {
        return Err(ProverError::ParamDigestMismatch);
    }

    let proof_kind = map_public_to_config_kind(public_inputs.kind());
    let air_spec_id = resolve_air_spec_id(&context.profile.air_spec_ids, proof_kind);
    let security_level = map_security_level(&context.profile);

    let public_inputs_bytes = serialize_public_inputs(public_inputs);
    let public_digest = compute_public_digest(&public_inputs_bytes);

    let lfsr_inputs = map_lfsr_public_inputs(public_inputs)?;
    let air = LfsrAir::new(lfsr_inputs.clone());
    let trace_schema = air.trace_schema()?;

    let witness_columns = parse_witness(witness)?;
    let columns = map_witness_to_schema(&witness_columns, &trace_schema, lfsr_inputs.length)?;

    let mut trace_builder = air.new_trace_builder()?;
    for (meta, column) in trace_schema.columns.iter().zip(columns.iter()) {
        trace_builder.add_column(meta.role, column.clone())?;
    }
    let trace_data = trace_builder.build(trace_schema.degree_bounds)?;
    let mut trace_columns = Vec::with_capacity(trace_schema.columns.len());
    for (index, _) in trace_schema.columns.iter().enumerate() {
        trace_columns.push(trace_data.column(ColIx::new(index))?.to_vec());
    }
    let trace = Trace::from_columns(trace_schema.clone(), trace_columns.clone())?;

    let mut boundary_builder = air.new_boundary_builder()?;
    for (index, meta) in trace_schema.columns.iter().enumerate() {
        for boundary in &meta.boundaries {
            let value = trace_data.boundary_value(ColIx::new(index), *boundary)?;
            boundary_builder.set(ColIx::new(index), *boundary, value)?;
        }
    }
    let _boundary_constraints = boundary_builder.build()?;

    let lde_params = map_lde_profile(context.profile.lde_factor as usize);
    let lde_values = trace.lde_evaluations(lde_params)?;

    let stark_params = canonical_stark_params(&context.profile);
    let (core_root, core_aux, trace_leaves) = commit_evaluations(&stark_params, &lde_values)?;

    let mut air_transcript = prepare_air_transcript(&stark_params, &public_digest, &core_root)?;
    let degree_bounds = trace_schema.degree_bounds;
    let constraint_groups = build_constraint_groups(&air, &trace, lde_params)?;
    let (composition_values, composition_commitment) = compose(
        &air,
        CompositionParams {
            stark: &stark_params,
            transcript: &mut air_transcript,
            degree_bounds,
            groups: &constraint_groups,
        },
    )?;
    let aux_root = digest_to_array(composition_commitment.root.as_bytes());
    let composition_aux = composition_commitment.aux;
    let composition_leaves = evaluations_to_leaves(&composition_values)?;

    let mut transcript = ProofTranscript::new(TranscriptHeader {
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
    let alpha_vector = challenges.draw_alpha_vector(PROOF_ALPHA_VECTOR_LEN)?;
    let ood_points = challenges.draw_ood_points(PROOF_MIN_OOD_POINTS)?;
    let _ood_seed = challenges.draw_ood_seed()?;

    let fri_seed = challenges.draw_fri_seed()?;
    let fri_proof =
        FriProof::prove_with_params(security_level, fri_seed, &composition_values, &stark_params)?;

    // Consume the η challenges to keep transcript counters aligned with the proof.
    for (layer_index, _) in fri_proof.layer_roots.iter().enumerate() {
        let _ = challenges.draw_fri_eta(layer_index)?;
    }
    let _ = challenges.draw_query_seed()?;

    let trace_indices: Vec<u32> = fri_proof
        .queries
        .iter()
        .map(|query| query.position.try_into().unwrap_or(u32::MAX))
        .collect();

    let sampled_trace_values: Vec<FieldElement> = trace_indices
        .iter()
        .map(|&index| {
            let pos = index as usize;
            lde_values.get(pos).copied().unwrap_or(FieldElement::ZERO)
        })
        .collect();
    let sampled_composition_values: Vec<FieldElement> = trace_indices
        .iter()
        .map(|&index| {
            let pos = index as usize;
            composition_values
                .get(pos)
                .copied()
                .unwrap_or(FieldElement::ZERO)
        })
        .collect();
    let composition_openings = build_composition_openings(
        &stark_params,
        &composition_aux,
        &composition_leaves,
        &trace_indices,
    )?;
    let trace_openings =
        build_trace_openings(&stark_params, &core_aux, &trace_leaves, &trace_indices)?;
    let ood_openings = derive_ood_openings(
        &ood_points,
        &alpha_vector,
        &sampled_trace_values,
        &sampled_composition_values,
    );
    let fri_layer_roots = fri_proof.layer_roots.clone();
    let commitment_digest = compute_commitment_digest(&core_root, &aux_root, &fri_layer_roots);

    let fri_parameters = FriParametersMirror {
        fold: 2,
        cap_degree: context.profile.fri_depth_range.max as u16,
        cap_size: min(
            fri_proof.final_polynomial.len() as u32,
            crate::proof::types::PROOF_TELEMETRY_MAX_CAP_SIZE,
        ),
        query_budget: security_level.query_budget() as u16,
    };

    let merkle = MerkleProofBundle {
        core_root,
        aux_root,
        fri_layer_roots,
    };

    let telemetry = Telemetry {
        header_length: 0,
        body_length: 0,
        fri_parameters,
        integrity_digest: DigestBytes::default(),
    };

    let mut proof = Proof {
        version: PROOF_VERSION,
        kind: proof_kind,
        param_digest: context.param_digest.clone(),
        air_spec_id,
        public_inputs: public_inputs_bytes,
        public_digest: DigestBytes {
            bytes: public_digest,
        },
        commitment_digest: DigestBytes {
            bytes: commitment_digest,
        },
        has_composition_commit: true,
        merkle,
        openings: Openings {
            trace: trace_openings,
            composition: Some(composition_openings),
            out_of_domain: ood_openings,
        },
        fri_proof,
        has_telemetry: true,
        telemetry,
    };

    let body_payload = proof.serialize_payload();
    let header_bytes = proof.serialize_header(&body_payload);
    proof.telemetry.body_length = (body_payload.len() + 32) as u32;
    proof.telemetry.header_length = header_bytes.len() as u32;

    let integrity_digest = compute_integrity_digest(&header_bytes, &body_payload);
    proof.telemetry.integrity_digest = DigestBytes {
        bytes: integrity_digest,
    };

    let total_size = header_bytes.len() + body_payload.len() + 32;
    if total_size > context.limits.max_proof_size_bytes as usize {
        return Err(ProverError::ProofTooLarge {
            actual: total_size,
            limit: context.limits.max_proof_size_bytes,
        });
    }

    Ok(proof)
}

#[derive(Debug, Clone, Default)]
struct WitnessColumns {
    rows: usize,
    main: Vec<Vec<FieldElement>>,
    auxiliary: Vec<Vec<FieldElement>>,
    permutation: Vec<Vec<FieldElement>>,
    lookup: Vec<Vec<FieldElement>>,
}

fn parse_witness(witness: WitnessBlob<'_>) -> Result<WitnessColumns, ProverError> {
    const HEADER_FIELDS: usize = 5;
    const FIELD_BYTES: usize = 8;
    if witness.bytes.len() < HEADER_FIELDS * 4 {
        return Err(ProverError::MalformedWitness("witness_header"));
    }

    let mut cursor = 0usize;
    let take_u32 = |bytes: &[u8], offset: &mut usize| -> Result<u32, ProverError> {
        let end = offset
            .checked_add(4)
            .ok_or(ProverError::MalformedWitness("witness_overflow"))?;
        let slice = bytes
            .get(*offset..end)
            .ok_or(ProverError::MalformedWitness("witness_header"))?;
        let mut buf = [0u8; 4];
        buf.copy_from_slice(slice);
        *offset = end;
        Ok(u32::from_le_bytes(buf))
    };

    let rows = take_u32(witness.bytes, &mut cursor)? as usize;
    if rows == 0 {
        return Err(ProverError::MalformedWitness("trace_rows"));
    }
    let main_cols = take_u32(witness.bytes, &mut cursor)? as usize;
    let aux_cols = take_u32(witness.bytes, &mut cursor)? as usize;
    let perm_cols = take_u32(witness.bytes, &mut cursor)? as usize;
    let lookup_cols = take_u32(witness.bytes, &mut cursor)? as usize;

    let total_columns = main_cols
        .checked_add(aux_cols)
        .and_then(|v| v.checked_add(perm_cols))
        .and_then(|v| v.checked_add(lookup_cols))
        .ok_or(ProverError::MalformedWitness("column_overflow"))?;
    let expected = HEADER_FIELDS * 4 + total_columns * rows * FIELD_BYTES;
    if witness.bytes.len() != expected {
        return Err(ProverError::MalformedWitness("witness_size"));
    }

    let parse_segment = |count: usize,
                         data: &[u8],
                         offset: &mut usize,
                         label: &'static str|
     -> Result<Vec<Vec<FieldElement>>, ProverError> {
        let mut segment = Vec::with_capacity(count);
        for _ in 0..count {
            let mut column = Vec::with_capacity(rows);
            for _ in 0..rows {
                let end = offset
                    .checked_add(FIELD_BYTES)
                    .ok_or(ProverError::MalformedWitness("witness_overflow"))?;
                let slice = data
                    .get(*offset..end)
                    .ok_or(ProverError::MalformedWitness(label))?;
                let mut buf = [0u8; FIELD_BYTES];
                buf.copy_from_slice(slice);
                let value = FieldElement::from_bytes(&buf).map_err(|err| match err {
                    FieldDeserializeError::FieldDeserializeNonCanonical => {
                        ProverError::MalformedWitness("non_canonical_field")
                    }
                })?;
                column.push(value);
                *offset = end;
            }
            segment.push(column);
        }
        Ok(segment)
    };

    let main = parse_segment(main_cols, witness.bytes, &mut cursor, "main_columns")?;
    let auxiliary = parse_segment(aux_cols, witness.bytes, &mut cursor, "aux_columns")?;
    let permutation = parse_segment(perm_cols, witness.bytes, &mut cursor, "perm_columns")?;
    let lookup = parse_segment(lookup_cols, witness.bytes, &mut cursor, "lookup_columns")?;

    Ok(WitnessColumns {
        rows,
        main,
        auxiliary,
        permutation,
        lookup,
    })
}

fn map_witness_to_schema(
    witness: &WitnessColumns,
    schema: &TraceSchema,
    expected_rows: usize,
) -> Result<Vec<Vec<FieldElement>>, ProverError> {
    if witness.rows != expected_rows {
        return Err(ProverError::MalformedWitness("trace_length"));
    }
    if !witness.permutation.is_empty() || !witness.lookup.is_empty() {
        return Err(ProverError::MalformedWitness("unsupported_witness_segment"));
    }

    let mut main_ix = 0usize;
    let mut aux_ix = 0usize;
    let mut columns = Vec::with_capacity(schema.columns.len());
    for meta in &schema.columns {
        let source = match meta.role {
            TraceRole::Main => {
                let column = witness
                    .main
                    .get(main_ix)
                    .ok_or(ProverError::MalformedWitness("main_columns"))?;
                main_ix += 1;
                column
            }
            TraceRole::Auxiliary => {
                let column = witness
                    .auxiliary
                    .get(aux_ix)
                    .ok_or(ProverError::MalformedWitness("aux_columns"))?;
                aux_ix += 1;
                column
            }
        };
        if source.len() != witness.rows {
            return Err(ProverError::MalformedWitness("column_length"));
        }
        columns.push(source.clone());
    }

    if main_ix != witness.main.len() || aux_ix != witness.auxiliary.len() {
        return Err(ProverError::MalformedWitness("column_count_mismatch"));
    }

    Ok(columns)
}

fn map_lfsr_public_inputs(
    public_inputs: &PublicInputs<'_>,
) -> Result<LfsrPublicInputs, ProverError> {
    match public_inputs {
        PublicInputs::Execution { header, body } => {
            if body.len() != 8 {
                return Err(ProverError::MalformedWitness("lfsr_seed_length"));
            }
            let mut seed_bytes = [0u8; 8];
            seed_bytes.copy_from_slice(body);
            let seed = FieldElement::from_bytes(&seed_bytes).map_err(|err| match err {
                FieldDeserializeError::FieldDeserializeNonCanonical => {
                    ProverError::MalformedWitness("lfsr_seed")
                }
            })?;
            if header.trace_width != 1 {
                return Err(ProverError::MalformedWitness("trace_width"));
            }
            LfsrPublicInputs::new(seed, header.trace_length as usize).map_err(ProverError::Air)
        }
        _ => Err(ProverError::MalformedWitness("unsupported_public_inputs")),
    }
}

fn build_constraint_groups<A: AirContract>(
    air: &A,
    trace: &Trace,
    lde_params: &'static LowDegreeExtensionParameters,
) -> Result<Vec<ConstraintGroup>, ProverError> {
    let evaluator = air.new_evaluator()?;
    let constraints = evaluator.constraints()?;
    let domain_size = trace
        .length()
        .checked_mul(lde_params.blowup_factor)
        .ok_or(ProverError::MalformedWitness("domain_size"))?;

    if constraints.is_empty() {
        let zeros = vec![FieldElement::ZERO; domain_size];
        return Ok(vec![ConstraintGroup::new(
            "transition",
            TraceRole::Main,
            1,
            vec![zeros],
        )]);
    }

    let mut evaluations = Vec::with_capacity(constraints.len());
    let mut max_degree = 0usize;
    for constraint in constraints {
        max_degree = max(max_degree, constraint.degree);
        let mut column = vec![FieldElement::ZERO; domain_size];
        for step in 0..trace.length() {
            let view = trace.row_pair(step)?;
            column[step] = evaluate_poly_expr(&constraint.expr, view)?;
        }
        evaluations.push(column);
    }

    Ok(vec![ConstraintGroup::new(
        "transition",
        TraceRole::Main,
        max_degree.max(1),
        evaluations,
    )])
}

fn evaluate_poly_expr(expr: &PolyExpr, row: NextRowView<'_>) -> Result<FieldElement, ProverError> {
    match expr {
        PolyExpr::Const(value) => Ok(*value),
        PolyExpr::Column { column } => {
            let (current, _) = row.get(*column)?;
            Ok(current)
        }
        PolyExpr::Next { column } => {
            let (_, next) = row.get(*column)?;
            Ok(next)
        }
        PolyExpr::Neg(inner) => Ok(evaluate_poly_expr(inner, row)?.neg()),
        PolyExpr::Add(lhs, rhs) => {
            let left = evaluate_poly_expr(lhs, row)?;
            let right = evaluate_poly_expr(rhs, row)?;
            Ok(left.add(&right))
        }
        PolyExpr::Sub(lhs, rhs) => {
            let left = evaluate_poly_expr(lhs, row)?;
            let right = evaluate_poly_expr(rhs, row)?;
            Ok(left.sub(&right))
        }
        PolyExpr::Mul(lhs, rhs) => {
            let left = evaluate_poly_expr(lhs, row)?;
            let right = evaluate_poly_expr(rhs, row)?;
            Ok(left.mul(&right))
        }
    }
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

fn map_lde_profile(factor: usize) -> &'static LowDegreeExtensionParameters {
    match factor {
        16 => &PROFILE_HISEC_X16,
        _ => &PROFILE_X8,
    }
}

fn commit_evaluations(
    params: &StarkParams,
    evaluations: &[FieldElement],
) -> Result<([u8; 32], CommitAux, Vec<Leaf>), ProverError> {
    let leaves = evaluations_to_leaves(evaluations)?;
    let (root, aux) = <MerkleTree<DeterministicMerkleHasher> as MerkleCommit>::commit(
        params,
        leaves.clone().into_iter(),
    )?;
    Ok((digest_to_array(root.as_bytes()), aux, leaves))
}

fn prepare_air_transcript(
    params: &StarkParams,
    public_digest: &[u8; 32],
    trace_root: &[u8; 32],
) -> Result<AirTranscript, ProverError> {
    let mut transcript = AirTranscript::new(params, TranscriptContext::StarkMain);
    let mut digest_bytes = [0u8; 8];
    digest_bytes.copy_from_slice(&public_digest[..8]);
    let digest_felt = FieldElement::from_bytes(&digest_bytes)
        .map_err(|_| ProverError::MalformedWitness("transcript_public_digest"))?;
    transcript
        .absorb_field_elements(TranscriptLabel::PublicInputsDigest, &[digest_felt])
        .map_err(|_| ProverError::MalformedWitness("transcript_public"))?;
    transcript
        .absorb_digest(
            TranscriptLabel::TraceRoot,
            &DigestBytes { bytes: *trace_root },
        )
        .map_err(|_| ProverError::MalformedWitness("transcript_trace_root"))?;
    let _ = transcript
        .challenge_field(TranscriptLabel::TraceChallengeA)
        .map_err(|_| ProverError::MalformedWitness("transcript_trace_challenge"))?;
    transcript
        .absorb_digest(TranscriptLabel::CompRoot, &DigestBytes { bytes: [0u8; 32] })
        .map_err(|_| ProverError::MalformedWitness("transcript_comp_root_placeholder"))?;
    Ok(transcript)
}

fn evaluations_to_leaves(values: &[FieldElement]) -> Result<Vec<Leaf>, ProverError> {
    if values.is_empty() {
        return Ok(Vec::new());
    }
    let mut leaves = Vec::with_capacity(values.len());
    for value in values {
        let mut bytes = Vec::with_capacity(8);
        bytes.extend_from_slice(&value.to_bytes());
        leaves.push(Leaf::new(bytes));
    }
    Ok(leaves)
}

fn build_trace_openings(
    params: &StarkParams,
    aux: &CommitAux,
    leaves: &[Leaf],
    indices: &[u32],
) -> Result<TraceOpenings, ProverError> {
    let (leaf_bytes, paths) = build_opening_artifacts(params, aux, leaves, indices)?;
    Ok(TraceOpenings {
        indices: indices.to_vec(),
        leaves: leaf_bytes,
        paths,
    })
}

fn build_composition_openings(
    params: &StarkParams,
    aux: &CommitAux,
    leaves: &[Leaf],
    indices: &[u32],
) -> Result<CompositionOpenings, ProverError> {
    let (leaf_bytes, paths) = build_opening_artifacts(params, aux, leaves, indices)?;
    Ok(CompositionOpenings {
        indices: indices.to_vec(),
        leaves: leaf_bytes,
        paths,
    })
}

fn build_opening_artifacts(
    params: &StarkParams,
    aux: &CommitAux,
    leaves: &[Leaf],
    indices: &[u32],
) -> Result<(Vec<Vec<u8>>, Vec<MerkleAuthenticationPath>), ProverError> {
    let mut leaf_bytes = Vec::with_capacity(indices.len());
    let mut paths = Vec::with_capacity(indices.len());
    for &index in indices {
        let proof =
            <MerkleTree<DeterministicMerkleHasher> as MerkleCommit>::open(params, aux, &[index])?;
        let bytes = leaves
            .get(index as usize)
            .map(|leaf| leaf.as_bytes().to_vec())
            .unwrap_or_default();
        leaf_bytes.push(bytes);
        paths.push(convert_tree_proof(&proof, index));
    }
    Ok((leaf_bytes, paths))
}

fn convert_tree_proof(proof: &MerkleProof, index: u32) -> MerkleAuthenticationPath {
    let mut nodes = Vec::new();
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
                let sibling_index = (position as usize)
                    .saturating_sub(1)
                    .min(digests.len().saturating_sub(1));
                nodes.push(MerklePathNode {
                    index: position,
                    sibling: digest_to_array(digests[sibling_index].as_bytes()),
                });
            }
        }
        if arity > 0 {
            current /= arity;
        }
    }
    MerkleAuthenticationPath { nodes }
}

fn derive_ood_openings(
    points: &[[u8; 32]],
    _alpha_vector: &[[u8; 32]],
    trace_values: &[FieldElement],
    composition_values: &[FieldElement],
) -> Vec<OutOfDomainOpening> {
    if composition_values.is_empty() || trace_values.is_empty() {
        return Vec::new();
    }
    let trace_len = trace_values.len();
    let comp_len = composition_values.len();
    points
        .iter()
        .map(|point| {
            let comp_index = (point[0] as usize) % comp_len;
            let trace_index = comp_index % trace_len;
            let core_value = field_to_bytes(trace_values[trace_index]);
            let comp_value = field_to_bytes(composition_values[comp_index]);
            OutOfDomainOpening {
                point: *point,
                core_values: vec![core_value],
                aux_values: Vec::new(),
                composition_value: comp_value,
            }
        })
        .collect()
}

fn field_to_bytes(value: FieldElement) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    let le = value.to_bytes();
    bytes[..le.len()].copy_from_slice(&le);
    bytes
}

fn digest_to_array(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let len = bytes.len().min(32);
    out[..len].copy_from_slice(&bytes[..len]);
    out
}

/// Helper converting prover errors into verification failures when the prover
/// surface is reused by integration tests.
impl From<ProverError> for VerifyError {
    fn from(error: ProverError) -> Self {
        match error {
            ProverError::UnsupportedProofVersion(version) => VerifyError::VersionMismatch {
                expected: PROOF_VERSION,
                actual: version,
            },
            ProverError::ParamDigestMismatch => VerifyError::ParamsHashMismatch,
            ProverError::MalformedWitness(_) => {
                VerifyError::UnexpectedEndOfBuffer("malformed_witness".to_string())
            }
            ProverError::Transcript(_) => VerifyError::TranscriptOrder,
            ProverError::Fri(FriError::LayerRootMismatch { .. }) => VerifyError::FriVerifyFailed {
                issue: FriVerifyIssue::LayerMismatch,
            },
            ProverError::Fri(FriError::PathInvalid { .. }) => VerifyError::MerkleVerifyFailed {
                section: MerkleSection::FriPath,
            },
            ProverError::Fri(FriError::QueryOutOfRange { .. }) => VerifyError::FriVerifyFailed {
                issue: FriVerifyIssue::QueryOutOfRange,
            },
            ProverError::Fri(_) => VerifyError::FriVerifyFailed {
                issue: FriVerifyIssue::Generic,
            },
            ProverError::Air(_) => VerifyError::UnexpectedEndOfBuffer("air_error".to_string()),
            ProverError::Merkle(_) => VerifyError::MerkleVerifyFailed {
                section: MerkleSection::FriPath,
            },
            ProverError::ProofTooLarge { .. } => VerifyError::ProofTooLarge,
        }
    }
}
