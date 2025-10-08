#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]

//! Core library entry point for the `rpp-stark` proof system.
//!
//! The crate exposes declarative contracts for proof generation, verification
//! and aggregation. All functions are intentionally left without
//! implementations; they simply document the required parameters and the
//! deterministic sequencing dictated by the specification.

pub mod air;
pub mod config;
pub mod fft;
pub mod field;
pub mod fri;
pub mod hash;
pub mod merkle;
pub mod params;
pub mod proof;
pub mod ser;
pub mod transcript;
pub mod utils;
pub mod vrf;

use config::{ProofSystemConfig, ProverContext, VerifierContext};
use proof::aggregation;
use proof::prover;
use proof::public_inputs::PublicInputs;
use proof::ser::map_public_to_config_kind;
use proof::types::{FriVerifyIssue, MerkleSection};
use proof::ProofKind;
use ser::{SerError, SerKind as SerializationKind};

pub use proof::aggregation::{BatchProofRecord, BatchVerificationOutcome, BlockContext};
pub use proof::types::{Proof, Telemetry, VerifyError, VerifyReport, PROOF_VERSION};
use utils::serialization::{ProofBytes, WitnessBlob};

pub use air::example::{
    lfsr::PublicInputs as LfsrPublicInputs, LfsrAir as ExampleLfsrAir,
    LfsrTraceBuilder as ExampleLfsrTraceBuilder,
};
pub use air::traits::{
    Air as AirContract, BoundaryBuilder as AirBoundaryBuilder,
    BoundaryConstraint as AirBoundaryConstraint, Constraint as AirConstraint,
    Evaluator as AirEvaluator, PolyExpr as AirPolyExpr, PublicInputsCodec as AirPublicInputsCodec,
    TraceBuilder as AirTraceBuilder,
};
pub use air::types::{
    AirError, BoundaryAt, DegreeBounds, LdeOrder, PublicFieldMeta, PublicFieldType, PublicSpec,
    SerKind, TraceColMeta, TraceData, TraceRole, TraceSchema,
};

/// Result type used throughout the library to surface deterministic errors.
pub type StarkResult<T> = core::result::Result<T, StarkError>;

/// Error enumeration for the STARK engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StarkError {
    /// The requested feature is not yet implemented.
    NotImplemented(&'static str),
    /// The provided input failed validation checks.
    InvalidInput(&'static str),
    /// A generic error surfaced from a subsystem.
    SubsystemFailure(&'static str),
}

/// Verdict returned by verification functions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationVerdict {
    /// Proof accepted after all checks.
    Accept,
    /// Proof rejected with a documented failure class.
    Reject(VerifyError),
}

/// Generates a proof for the specified [`ProofKind`].
///
/// The function follows the canonical lifecycle:
/// 1. Bind the [`ProofSystemConfig`] and [`ProverContext`] against the declared
///    `kind`.
/// 2. Ingest the phase-2 public input layout using [`PublicInputs`].
/// 3. Absorb the witness container and execute the pipeline described in the
///    `proof::prover` module.
/// 4. Assemble the [`proof::types::Proof`] container and serialise it using the
///    canonical helpers exposed by [`proof::ser`].
///
/// No implementation logic is provided here; integrators must supply the
/// execution engine while preserving the documented order of operations.
pub fn generate_proof(
    kind: ProofKind,
    public_inputs: &PublicInputs<'_>,
    witness: WitnessBlob<'_>,
    config: &ProofSystemConfig,
    prover_context: &ProverContext,
) -> StarkResult<ProofBytes> {
    if kind != public_inputs.kind() {
        return Err(StarkError::InvalidInput("proof_kind_mismatch"));
    }

    let envelope = prover::build_envelope(public_inputs, witness, config, prover_context)
        .map_err(map_prover_error)?;
    let bytes = envelope.to_bytes().map_err(map_serialization_error)?;
    Ok(ProofBytes::new(bytes))
}

/// Verifies a single proof and returns a [`VerificationVerdict`].
///
/// The verification logic MUST execute the steps described in the
/// `proof::verifier` module. The `config` and `verifier_context`
/// parameters must match the ones used by the prover; otherwise
/// [`proof::types::VerifyError::ParamsHashMismatch`] is expected.
pub fn verify_proof(
    kind: ProofKind,
    public_inputs: &PublicInputs<'_>,
    proof_bytes: &ProofBytes,
    config: &ProofSystemConfig,
    verifier_context: &VerifierContext,
) -> StarkResult<VerificationVerdict> {
    if kind != public_inputs.kind() {
        return Err(StarkError::InvalidInput("proof_kind_mismatch"));
    }

    let declared_kind = map_public_to_config_kind(kind);
    match proof::verifier::verify_proof_bytes(
        declared_kind,
        public_inputs,
        proof_bytes,
        config,
        verifier_context,
    ) {
        Ok(report) => Ok(match report.error {
            None => VerificationVerdict::Accept,
            Some(error) => VerificationVerdict::Reject(error),
        }),
        Err(error) => Err(map_verify_error(error)),
    }
}

/// Verifies a batch of proofs under a shared block context.
///
/// Implementations must follow the aggregation rules documented in the
/// `proof::aggregation` module. The returned outcome records
/// whether all proofs were accepted and, in case of failures, which
/// [`proof::types::VerifyError`] triggered the rejection.
pub fn batch_verify(
    block_context: &proof::aggregation::BlockContext,
    proofs: &[BatchProofRecord<'_>],
    config: &ProofSystemConfig,
    verifier_context: &VerifierContext,
) -> StarkResult<BatchVerificationOutcome> {
    for record in proofs {
        if record.kind != record.public_inputs.kind() {
            return Err(StarkError::InvalidInput("proof_kind_mismatch"));
        }
    }

    let outcome = aggregation::batch_verify(block_context, proofs, config, verifier_context);
    Ok(outcome)
}

/// Convenience helper describing the canonical proof envelope layout.
pub fn proof_envelope_spec() -> &'static str {
    "See proof::types::Proof and proof::ser for the canonical layout implementation."
}

fn map_prover_error(error: prover::ProverError) -> StarkError {
    use prover::ProverError;

    match error {
        ProverError::UnsupportedProofVersion(_) => {
            StarkError::InvalidInput("unsupported_proof_version")
        }
        ProverError::ParamDigestMismatch => {
            StarkError::InvalidInput("prover_param_digest_mismatch")
        }
        ProverError::MalformedWitness(reason) => StarkError::InvalidInput(reason),
        ProverError::Transcript(_) => StarkError::SubsystemFailure("prover_transcript_error"),
        ProverError::Fri(_) => StarkError::SubsystemFailure("prover_fri_error"),
        ProverError::Air(_) => StarkError::SubsystemFailure("prover_air_error"),
        ProverError::Merkle(_) => StarkError::SubsystemFailure("prover_merkle_error"),
        ProverError::ProofTooLarge { .. } => StarkError::InvalidInput("proof_too_large"),
        ProverError::Serialization(kind) => {
            map_serialization_error(SerError::invalid_value(kind, "prover_serialization"))
        }
    }
}

fn map_serialization_error(error: SerError) -> StarkError {
    let reason = match error.kind() {
        SerializationKind::Proof => "proof_serialization_error",
        SerializationKind::TraceCommitment => "trace_commitment_serialization_error",
        SerializationKind::CompositionCommitment => "composition_commitment_serialization_error",
        SerializationKind::Fri => "fri_serialization_error",
        SerializationKind::Openings => "openings_serialization_error",
        SerializationKind::Telemetry => "telemetry_serialization_error",
        SerializationKind::PublicInputs => "public_inputs_serialization_error",
        SerializationKind::Params => "params_serialization_error",
    };
    StarkError::SubsystemFailure(reason)
}

fn map_verify_error(error: VerifyError) -> StarkError {
    match error {
        VerifyError::VersionMismatch { .. } => StarkError::InvalidInput("version_mismatch"),
        VerifyError::UnknownProofKind(_) => StarkError::InvalidInput("unknown_proof_kind"),
        VerifyError::HeaderLengthMismatch { .. } => {
            StarkError::InvalidInput("header_length_mismatch")
        }
        VerifyError::BodyLengthMismatch { .. } => StarkError::InvalidInput("body_length_mismatch"),
        VerifyError::UnexpectedEndOfBuffer(_) => {
            StarkError::InvalidInput("unexpected_end_of_buffer")
        }
        VerifyError::IntegrityDigestMismatch => {
            StarkError::InvalidInput("integrity_digest_mismatch")
        }
        VerifyError::InvalidFriSection(_) => StarkError::InvalidInput("invalid_fri_section"),
        VerifyError::NonCanonicalFieldElement => {
            StarkError::InvalidInput("non_canonical_field_element")
        }
        VerifyError::ParamsHashMismatch => StarkError::InvalidInput("param_digest_mismatch"),
        VerifyError::PublicInputMismatch => StarkError::InvalidInput("public_input_mismatch"),
        VerifyError::TranscriptOrder => StarkError::InvalidInput("transcript_order"),
        VerifyError::OutOfDomainInvalid => StarkError::InvalidInput("out_of_domain_invalid"),
        VerifyError::UnsupportedMerkleScheme => {
            StarkError::InvalidInput("unsupported_merkle_scheme")
        }
        VerifyError::MerkleVerifyFailed { section } => match section {
            MerkleSection::CommitmentDigest => StarkError::InvalidInput("merkle_commitment_digest"),
            MerkleSection::FriRoots => StarkError::InvalidInput("merkle_fri_roots"),
            MerkleSection::FriPath => StarkError::InvalidInput("merkle_fri_path"),
            MerkleSection::TraceCommit => StarkError::InvalidInput("merkle_trace_commit"),
            MerkleSection::CompositionCommit => {
                StarkError::InvalidInput("merkle_composition_commit")
            }
        },
        VerifyError::TraceLeafMismatch => StarkError::InvalidInput("trace_leaf_mismatch"),
        VerifyError::CompositionLeafMismatch => {
            StarkError::InvalidInput("composition_leaf_mismatch")
        }
        VerifyError::TraceOodMismatch => StarkError::InvalidInput("trace_ood_mismatch"),
        VerifyError::CompositionOodMismatch => StarkError::InvalidInput("composition_ood_mismatch"),
        VerifyError::FriVerifyFailed { issue } => match issue {
            FriVerifyIssue::QueryOutOfRange => StarkError::InvalidInput("fri_query_out_of_range"),
            FriVerifyIssue::PathInvalid => StarkError::InvalidInput("fri_path_invalid"),
            FriVerifyIssue::LayerMismatch => StarkError::InvalidInput("fri_layer_mismatch"),
            FriVerifyIssue::SecurityLevelMismatch => {
                StarkError::InvalidInput("fri_security_level_mismatch")
            }
            FriVerifyIssue::LayerBudgetExceeded => {
                StarkError::InvalidInput("fri_layer_budget_exceeded")
            }
            FriVerifyIssue::EmptyCodeword => StarkError::InvalidInput("fri_empty_codeword"),
            FriVerifyIssue::VersionMismatch => StarkError::InvalidInput("fri_version_mismatch"),
            FriVerifyIssue::QueryBudgetMismatch => {
                StarkError::InvalidInput("fri_query_budget_mismatch")
            }
            FriVerifyIssue::FoldingConstraint => StarkError::InvalidInput("fri_folding_constraint"),
            FriVerifyIssue::OodsInvalid => StarkError::InvalidInput("fri_oods_invalid"),
            FriVerifyIssue::Generic => StarkError::InvalidInput("fri_generic_failure"),
        },
        VerifyError::DegreeBoundExceeded => StarkError::InvalidInput("degree_bound_exceeded"),
        VerifyError::ProofTooLarge => StarkError::InvalidInput("proof_too_large"),
        VerifyError::EmptyOpenings => StarkError::InvalidInput("empty_openings"),
        VerifyError::IndicesNotSorted => StarkError::InvalidInput("indices_not_sorted"),
        VerifyError::IndicesDuplicate => StarkError::InvalidInput("indices_duplicate"),
        VerifyError::IndicesMismatch => StarkError::InvalidInput("indices_mismatch"),
        VerifyError::AggregationDigestMismatch => {
            StarkError::InvalidInput("aggregation_digest_mismatch")
        }
        VerifyError::Serialization(_) => StarkError::InvalidInput("serialization_error"),
        VerifyError::DeterministicHash(_) => {
            StarkError::SubsystemFailure("deterministic_hash_error")
        }
    }
}
