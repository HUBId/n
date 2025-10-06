//! Deterministic verifier skeleton.
//!
//! The real verifier mirrors the prover pipeline by replaying the transcript,
//! recomputing Fiat–Shamir challenges and validating the FRI proof.  This
//! placeholder exposes the public API so downstream consumers can depend on the
//! interfaces while the implementation is developed.

use crate::config::{
    AirSpecId, ProofKind as ConfigProofKind, ProofKindLayout, ProofSystemConfig, VerifierContext,
};
use crate::fri::types::{FriError, FriSecurityLevel};
use crate::proof::public_inputs::PublicInputs;
use crate::proof::transcript::TranscriptBlockContext;
use crate::proof::types::{Proof, VerifyError, VerifyReport};
use crate::utils::serialization::ProofBytes;

/// Specification describing the single-proof verification flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SingleVerifySpec;

impl SingleVerifySpec {
    /// Ordered sequence of the verification steps.
    pub const STEPS: &'static [&'static str] = &["decode", "precheck", "fri_verify", "report"];
}

/// Skeleton implementation of the single-proof verifier.
pub fn verify(
    _declared_kind: ConfigProofKind,
    _public_inputs: &PublicInputs<'_>,
    _proof_bytes: &ProofBytes,
    _config: &ProofSystemConfig,
    _context: &VerifierContext,
) -> Result<VerifyReport, VerifyError> {
    todo!("verify is not implemented yet")
}

/// Result of the structural pre-checks performed before FRI verification.
#[derive(Debug, Clone)]
pub(crate) struct PrecheckedProof {
    /// Fully decoded proof container.
    pub(crate) proof: Proof,
    /// Derived FRI seed.
    pub(crate) fri_seed: [u8; 32],
    /// Security level advertised by the profile.
    pub(crate) security_level: FriSecurityLevel,
}

/// Performs structural checks on the serialized proof before FRI verification.
pub(crate) fn precheck_proof_bytes(
    _declared_kind: ConfigProofKind,
    _public_inputs: &PublicInputs<'_>,
    _proof_bytes: &ProofBytes,
    _config: &ProofSystemConfig,
    _context: &VerifierContext,
    _block_context: Option<&TranscriptBlockContext>,
) -> Result<PrecheckedProof, VerifyError> {
    todo!("precheck_proof_bytes is not implemented yet")
}

/// Executes the FRI verification stage for a prechecked proof.
pub(crate) fn execute_fri_stage(_proof: &PrecheckedProof) -> Result<(), VerifyError> {
    todo!("execute_fri_stage is not implemented yet")
}

/// Helper exposing the encode rules for [`ConfigProofKind`].
pub fn encode_proof_kind(_kind: ConfigProofKind) -> u8 {
    todo!("encode_proof_kind is not implemented yet")
}

/// Resolves the AIR specification identifier from the layout.
pub fn resolve_air_spec_id(
    _layout: &ProofKindLayout<AirSpecId>,
    _kind: ConfigProofKind,
) -> AirSpecId {
    todo!("resolve_air_spec_id is not implemented yet")
}

/// Maps a FRI error into the public [`VerifyError`] variants.
pub fn map_fri_error(_error: FriError) -> VerifyError {
    todo!("map_fri_error is not implemented yet")
}

/// Placeholder for future telemetry validation.
pub fn validate_telemetry(_proof: &Proof) -> Result<(), VerifyError> {
    todo!("validate_telemetry is not implemented yet")
}
