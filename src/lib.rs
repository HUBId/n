//! Core library entry point for the `rpp-stark` proof system.
//! This module exposes the high-level and low-level APIs for proof generation and verification.

pub mod air;
pub mod config;
pub mod fft;
pub mod field;
pub mod fri;
pub mod hash;
pub mod proof;
pub mod utils;

use proof::{prover::Prover, verifier::Verifier};
use utils::serialization::ProofBytes;

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

/// High-level interface for proof generation.
pub fn generate_proof(context: &config::ProverContext) -> StarkResult<ProofBytes> {
    let prover = Prover::new(context.clone());
    prover.create_proof()
}

/// High-level interface for proof verification.
pub fn verify_proof(context: &config::VerifierContext, proof: &ProofBytes) -> StarkResult<bool> {
    let verifier = Verifier::new(context.clone());
    verifier.verify(proof)
}
