//! Proof generation and verification subsystem.
//! Provides embedded prover and verifier implementations for the STARK engine.

pub mod prover;
pub mod verifier;

pub use prover::Prover;
pub use verifier::Verifier;
