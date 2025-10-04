//! Proof generation and verification subsystem.
//!
//! This module hierarchy documents the contracts for the complete
//! proof lifecycle without providing executable logic. Every struct or enum
//! captures layout, ordering or identifier information required to integrate
//! with the `rpp-stark` ecosystem.

pub mod aggregation;
pub mod api;
pub mod envelope;
pub mod errors;
pub mod prover;
pub mod public_inputs;
pub mod transcript;
pub mod verifier;

pub use aggregation::{BatchProofRecord, BatchVerificationOutcome, BlockContext};
pub use errors::VerificationFailure;
pub use public_inputs::ProofKind;
