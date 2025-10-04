//! Proof generation and verification subsystem.
//! Provides embedded prover and verifier interfaces for the STARK engine.

pub mod api;
pub mod envelope;
pub mod prover;
pub mod public_inputs;
pub mod transcript;
pub mod verifier;

pub use api::{generate_proof, verify_proof, ProofRequest, ProofResponse};
pub use envelope::{ProofEnvelope, ProofEnvelopeHeader};
pub use prover::Prover;
pub use public_inputs::{ProofKind, PublicInputs};
pub use verifier::Verifier;
