//! # Proof module overview
//!
//! ```text
//! proof
//! ├── types      — canonical data models such as [`types::Proof`]
//! ├── ser        — serialization helpers exposing public function signatures
//! ├── envelope   — envelope builder scaffolding around [`types::Proof`]
//! └── verifier   — verification contracts exporting [`verifier::verify`]
//! ```
//!
//! The module currently provides type definitions and API shells that mirror the
//! specification. Implementations intentionally use `todo!()` so downstream
//! consumers can plug in real logic without altering the public surface.

pub mod envelope;
pub mod ser;
pub mod types;
pub mod verifier;

pub(crate) mod aggregation;
pub(crate) mod api;
pub mod prover;
pub mod public_inputs;
pub mod transcript;

pub use public_inputs::ProofKind;
pub use types::{
    FriTelemetry, MerkleProofBundle, Openings, Proof, Telemetry, VerifyError, VerifyReport,
    PROOF_VERSION,
};
pub use verifier::verify;
