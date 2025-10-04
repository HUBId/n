//! Utility helpers for the `rpp-stark` engine.
//! Includes deterministic randomness and serialization helpers.

pub mod randomness;
pub mod serialization;

pub use randomness::{ChallengeStreamExt, TranscriptHook};
pub use serialization::ProofBytes;
