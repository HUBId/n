//! FRI commitment scheme descriptors.
//! Provides configuration profiles, folding schedules, proof metadata, and batching APIs.

pub mod batch;
pub mod config;
pub mod folding;
pub mod proof;

pub use batch::{BatchDigest, BatchQueryPosition, BatchSeed, FriBatch, FriBatchVerificationApi};
pub use folding::{FoldingLayer, FoldingLayout, LayerCommitment, QuarticFriFolding, QUARTIC_FOLD};
pub use proof::{FriProof, FriProofDescriptor, OpeningSequence, QueryMapping};
