//! FRI commitment scheme primitives.
//! Provides folding strategies, proof representation, and batch verification utilities.

pub mod batch;
pub mod config;
pub mod folding;
pub mod proof;

pub use batch::FriBatch;
pub use folding::{FriFolding, FriLayer};
pub use proof::{FriProof, FriQuery};
