//! Algebraic Intermediate Representation (AIR) module.
//! Provides traits for defining transition and boundary constraints used in STARK proofs.

pub mod boundary;
pub mod constraints;
pub mod transition;

pub use constraints::{Air, ConstraintEvaluator};
