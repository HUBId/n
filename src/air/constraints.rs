//! Constraint traits describing the AIR interface.
//! Applications implement these traits to define algebraic constraints.

use crate::field::FieldElement;

/// Trait representing the Algebraic Intermediate Representation for a computation.
pub trait Air {
    /// Returns the number of registers in the execution trace.
    fn trace_width(&self) -> usize;
    /// Returns the transition constraint evaluator.
    fn transition(&self) -> &dyn ConstraintEvaluator;
    /// Returns the boundary constraint evaluator.
    fn boundary(&self) -> &dyn ConstraintEvaluator;
}

/// Trait implemented by deterministic constraint evaluators.
pub trait ConstraintEvaluator {
    /// Evaluates constraints at the provided step and returns the resulting values.
    fn evaluate(&self, step: usize, registers: &[FieldElement]) -> Vec<FieldElement>;
}
