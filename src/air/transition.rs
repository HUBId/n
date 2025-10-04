//! Transition constraint helpers.
//! Contains deterministic evaluation logic used across AIR implementations.

use crate::field::FieldElement;

/// Transition constraint representation storing evaluation coefficients.
#[derive(Debug, Clone)]
pub struct TransitionConstraint {
    /// Coefficients of the constraint polynomial.
    pub coefficients: Vec<FieldElement>,
}

impl TransitionConstraint {
    /// Constructs a new transition constraint.
    pub fn new(coefficients: Vec<FieldElement>) -> Self {
        Self { coefficients }
    }

    /// Evaluates the transition constraint at the provided state.
    pub fn evaluate(&self, registers: &[FieldElement]) -> FieldElement {
        let mut acc = FieldElement::zero();
        for (coeff, reg) in self.coefficients.iter().zip(registers.iter()) {
            acc = acc.add(coeff.mul(*reg));
        }
        acc
    }
}
