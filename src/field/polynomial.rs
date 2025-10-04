//! Polynomial utilities operating over the prime field.
//! The module provides deterministic arithmetic for trace and constraint polynomials.

use super::FieldElement;

/// Dense polynomial represented by coefficients in ascending order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Polynomial {
    /// Coefficients starting from the constant term.
    pub coefficients: Vec<FieldElement>,
}

impl Polynomial {
    /// Constructs a polynomial from raw coefficients.
    pub fn new(coefficients: Vec<FieldElement>) -> Self {
        Self { coefficients }
    }

    /// Evaluates the polynomial at the provided point using Horner's method.
    pub fn evaluate(&self, point: FieldElement) -> FieldElement {
        let mut result = FieldElement::zero();
        for coeff in self.coefficients.iter().rev() {
            result = result.mul(point).add(*coeff);
        }
        result
    }

    /// Returns the degree of the polynomial or `None` if the polynomial is zero.
    pub fn degree(&self) -> Option<usize> {
        for (idx, coeff) in self.coefficients.iter().enumerate().rev() {
            if coeff.as_u64() != 0 {
                return Some(idx);
            }
        }
        None
    }
}
