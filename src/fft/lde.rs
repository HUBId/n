//! Low-degree extension routines for the evaluation domain.
//! Performs deterministic polynomial extension over multiplicative cosets.

use crate::field::{polynomial::Polynomial, FieldElement};
use crate::StarkError;
use crate::StarkResult;

/// Deterministic descriptor for LDE operations.
#[derive(Debug, Clone)]
pub struct LowDegreeExtension {
    /// Target domain size after extension.
    pub blowup_factor: usize,
}

impl LowDegreeExtension {
    /// Creates a new LDE descriptor.
    pub fn new(blowup_factor: usize) -> Self {
        Self { blowup_factor }
    }

    /// Executes the low-degree extension, returning the evaluations over the expanded domain.
    pub fn extend(&self, polynomial: &Polynomial) -> StarkResult<Vec<FieldElement>> {
        if self.blowup_factor == 0 {
            return Err(StarkError::InvalidInput("blowup factor must be non-zero"));
        }
        // Placeholder deterministic implementation using naive evaluation.
        let domain_size = polynomial.coefficients.len() * self.blowup_factor;
        let mut result = Vec::with_capacity(domain_size);
        for i in 0..domain_size {
            let point = FieldElement::new(i as u64);
            result.push(polynomial.evaluate(point));
        }
        Ok(result)
    }
}
