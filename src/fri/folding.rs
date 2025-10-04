//! FRI folding strategy definitions.
//! Provides deterministic folding operations for polynomial commitments.

use crate::field::FieldElement;
use crate::{StarkError, StarkResult};

/// Represents a single layer in the FRI folding process.
#[derive(Debug, Clone)]
pub struct FriLayer {
    /// Evaluation points at the current layer.
    pub evaluations: Vec<FieldElement>,
}

/// Deterministic folding operator.
#[derive(Debug, Clone)]
pub struct FriFolding {
    /// Folding factor applied at each layer.
    pub folding_factor: usize,
}

impl FriFolding {
    /// Creates a new folding descriptor.
    pub fn new(folding_factor: usize) -> Self {
        Self { folding_factor }
    }

    /// Performs a single folding step, reducing the number of evaluations.
    pub fn fold(&self, layer: &FriLayer) -> StarkResult<FriLayer> {
        if self.folding_factor == 0 {
            return Err(StarkError::InvalidInput("folding factor must be non-zero"));
        }
        if layer.evaluations.len() % self.folding_factor != 0 {
            return Err(StarkError::InvalidInput(
                "evaluations length must be divisible by folding factor",
            ));
        }
        let mut next = Vec::with_capacity(layer.evaluations.len() / self.folding_factor);
        for chunk in layer.evaluations.chunks(self.folding_factor) {
            let mut acc = FieldElement::zero();
            for value in chunk {
                acc = acc.add(*value);
            }
            next.push(acc);
        }
        Ok(FriLayer { evaluations: next })
    }
}
