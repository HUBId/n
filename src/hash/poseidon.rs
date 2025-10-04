//! Poseidon hash permutation for field elements.
//! The implementation is a placeholder outlining the deterministic interface.

use super::config::PoseidonParameters;
use crate::field::FieldElement;
use crate::{StarkError, StarkResult};

/// Poseidon state representation used during hashing.
#[derive(Debug, Clone)]
pub struct PoseidonState {
    /// Current state elements.
    pub elements: Vec<FieldElement>,
    /// Poseidon parameters controlling the permutation.
    pub parameters: PoseidonParameters,
}

impl PoseidonState {
    /// Creates a new Poseidon state initialised with zero elements.
    pub fn new(parameters: PoseidonParameters) -> Self {
        let mut elements = Vec::with_capacity(parameters.width);
        elements.resize(parameters.width, FieldElement::zero());
        Self {
            elements,
            parameters,
        }
    }

    /// Absorbs field elements into the state using a deterministic sponge interface.
    pub fn absorb(&mut self, input: &[FieldElement]) {
        for (i, value) in input.iter().enumerate() {
            let index = i % self.elements.len();
            self.elements[index] = self.elements[index].add(*value);
        }
    }

    /// Applies the Poseidon permutation rounds.
    pub fn permute(&mut self) {
        for _ in 0..self.parameters.full_rounds {
            for element in &mut self.elements {
                *element = element.pow(5);
            }
        }
    }

    /// Extracts a deterministic field element from the state.
    pub fn squeeze(&mut self) -> FieldElement {
        self.permute();
        self.elements[0]
    }

    /// Convenience helper producing a hash digest from an input slice.
    pub fn hash(&mut self, input: &[FieldElement]) -> StarkResult<FieldElement> {
        if input.is_empty() {
            return Err(StarkError::InvalidInput("poseidon input cannot be empty"));
        }
        self.absorb(input);
        Ok(self.squeeze())
    }
}
