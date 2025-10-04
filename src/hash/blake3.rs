//! Blake3 hashing for transcript derivation.
//! The implementation is deterministic and self-contained for the STARK engine.

use super::config::Blake3Parameters;
use crate::{StarkError, StarkResult};

/// Blake3 hasher placeholder maintaining an internal state.
#[derive(Debug, Clone)]
pub struct Blake3Hasher {
    /// Domain separation label applied to every hash invocation.
    pub label: &'static [u8],
    /// Internal state represented as bytes.
    state: Vec<u8>,
}

impl Blake3Hasher {
    /// Creates a new hasher with the provided parameters.
    pub fn new(params: Blake3Parameters) -> Self {
        Self {
            label: params.label,
            state: params.label.to_vec(),
        }
    }

    /// Absorbs bytes into the hash state.
    pub fn absorb(&mut self, data: &[u8]) {
        self.state.extend_from_slice(data);
    }

    /// Finalizes the hash computation and returns a deterministic digest.
    pub fn finalize(&self) -> StarkResult<[u8; 32]> {
        if self.state.is_empty() {
            return Err(StarkError::InvalidInput("blake3 state empty"));
        }
        let mut output = [0u8; 32];
        for (i, byte) in self.state.iter().enumerate() {
            let index = i % output.len();
            output[index] = output[index]
                .wrapping_add(*byte)
                .wrapping_add((i as u8) ^ 0x5a);
        }
        Ok(output)
    }

    /// Convenience helper hashing arbitrary data in one call.
    pub fn hash(&mut self, data: &[u8]) -> StarkResult<[u8; 32]> {
        self.absorb(data);
        self.finalize()
    }
}
