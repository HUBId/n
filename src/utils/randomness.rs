//! Deterministic randomness generation based on Blake3 transcripts.
//! Provides a reproducible RNG for sampling queries and challenges.

use crate::hash::config::Blake3Parameters;
use crate::hash::Blake3Hasher;
use crate::{StarkError, StarkResult};

/// Deterministic random number generator derived from Blake3.
#[derive(Debug, Clone)]
pub struct DeterministicRng {
    /// Underlying hasher used to produce pseudorandom output.
    hasher: Blake3Hasher,
    /// Counter ensuring unique outputs per request.
    counter: u64,
}

impl DeterministicRng {
    /// Creates a new RNG with the provided parameters.
    pub fn new(params: Blake3Parameters) -> Self {
        Self {
            hasher: Blake3Hasher::new(params),
            counter: 0,
        }
    }

    /// Produces the next pseudorandom field element seed as 32 bytes.
    pub fn next_bytes(&mut self) -> StarkResult<[u8; 32]> {
        self.counter = self.counter.wrapping_add(1);
        let mut data = Vec::new();
        data.extend_from_slice(&self.counter.to_le_bytes());
        self.hasher.absorb(&data);
        self.hasher.finalize()
    }

    /// Reseeds the transcript with deterministic additional data.
    pub fn reseed(&mut self, seed: &[u8]) -> StarkResult<()> {
        if seed.is_empty() {
            return Err(StarkError::InvalidInput("reseed seed cannot be empty"));
        }
        self.hasher.absorb(seed);
        Ok(())
    }
}
