//! Serialization utilities for proofs and transcripts.
//! Provides deterministic byte representations for cross-component communication.

/// Wrapper around proof bytes ensuring explicit conversions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofBytes {
    /// Raw proof representation.
    bytes: Vec<u8>,
}

impl ProofBytes {
    /// Creates a new proof byte container.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Returns the underlying byte slice.
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }
}
