//! Configuration module for the `rpp-stark` engine.
//! Provides strongly typed contexts used to parameterize proof generation and verification.

use crate::field::prime_field::Modulus;
use crate::{fri::config::FriProfile, hash::config::HashParameters};

/// Shared configuration between prover and verifier specifying the evaluation domain and FRI setup.
#[derive(Debug, Clone)]
pub struct StarkConfig {
    /// The size of the trace domain.
    pub trace_length: usize,
    /// Field modulus configuration.
    pub field_modulus: Modulus,
    /// FRI profile describing folding strategy and sampling queries.
    pub fri: FriProfile,
    /// Hash configuration for commitments and transcripts.
    pub hash: HashParameters,
}

impl StarkConfig {
    /// Validates the configuration and produces a deterministic error on failure.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.trace_length == 0 {
            return Err("trace length must be non-zero");
        }
        if !self.field_modulus.is_prime {
            return Err("field modulus must be prime");
        }
        Ok(())
    }
}

/// Context used by the prover to drive proof generation.
#[derive(Debug, Clone)]
pub struct ProverContext {
    /// Global STARK configuration shared with the verifier.
    pub stark: StarkConfig,
    /// Optional thread count for deterministic batching.
    pub max_threads: usize,
}

impl ProverContext {
    /// Constructs a new prover context with deterministic defaults.
    pub fn new(stark: StarkConfig) -> Self {
        Self {
            stark,
            max_threads: 1,
        }
    }
}

/// Context used by the verifier to execute deterministic verification logic.
#[derive(Debug, Clone)]
pub struct VerifierContext {
    /// Global STARK configuration shared with the prover.
    pub stark: StarkConfig,
    /// Number of sampling queries performed during verification.
    pub query_count: usize,
}

impl VerifierContext {
    /// Constructs a new verifier context.
    pub fn new(stark: StarkConfig) -> Self {
        Self {
            stark,
            query_count: 0,
        }
    }
}
