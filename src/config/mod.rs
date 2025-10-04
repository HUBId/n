//! Configuration module for the `rpp-stark` engine.
//!
//! The items in this module only document the configuration surface. They are
//! intentionally void of executable logic but capture the design intent and
//! naming conventions for downstream implementers.

use crate::utils::serialization::DigestBytes;

/// Maximum admissible size for any serialized proof (including envelope).
///
/// Verifiers MUST reject proofs exceeding this bound to preserve deterministic
/// resource usage and to avoid unbounded allocations during streaming.
pub const MAX_PROOF_SIZE_BYTES: usize = 32 * 1024 * 1024;

/// Profiles tuning the trade-off between throughput and security.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PerformanceProfile {
    /// Balanced defaults optimised for low-latency proving on consumer
    /// hardware.
    Standard,
    /// Emphasises security margins by increasing query budgets and digest
    /// sizes.
    HighSecurity,
    /// Optional profile that prioritises batch throughput at the cost of
    /// higher memory pressure.
    HighThroughput,
}

/// Rules describing how the prover/verifier may parallelise work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParallelizationRules {
    /// Maximum number of host threads made available to the runtime.
    pub max_threads: usize,
    /// Minimum chunk size (in field elements) that should be scheduled per
    /// worker.
    pub min_chunk_size: usize,
    /// Maximum chunk size tolerated before splitting work units.
    pub max_chunk_size: usize,
}

/// Security goals attached to a configuration profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecurityGoals {
    /// Maximum number of queries the verifier may consume before exhausting
    /// its deterministic budget.
    pub query_budget: u32,
    /// Bit-length of the transcript digest binding the protocol state.
    pub digest_length_bits: u16,
    /// Optional limit on witness disclosure events.
    pub witness_extraction_budget: u16,
}

/// Describes how integrity digests are parameterised.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntegrityParameters {
    /// Domain separation tag for the transcript hash.
    pub domain_tag: &'static str,
    /// Optional preimage bound used in higher level protocol composition.
    pub upper_bound: Option<DigestBytes>,
}

/// Shared configuration between prover and verifier specifying the evaluation
/// domain and profile choices.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StarkConfig {
    /// Selected performance profile.
    pub profile: PerformanceProfile,
    /// Negotiated security goals.
    pub security: SecurityGoals,
    /// Integrity parameters used by transcript hashing.
    pub integrity: IntegrityParameters,
}

/// Context used by the prover to drive proof generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProverContext {
    /// Baseline configuration shared with the verifier.
    pub stark: StarkConfig,
    /// Runtime parallelisation rules derived from the host environment.
    pub parallelization: ParallelizationRules,
}

/// Context used by the verifier to execute deterministic verification logic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifierContext {
    /// Baseline configuration shared with the prover.
    pub stark: StarkConfig,
    /// Security policy enforced during verification (e.g. VRF sampling).
    pub security: SecurityGoals,
}
