//! Global configuration and context descriptors for the `rpp-stark` proof
//! engine.
//!
//! The declarations in this module only expose contracts and identifiers.
//! Implementations are intentionally omitted so that integrators can supply
//! their own runtime while inheriting the canonical documentation for
//! determinism, parameter pinning and resource limits.

use crate::utils::serialization::DigestBytes;

/// Canonical digest binding all protocol parameters for a given profile.
///
/// The digest MUST be computed over the following little-endian encoded
/// sequence:
/// 1. `field_id:u16`
/// 2. [`PoseidonParamId::to_le_bytes`]
/// 3. `lde_factor:u32`
/// 4. [`FriPlanId::to_le_bytes`]
/// 5. `query_budget:u32`
/// 6. [`MerkleSchemeId::to_le_bytes`]
/// 7. [`TranscriptVersionId::to_le_bytes`]
/// 8. [`AirSpecId::to_le_bytes`]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParamDigest(pub DigestBytes);

/// Identifier for Poseidon parameter sets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoseidonParamId(pub u16);

impl PoseidonParamId {
    /// Returns the canonical little-endian representation of the identifier.
    pub const fn to_le_bytes(self) -> [u8; 2] {
        self.0.to_le_bytes()
    }
}

/// Identifier for transcript versions (Phase 3 binding).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TranscriptVersionId(pub u8);

impl TranscriptVersionId {
    /// Returns the little-endian encoding of the identifier.
    pub const fn to_le_bytes(self) -> [u8; 1] {
        [self.0]
    }
}

/// Identifier for Merkle scheme variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MerkleSchemeId(pub u16);

impl MerkleSchemeId {
    /// Returns the little-endian encoding of the identifier.
    pub const fn to_le_bytes(self) -> [u8; 2] {
        self.0.to_le_bytes()
    }
}

/// Identifier for FRI folding plans.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FriPlanId(pub u16);

impl FriPlanId {
    /// Returns the little-endian encoding of the identifier.
    pub const fn to_le_bytes(self) -> [u8; 2] {
        self.0.to_le_bytes()
    }
}

/// Identifier for AIR (algebraic intermediate representation) specifications.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AirSpecId(pub u16);

impl AirSpecId {
    /// Returns the little-endian encoding of the identifier.
    pub const fn to_le_bytes(self) -> [u8; 2] {
        self.0.to_le_bytes()
    }
}

/// Identifier describing the deterministic thread pool selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreadPoolProfile {
    /// Exactly one worker executes all tasks sequentially.
    SingleThread,
    /// Fixed number of workers with static round-robin scheduling.
    FixedStatic { worker_count: u8 },
}

/// Chunking strategy used when splitting trace or query workloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkingPolicy {
    /// Minimum number of field elements assigned to a worker.
    pub min_chunk_items: u32,
    /// Maximum number of field elements assigned to a worker.
    pub max_chunk_items: u32,
    /// Explicit stride (in elements) used when slicing evaluation domains.
    pub stride: u32,
}

/// Profile describing the overall security/performance target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    /// Balanced defaults designed for general rollup proving.
    Standard,
    /// High security profile increasing LDE and query budgets.
    HighSecurity,
}

/// Hard resource limits shared between prover and verifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResourceLimits {
    /// Maximum serialized proof size in bytes.
    pub max_proof_size_bytes: u32,
    /// Maximum number of FRI layers allowed for any proof.
    pub max_layers: u8,
    /// Maximum number of FRI queries per proof.
    pub max_queries: u16,
    /// Maximum trace width (number of columns) per proof kind.
    pub max_trace_width: u32,
    /// Maximum number of trace steps per proof kind.
    pub max_trace_steps: u32,
}

/// Deterministic domains negotiated for the prover pipeline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainParameters {
    /// Multiplicative low-degree extension factor.
    pub lde_factor: u32,
    /// Vector of evaluation domain sizes per register group.
    pub register_domain_sizes: Vec<u32>,
}

/// Context required by the prover to execute the deterministic pipeline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProverContext {
    /// Digest pinning all parameters for the current profile.
    pub param_digest: ParamDigest,
    /// Poseidon parameter identifier (Phase 2 binding).
    pub poseidon_param_id: PoseidonParamId,
    /// Transcript version identifier (Phase 3 binding).
    pub transcript_version_id: TranscriptVersionId,
    /// Merkle commitment scheme identifier.
    pub merkle_scheme_id: MerkleSchemeId,
    /// FRI plan identifier (Phase 4 binding).
    pub fri_plan_id: FriPlanId,
    /// AIR specification identifier (Phase 2 binding).
    pub air_spec_id: AirSpecId,
    /// Deterministic low-degree extension factor and domain sizes.
    pub domains: DomainParameters,
    /// Thread pool description (no work stealing).
    pub thread_pool: ThreadPoolProfile,
    /// Chunking policy used throughout the pipeline.
    pub chunking: ChunkingPolicy,
    /// Selected profile (standard or high security).
    pub profile: Profile,
    /// Resource limits enforced by the prover before entering heavy phases.
    pub limits: ResourceLimits,
}

/// Deterministic counters optionally collected by the verifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeterministicMetrics {
    /// Number of hashes performed while validating a proof.
    pub hash_invocations: u64,
    /// Number of field operations performed.
    pub field_operations: u64,
}

/// Context used by the verifier when replaying proofs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifierContext {
    /// Digest pinning all parameters for the current profile.
    pub param_digest: ParamDigest,
    /// Poseidon parameter identifier (for transcript reconstruction).
    pub poseidon_param_id: PoseidonParamId,
    /// Transcript version identifier (Phase 3 binding).
    pub transcript_version_id: TranscriptVersionId,
    /// Merkle commitment scheme identifier.
    pub merkle_scheme_id: MerkleSchemeId,
    /// FRI plan identifier (Phase 4 binding).
    pub fri_plan_id: FriPlanId,
    /// AIR specification identifier (Phase 2 binding).
    pub air_spec_id: AirSpecId,
    /// Hard resource limits validated before expensive checks.
    pub limits: ResourceLimits,
    /// Selected verification profile.
    pub profile: Profile,
    /// Optional deterministic counters (no timestamps allowed).
    pub metrics: Option<DeterministicMetrics>,
}

/// Shared configuration struct referencing profiles and parameter IDs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofSystemConfig {
    /// Parameter digest that must match prover/verifier contexts.
    pub param_digest: ParamDigest,
    /// Selected profile for both prover and verifier.
    pub profile: Profile,
    /// Resource limits that must be documented in user-facing manuals.
    pub limits: ResourceLimits,
}

impl ProofSystemConfig {
    /// Returns a short textual description of the configuration scope.
    pub const DESCRIPTION: &'static str =
        "Phase2-5 parameter pinning; any change requires new ParamDigest";
}

/// Default maximum proof size applied across the system.
pub const MAX_PROOF_SIZE_BYTES: u32 = 32 * 1024 * 1024;

/// Default maximum number of FRI queries permitted per proof.
pub const MAX_FRI_QUERIES: u16 = 128;

/// Default maximum number of FRI layers for the recursive folding.
pub const MAX_FRI_LAYERS: u8 = 16;
