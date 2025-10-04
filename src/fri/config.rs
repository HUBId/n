//! Canonical configuration descriptions for the FRI protocol.
//! Provides named profiles that are shared between prover and verifier.

/// Canonical digest representation for a FRI parameter set.
///
/// The digest is computed over the canonical serialization of the
/// folding factor, query schedule, and target depth using BLAKE3.
/// The hexadecimal strings exposed below allow integrators to pin
/// protocol parameters without embedding executable verification logic.
pub type ParameterDigest = &'static str;

/// Describes a complete FRI profile that can be referenced by the
/// STARK configuration and transcript builders.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FriProfile {
    /// Human readable profile identifier.
    pub name: &'static str,
    /// Folding factor applied to each layer; we only expose quartic
    /// folding in this module.
    pub folding_factor: usize,
    /// Number of sampling queries performed by the verifier.
    pub query_count: usize,
    /// Target depth (logarithmic size) of the final layer after folding.
    pub target_depth: usize,
    /// Digest binding the profile to a concrete transcript layout.
    pub parameter_digest: ParameterDigest,
}

/// Standard security profile targeting typical rollup deployments.
pub const STANDARD_FRI_PROFILE: FriProfile = FriProfile {
    name: "standard",
    folding_factor: 4,
    query_count: 64,
    target_depth: 6,
    parameter_digest: "31d7f096bd7cf0ebc5d4d88dbcccf20ebb6a520fe52b39cac3d1a1a0f1d5e2aa",
};

/// High security profile with an increased query budget.
pub const HISEC_FRI_PROFILE: FriProfile = FriProfile {
    name: "hisec",
    folding_factor: 4,
    query_count: 96,
    target_depth: 8,
    parameter_digest: "8f44b61cfe2b67ab681a2a19d4e9febb0e5bc2b1de9a5596d1f52e8f8e0cd5a4",
};
