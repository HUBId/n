use crate::config::{ProfileConfig, PROFILE_HIGH_SECURITY_CONFIG, PROFILE_STANDARD_CONFIG};
use crate::params::{FriFolding, HashKind, LdeOrder, StarkParams, StarkParamsBuilder};

/// Returns the canonical Stark parameter set shared by prover and verifier.
///
/// The current implementation relies on the deterministic profile used by the
/// built-in prover.  Both parties fix the hashing backend to Blake2s and commit
/// to single-field-element Merkle leaves.  The helper mirrors the prover
/// configuration so callers can rely on identical Merkle framing without
/// leaking the builder details elsewhere in the crate.
pub fn canonical_stark_params(profile: &ProfileConfig) -> StarkParams {
    let mut builder = StarkParamsBuilder::new();
    builder.hash = HashKind::Blake2s { digest_size: 32 };
    builder.merkle.leaf_width = 1;
    builder.lde.blowup = profile.lde_factor as u32;
    builder.fri.queries = profile.fri_queries;
    builder.fri.domain_log2 = profile.fri_depth_range.max as u16;
    builder.fri.num_layers = profile
        .fri_depth_range
        .max
        .saturating_sub(profile.fri_depth_range.min)
        .saturating_add(1);

    if profile.id == PROFILE_HIGH_SECURITY_CONFIG.id {
        builder.lde.order = LdeOrder::ColMajor;
        builder.fri.folding = FriFolding::Coset;
    } else if profile.id == PROFILE_STANDARD_CONFIG.id {
        builder.lde.order = LdeOrder::RowMajor;
        builder.fri.folding = FriFolding::Natural;
    }

    builder
        .build()
        .expect("canonical Stark parameters must be valid")
}
