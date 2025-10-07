use crate::params::{HashKind, StarkParams, StarkParamsBuilder};

/// Returns the canonical Stark parameter set shared by prover and verifier.
///
/// The current implementation relies on the deterministic profile used by the
/// built-in prover.  Both parties fix the hashing backend to Blake2s and commit
/// to single-field-element Merkle leaves.  The helper mirrors the prover
/// configuration so callers can rely on identical Merkle framing without
/// leaking the builder details elsewhere in the crate.
pub fn canonical_stark_params() -> StarkParams {
    let mut builder = StarkParamsBuilder::new();
    builder.hash = HashKind::Blake2s { digest_size: 32 };
    builder.merkle.leaf_width = 1;
    builder
        .build()
        .expect("canonical Stark parameters must be valid")
}
