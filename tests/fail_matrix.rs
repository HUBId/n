#[path = "fail_matrix/composition.rs"]
mod composition;
#[path = "fail_matrix/fixture.rs"]
mod fixture;
#[path = "fail_matrix/fri.rs"]
mod fri;
#[path = "fail_matrix/header.rs"]
mod header;
#[path = "fail_matrix/indices.rs"]
mod indices;
#[path = "fail_matrix/merkle.rs"]
mod merkle;
#[path = "fail_matrix/ood.rs"]
mod ood;
#[path = "fail_matrix/snapshots.rs"]
mod snapshots;
#[path = "fail_matrix/telemetry.rs"]
mod telemetry;

pub use fixture::{
    corrupt_merkle_path, duplicate_composition_index, duplicate_trace_index,
    flip_composition_leaf_byte, flip_header_version, flip_ood_composition_value,
    flip_ood_trace_core_value, flip_param_digest_byte, flip_public_digest_byte,
    mismatch_composition_indices, mismatch_fri_offset, mismatch_openings_offset,
    mismatch_telemetry_body_length, mismatch_telemetry_flag, mismatch_telemetry_header_length,
    mismatch_telemetry_integrity_digest, mismatch_telemetry_offset, mismatch_trace_indices,
    mismatch_trace_root, perturb_fri_fold_challenge, swap_composition_indices, swap_trace_indices,
    truncate_trace_paths, FailMatrixFixture, MutatedProof,
};
