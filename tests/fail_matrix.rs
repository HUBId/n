#[path = "fail_matrix/fixture.rs"]
mod fixture;
#[path = "fail_matrix/header.rs"]
mod header;
#[path = "fail_matrix/indices.rs"]
mod indices;
#[path = "fail_matrix/merkle.rs"]
mod merkle;
#[path = "fail_matrix/fri.rs"]
mod fri;

pub use fixture::{
    corrupt_merkle_path, duplicate_composition_index, duplicate_trace_index, flip_header_version,
    flip_param_digest_byte, flip_public_digest_byte, mismatch_composition_indices,
    mismatch_trace_indices, mismatch_trace_root, perturb_fri_fold_challenge, swap_composition_indices,
    swap_trace_indices, truncate_trace_paths, FailMatrixFixture, MutatedProof,
};
