#[path = "fail_matrix/fixture.rs"]
mod fixture;
#[path = "fail_matrix/header.rs"]
mod header;
#[path = "fail_matrix/indices.rs"]
mod indices;

pub use fixture::{
    corrupt_merkle_path, duplicate_composition_index, duplicate_trace_index, flip_header_version,
    flip_param_digest_byte, flip_public_digest_byte, mismatch_composition_indices,
    mismatch_trace_indices, swap_composition_indices, swap_trace_indices, FailMatrixFixture,
    MutatedProof,
};
