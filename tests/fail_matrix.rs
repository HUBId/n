#[path = "fail_matrix/fixture.rs"]
mod fixture;
#[path = "fail_matrix/header.rs"]
mod header;

pub use fixture::{
    corrupt_merkle_path, flip_header_version, flip_param_digest_byte, flip_public_digest_byte,
    swap_trace_indices, FailMatrixFixture,
};
