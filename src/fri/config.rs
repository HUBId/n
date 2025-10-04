//! Configuration objects for the FRI protocol.
//! Defines folding schedule and query parameters used across prover and verifier.

/// Parameters describing the FRI folding schedule.
#[derive(Debug, Clone)]
pub struct FriParameters {
    /// Number of queries sampled during verification.
    pub query_count: usize,
    /// Logarithmic domain size.
    pub log_domain_size: usize,
    /// Folding factor applied at each layer.
    pub folding_factor: usize,
}

impl FriParameters {
    /// Creates a new parameter set.
    pub fn new(query_count: usize, log_domain_size: usize, folding_factor: usize) -> Self {
        Self {
            query_count,
            log_domain_size,
            folding_factor,
        }
    }
}
