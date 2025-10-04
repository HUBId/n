//! Hash configuration definitions shared across prover and verifier.
//! Parameters ensure deterministic hash usage within transcripts and commitments.

/// Poseidon parameter set descriptor.
#[derive(Debug, Clone)]
pub struct PoseidonParameters {
    /// Number of full rounds in the permutation.
    pub full_rounds: usize,
    /// Number of partial rounds in the permutation.
    pub partial_rounds: usize,
    /// Width of the permutation state.
    pub width: usize,
}

impl PoseidonParameters {
    /// Creates a new parameter set with deterministic defaults.
    pub fn new(full_rounds: usize, partial_rounds: usize, width: usize) -> Self {
        Self {
            full_rounds,
            partial_rounds,
            width,
        }
    }
}

/// Blake3 parameter descriptor for transcript usage.
#[derive(Debug, Clone)]
pub struct Blake3Parameters {
    /// Fixed domain separation label.
    pub label: &'static [u8],
}

impl Blake3Parameters {
    /// Creates a new descriptor.
    pub const fn new(label: &'static [u8]) -> Self {
        Self { label }
    }
}

/// Aggregate hash parameters used by the STARK engine.
#[derive(Debug, Clone)]
pub struct HashParameters {
    /// Poseidon permutation configuration.
    pub poseidon: PoseidonParameters,
    /// Blake3 transcript configuration.
    pub blake3: Blake3Parameters,
}

impl HashParameters {
    /// Constructs aggregate parameters.
    pub fn new(poseidon: PoseidonParameters, blake3: Blake3Parameters) -> Self {
        Self { poseidon, blake3 }
    }
}
