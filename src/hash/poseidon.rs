//! Poseidon hash permutation parameter declarations.
//!
//! This module intentionally exposes the structure of the Poseidon permutation used by
//! the STARK stack without providing an executable permutation.  Consumers rely on the
//! documented constants to wire a field-arithmetic implementation in host environments
//! that have access to the actual constants.

use crate::field::FieldElement;

/// Describes a Poseidon MDS matrix without committing to concrete coefficients.
///
/// Implementations document how the matrix is structured and which field the entries
/// live in.  The actual coefficients are expected to be provided in environments that
/// have access to the full parameter set; in this repository we merely declare the
/// interface so downstream crates can plug in verified constants.
pub trait PoseidonMdsMatrix {
    /// Field over which the matrix is defined (the STARK base field).
    type Field;

    /// Width of the matrix which matches the width of the Poseidon state `t`.
    const WIDTH: usize;
}

/// Declares the round constants for a Poseidon permutation without enumerating them.
///
/// Implementations are required to specify how many full and partial rounds the
/// permutation executes and to expose a handle to the constant schedule.  The constants
/// themselves remain out of scope for this crate in order to keep the implementation
/// side-effect free.
pub trait PoseidonRoundConstants {
    /// Field element type used in the constant schedule.
    type Field;

    /// Total number of constants attached to full rounds.
    const FULL_ROUND_COUNT: usize;

    /// Total number of constants attached to partial rounds.
    const PARTIAL_ROUND_COUNT: usize;
}

/// Declares the permutation schedule and state geometry for Poseidon.
///
/// The trait bundles the width, rate, capacity, S-Box exponent `ALPHA` and the round
/// configuration.  Production implementations can attach concrete MDS matrices and
/// round constants by implementing [`PoseidonMdsMatrix`] and [`PoseidonRoundConstants`].
pub trait PoseidonPermutationSpec {
    /// Field type the permutation operates over.
    type Field;

    /// Rate of the sponge construction (number of elements absorbed per permutation).
    const RATE: usize;

    /// Capacity of the sponge construction ensuring cryptographic security.
    const CAPACITY: usize;

    /// State width `t = RATE + CAPACITY`.
    const WIDTH: usize;

    /// Exponent of the S-Box used during non-linear full rounds (`\alpha = 5`).
    const ALPHA: u32;

    /// Number of full rounds (`r_f = 8`).
    const FULL_ROUNDS: usize;

    /// Number of partial rounds (`r_p = 56`).
    const PARTIAL_ROUNDS: usize;

    /// Declaration of the MDS matrix used between rounds.
    type MdsMatrix: PoseidonMdsMatrix<Field = Self::Field>;

    /// Declaration of the round constant schedule.
    type RoundConstants: PoseidonRoundConstants<Field = Self::Field>;
}

/// Zero-sized type describing the 12×12 Poseidon MDS matrix used by the engine.
#[derive(Debug, Clone, Copy)]
pub struct PoseidonMdsMatrixV1;

impl PoseidonMdsMatrix for PoseidonMdsMatrixV1 {
    type Field = FieldElement;
    const WIDTH: usize = 12;
}

/// Round-constant descriptor for the Poseidon parameter set.
#[derive(Debug, Clone, Copy)]
pub struct PoseidonRoundConstantsV1;

impl PoseidonRoundConstants for PoseidonRoundConstantsV1 {
    type Field = FieldElement;
    const FULL_ROUND_COUNT: usize = 8;
    const PARTIAL_ROUND_COUNT: usize = 56;
}

/// Parameter specification for the Poseidon permutation with `t = 12`, `rate = 8`,
/// `capacity = 4`, `\alpha = 5`, `r_f = 8` and `r_p = 56`.
#[derive(Debug, Clone, Copy)]
pub struct PoseidonSpecV1;

impl PoseidonPermutationSpec for PoseidonSpecV1 {
    type Field = FieldElement;
    const RATE: usize = 8;
    const CAPACITY: usize = 4;
    const WIDTH: usize = 12;
    const ALPHA: u32 = 5;
    const FULL_ROUNDS: usize = 8;
    const PARTIAL_ROUNDS: usize = 56;
    type MdsMatrix = PoseidonMdsMatrixV1;
    type RoundConstants = PoseidonRoundConstantsV1;
}

/// Marker trait describing the permutation order applied to the Poseidon state.
///
/// The order alternates full rounds and partial rounds as defined by the permutation
/// specification.  The trait exists purely for documentation so that downstream users
/// can implement the actual permutation while adhering to the documented sequencing.
pub trait PoseidonPermutationOrder {
    /// Number of prefix full rounds executed before partial rounds start.
    const FULL_ROUNDS_BEFORE_PARTIAL: usize;

    /// Number of partial rounds executed in the middle of the permutation.
    const PARTIAL_ROUNDS: usize;

    /// Number of suffix full rounds executed after partial rounds complete.
    const FULL_ROUNDS_AFTER_PARTIAL: usize;
}

/// Sequencing of Poseidon rounds for the `PoseidonSpecV1` parameter set.
#[derive(Debug, Clone, Copy)]
pub struct PoseidonPermutationOrderV1;

impl PoseidonPermutationOrder for PoseidonPermutationOrderV1 {
    const FULL_ROUNDS_BEFORE_PARTIAL: usize = 4;
    const PARTIAL_ROUNDS: usize = 56;
    const FULL_ROUNDS_AFTER_PARTIAL: usize = 4;
}
