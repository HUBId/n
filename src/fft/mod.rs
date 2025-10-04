//! Fast Fourier Transform utilities for the `rpp-stark` engine.
//!
//! This module captures the type-level contracts for radix-2 FFT execution
//! without providing concrete algorithms.  The documented traits explicitly
//! state how Montgomery-encoded field elements, generator tables, and
//! deterministic chunking interplay to guarantee reproducibility across
//! platforms.

use core::marker::PhantomData;

use crate::field::FieldElement;

pub mod ifft;
pub mod lde;

pub use ifft::Ifft;

/// Maximum supported radix-2 domain size expressed as `log2(n)`.
///
/// Implementations are expected to enforce this bound when building FFT plans
/// to ensure generator tables remain precomputed and cache-friendly.
pub const RADIX2_MAX_LOG2_SIZE: usize = 32;

/// Ordering used when iterating evaluation domain elements.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Radix2Ordering {
    /// Natural (lexicographic) ordering.
    Natural,
    /// Bit-reversed ordering compatible with iterative Cooley-Tukey FFTs.
    BitReversed,
}

/// Placeholder table describing radix-2 generators in Montgomery form.
#[derive(Debug, Clone, Copy)]
pub struct Radix2GeneratorTable<F: 'static> {
    /// Successive powers of the primitive root used for the forward FFT.
    pub forward: &'static [F],
    /// Successive powers of the inverse root used for the inverse FFT.
    pub inverse: &'static [F],
    /// Marker tying the table to the field implementation.
    pub _field: PhantomData<F>,
}

impl<F: 'static> Radix2GeneratorTable<F> {
    /// Returns an empty placeholder table.
    pub const fn empty() -> Self {
        Self {
            forward: &[],
            inverse: &[],
            _field: PhantomData,
        }
    }
}

/// Canonical radix-2 evaluation domain descriptor.
#[derive(Debug, Clone, Copy)]
pub struct Radix2Domain<F: 'static> {
    /// Logarithm of the domain size.
    pub log2_size: usize,
    /// Element ordering used during iteration.
    pub ordering: Radix2Ordering,
    /// Precomputed generator tables in Montgomery form.
    pub generators: Radix2GeneratorTable<F>,
}

/// Trait describing evaluation domains used for FFTs.
pub trait EvaluationDomain<F> {
    /// Returns the logarithm of the domain size.
    fn log2_size(&self) -> usize;

    /// Returns the concrete ordering of the domain elements.
    fn ordering(&self) -> Radix2Ordering;

    /// Returns the generator table used for twiddle factor lookups.
    fn generators(&self) -> &Radix2GeneratorTable<F>;

    /// Provides a canonical description of the deterministic chunking strategy
    /// that must be used when parallelizing FFT butterflies.  The description is
    /// returned as a free-form string to keep the API descriptive while allowing
    /// implementors to document platform specific nuances (e.g. Montgomery
    /// conversion boundaries).
    fn chunking_description(&self) -> &'static str;
}

/// Trait documenting forward FFT execution contracts.
pub trait Fft<F> {
    /// Associated evaluation domain for the plan.
    type Domain: EvaluationDomain<F>;

    /// Returns the evaluation domain descriptor used by the plan.
    fn domain(&self) -> &Self::Domain;

    /// Executes the forward transform in-place on Montgomery encoded values.
    fn forward(&self, values: &mut [F]);
}

/// Canonical empty generator table for the default field.
pub const RADIX2_GENERATORS: Radix2GeneratorTable<FieldElement> = Radix2GeneratorTable {
    forward: &[],
    inverse: &[],
    _field: PhantomData,
};
