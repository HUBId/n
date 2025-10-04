//! Inverse FFT routines for polynomial reconstruction.
//!
//! The module documents the inverse transform side of the radix-2 pipeline.
//! Implementations operate entirely in Montgomery space to keep consistency with
//! forward transforms and polynomial storage.  Deterministic chunking mirrors the
//! forward transform to preserve transcript stability in interactive protocols.

use super::{EvaluationDomain, Radix2Domain};

/// Trait documenting inverse FFT execution contracts.
pub trait Ifft<F> {
    /// Associated evaluation domain.
    type Domain: EvaluationDomain<F>;

    /// Returns the evaluation domain descriptor used during interpolation.
    fn domain(&self) -> &Self::Domain;

    /// Executes the inverse transform, mutating the provided evaluations in
    /// place.
    fn inverse(&self, values: &mut [F]);
}

/// Descriptor for radix-2 inverse FFT plans.
#[derive(Debug, Clone, Copy)]
pub struct Radix2InverseFft<F: 'static> {
    /// Domain carrying ordering and generator metadata.
    pub domain: Radix2Domain<F>,
}
