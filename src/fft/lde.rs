//! Low-degree extension routines for the evaluation domain.
//!
//! This module exposes descriptive traits for low-degree extension (LDE)
//! operators.  Concrete back-ends plug in FFT-based or naive algorithms that
//! honour the documented Montgomery encoding and deterministic chunking rules.

use crate::field::polynomial::{Polynomial, PolynomialView};

/// Trait describing contracts for low-degree extensions over multiplicative
/// cosets.
pub trait LowDegreeExtension<F> {
    /// Returns the blowup factor applied during the extension.
    fn blowup_factor(&self) -> usize;

    /// Extends an owned polynomial.
    fn extend_owned(&self, polynomial: &Polynomial) -> Vec<F>;

    /// Extends a borrowed polynomial view.
    fn extend_view(&self, polynomial: PolynomialView<'_>) -> Vec<F>;
}

/// Descriptor capturing configuration for deterministic LDE chunking.
#[derive(Debug, Clone, Copy)]
pub struct LowDegreeExtensionDescriptor {
    /// Multiplicative blowup factor.
    pub blowup_factor: usize,
    /// Human-readable explanation of the deterministic chunking scheme used to
    /// distribute evaluation points across worker threads.
    pub chunking_description: &'static str,
}
