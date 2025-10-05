//! Fast Fourier Transform utilities for the `rpp-stark` engine.
//!
//! This module captures the type-level contracts for radix-2 FFT execution
//! without providing concrete algorithms.  The documented traits explicitly
//! state how Montgomery-encoded field elements, generator tables, and
//! deterministic chunking interplay to guarantee reproducibility across
//! platforms.

use core::marker::PhantomData;

use blake3::Hasher;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use crate::field::{
    prime_field::FieldElementOps, prime_field::MontgomeryConvertible, FieldElement,
};

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

const RADIX2_CHUNKING_DESCRIPTION: &str =
    "Radix-2 FFTs are chunked by splitting the domain into contiguous butterfly \
layers where each worker processes full Montgomery-encoded twiddle rows in \
natural order before synchronizing on the next depth.  This deterministic \
partitioning guarantees identical transcript ordering across platforms.";

const ROOT_DERIVATION_KEY: [u8; 32] = {
    let seed = *b"RPP-FFT-ROOTS/V1";
    let mut key = [0u8; 32];
    let mut i = 0;
    while i < seed.len() {
        key[i] = seed[i];
        i += 1;
    }
    key
};

static RADIX2_GENERATOR_CACHE: OnceLock<Mutex<HashMap<usize, Radix2GeneratorTable<FieldElement>>>> =
    OnceLock::new();

fn generator_cache() -> &'static Mutex<HashMap<usize, Radix2GeneratorTable<FieldElement>>> {
    RADIX2_GENERATOR_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn leak_field_elements(elements: Vec<FieldElement>) -> &'static [FieldElement] {
    let slice: &'static mut [FieldElement] = elements.leak();
    slice as &'static [FieldElement]
}

fn derive_primitive_root(log2_size: usize) -> FieldElement {
    assert!(
        log2_size <= RADIX2_MAX_LOG2_SIZE,
        "log2 size exceeds supported maximum"
    );
    if log2_size == 0 {
        return FieldElement::ONE;
    }
    let mut candidate_index = 0u64;
    loop {
        let mut hasher = Hasher::new_keyed(&ROOT_DERIVATION_KEY);
        hasher.update(&(log2_size as u64).to_le_bytes());
        hasher.update(&candidate_index.to_le_bytes());
        let hash = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(hash.as_bytes());
        let candidate = FieldElement::from_transcript_bytes(&bytes);
        if is_primitive_radix2_root(candidate, log2_size) {
            return candidate;
        }
        candidate_index = candidate_index.wrapping_add(1);
    }
}

fn is_primitive_radix2_root(root: FieldElement, log2_size: usize) -> bool {
    if log2_size == 0 {
        return root == FieldElement::ONE;
    }

    let order = 1u64 << log2_size;
    if root.pow(order) != FieldElement::ONE {
        return false;
    }

    let half_order = 1u64 << (log2_size - 1);
    root.pow(half_order) != FieldElement::ONE
}

fn build_twiddle_tables(
    primitive_root: FieldElement,
    log2_size: usize,
) -> (Vec<FieldElement>, Vec<FieldElement>) {
    assert!(
        log2_size <= RADIX2_MAX_LOG2_SIZE,
        "log2 size exceeds supported maximum"
    );
    let size = 1usize << log2_size;

    let mut forward = Vec::with_capacity(size);
    let mut inverse = Vec::with_capacity(size);

    let root_inverse = primitive_root
        .inv()
        .expect("primitive roots are non-zero and therefore invertible");

    let mut current_forward = FieldElement::ONE;
    let mut current_inverse = FieldElement::ONE;

    for _ in 0..size {
        forward.push(current_forward.to_montgomery());
        inverse.push(current_inverse.to_montgomery());
        current_forward = current_forward.mul(&primitive_root);
        current_inverse = current_inverse.mul(&root_inverse);
    }

    (forward, inverse)
}

fn generator_table_for(log2_size: usize) -> Radix2GeneratorTable<FieldElement> {
    let cache = generator_cache();
    let mut guard = cache.lock().expect("generator cache mutex poisoned");
    let entry = guard.entry(log2_size).or_insert_with(|| {
        let primitive_root = derive_primitive_root(log2_size);
        let (forward, inverse) = build_twiddle_tables(primitive_root, log2_size);
        Radix2GeneratorTable {
            forward: leak_field_elements(forward),
            inverse: leak_field_elements(inverse),
            _field: PhantomData,
        }
    });
    *entry
}

impl Radix2Domain<FieldElement> {
    /// Builds a radix-2 evaluation domain using the deterministic generator cache.
    pub fn new(log2_size: usize, ordering: Radix2Ordering) -> Self {
        assert!(
            log2_size <= RADIX2_MAX_LOG2_SIZE,
            "log2 size exceeds supported maximum"
        );
        let generators = generator_table_for(log2_size);
        Self {
            log2_size,
            ordering,
            generators,
        }
    }
}

impl EvaluationDomain<FieldElement> for Radix2Domain<FieldElement> {
    fn log2_size(&self) -> usize {
        self.log2_size
    }

    fn ordering(&self) -> Radix2Ordering {
        self.ordering
    }

    fn generators(&self) -> &Radix2GeneratorTable<FieldElement> {
        &self.generators
    }

    fn chunking_description(&self) -> &'static str {
        RADIX2_CHUNKING_DESCRIPTION
    }
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
