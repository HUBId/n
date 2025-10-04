//! Prime field interface tailored for the `rpp-stark` engine.
//!
//! This module intentionally exposes *only* the type- and trait-level
//! contracts that downstream back-ends must satisfy.  No arithmetic logic
//! is provided here; consumers are expected to supply constant-time
//! implementations that respect the documented invariants.

use core::fmt;

/// Metadata describing the underlying field modulus.
#[derive(Debug, Clone, Copy)]
pub struct Modulus {
    /// Prime modulus value in canonical representation.
    pub value: u64,
    /// Indicates whether the modulus passed primality checks during configuration.
    pub is_prime: bool,
}

impl Modulus {
    /// Creates a new modulus descriptor.
    pub const fn new(value: u64, is_prime: bool) -> Self {
        Self { value, is_prime }
    }
}

/// Canonical generator for the default field used across the system.
pub const DEFAULT_MODULUS: Modulus = Modulus::new(0xffffffff00000001, true);

/// Field element represented as a canonical value modulo the prime.
///
/// # Representation
///
/// * `FieldElement` is a transparent wrapper around a raw `u64`.  When the
///   element is in canonical (non-Montgomery) form the wrapped integer must be
///   within the range `[0, MODULUS.value)`.
/// * Montgomery form encodes elements as `a * R mod MODULUS`, where `R = 2^64`.
/// * Serialization uses **little-endian** byte order for canonical
///   representations; Montgomery encodings are documented separately by the
///   conversion traits.
///
/// # Safety & Auditing
///
/// The type itself performs no runtime validation.  Implementations of the
/// provided traits must enforce the documented invariants and perform
/// constant-time assertions where required by `ConstantTimeAssertions`.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct FieldElement(pub u64);

impl fmt::Debug for FieldElement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("FieldElement").field(&self.0).finish()
    }
}

impl FieldElement {
    /// Canonical prime modulus associated with this field.
    pub const MODULUS: Modulus = DEFAULT_MODULUS;
    /// Montgomery radix `R = 2^64 mod MODULUS`.
    pub const R: u64 = 0xffffffff;
    /// Precomputed `R^2 mod MODULUS` used for Montgomery conversions.
    pub const R2: u64 = 0xfffffffe00000001;
    /// `-MODULUS^{-1} mod 2^64`, the Montgomery reduction parameter.
    pub const MONTGOMERY_INV: u64 = 0xfffffffeffffffff;
    /// Designated generator for the multiplicative subgroup.
    pub const GENERATOR: FieldElement = FieldElement(3);
    /// Additive identity in canonical form.
    pub const ZERO: FieldElement = FieldElement(0);
    /// Multiplicative identity in canonical form.
    pub const ONE: FieldElement = FieldElement(1);
}

/// Trait describing the high-level arithmetic contract for field elements.
pub trait FieldElementOps: Sized {
    /// Adds two canonical field elements, returning the canonical representative.
    fn add(&self, rhs: &Self) -> Self;
    /// Subtracts `rhs` from `self` in canonical form.
    fn sub(&self, rhs: &Self) -> Self;
    /// Computes the additive inverse of `self`.
    fn neg(&self) -> Self;
    /// Multiplies two field elements.
    fn mul(&self, rhs: &Self) -> Self;
    /// Squares the field element.
    fn square(&self) -> Self;
    /// Computes the multiplicative inverse, returning `None` for zero.
    fn inv(&self) -> Option<Self>;
}

/// Trait capturing Montgomery encoding/decoding contracts.
pub trait MontgomeryConvertible: Sized {
    /// Converts a canonical element into Montgomery form.
    fn to_montgomery(&self) -> Self;
    /// Converts an element from Montgomery form back to canonical representation.
    fn from_montgomery(&self) -> Self;
}

/// Trait defining serialization requirements for field elements.
pub trait CanonicalSerialize: Sized {
    /// Canonical serialization output type (e.g. `[u8; 8]`).
    type Bytes;

    /// Serializes the element into canonical little-endian bytes.
    fn to_bytes(&self) -> Self::Bytes;

    /// Attempts to deserialize from canonical little-endian bytes.
    fn from_bytes(bytes: &Self::Bytes) -> Option<Self>;
}

/// Trait collecting constant-time auditing assertions required by higher layers.
pub trait ConstantTimeAssertions {
    /// Ensures the element is strictly less than the field modulus in constant time.
    fn assert_lt_modulus(&self);
    /// Ensures the element is *not* the additive identity in constant time.
    fn assert_nonzero(&self);
    /// Ensures the element is a valid canonical representative (or panics/logs otherwise).
    fn assert_canonical(&self);
}
