//! Prime field implementation tailored for the `rpp-stark` engine.
//! Provides deterministic arithmetic over a statically defined prime modulus.

use core::fmt;

/// Metadata describing the underlying field modulus.
#[derive(Debug, Clone, Copy)]
pub struct Modulus {
    /// Prime modulus value.
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
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct FieldElement {
    /// Canonical representative in the range `[0, modulus)`.
    value: u64,
}

impl FieldElement {
    /// Returns the additive identity.
    pub const fn zero() -> Self {
        Self { value: 0 }
    }

    /// Returns the multiplicative identity.
    pub const fn one() -> Self {
        Self { value: 1 }
    }

    /// Constructs an element from a raw value reduced modulo the default modulus.
    pub fn new(value: u64) -> Self {
        Self {
            value: value % DEFAULT_MODULUS.value,
        }
    }

    /// Exposes the underlying canonical value.
    pub fn as_u64(&self) -> u64 {
        self.value
    }

    /// Computes the modular addition of two field elements.
    pub fn add(self, other: Self) -> Self {
        let modulus = DEFAULT_MODULUS.value;
        let sum = self.value.wrapping_add(other.value);
        let mut result = sum;
        if result >= modulus || sum < self.value {
            result = result.wrapping_sub(modulus);
        }
        Self { value: result }
    }

    /// Computes modular subtraction.
    pub fn sub(self, other: Self) -> Self {
        let modulus = DEFAULT_MODULUS.value;
        let mut result = self.value.wrapping_sub(other.value);
        if self.value < other.value {
            result = result.wrapping_add(modulus);
        }
        Self { value: result }
    }

    /// Computes modular multiplication using 128-bit widening.
    pub fn mul(self, other: Self) -> Self {
        let modulus = DEFAULT_MODULUS.value as u128;
        let product = (self.value as u128) * (other.value as u128);
        Self {
            value: (product % modulus) as u64,
        }
    }

    /// Computes modular exponentiation via square-and-multiply.
    pub fn pow(self, mut exp: u64) -> Self {
        let mut result = Self::one();
        let mut base = self;
        while exp > 0 {
            if exp & 1 == 1 {
                result = result.mul(base);
            }
            base = base.mul(base);
            exp >>= 1;
        }
        result
    }

    /// Computes the multiplicative inverse using Fermat's little theorem.
    pub fn inv(self) -> Option<Self> {
        if self.value == 0 {
            return None;
        }
        Some(self.pow(DEFAULT_MODULUS.value - 2))
    }
}

impl fmt::Debug for FieldElement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("FieldElement").field(&self.value).finish()
    }
}
