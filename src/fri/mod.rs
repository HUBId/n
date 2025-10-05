//! Fully deterministic binary FRI implementation used by the prover and verifier.
//! The folding helpers expose the canonical coset-shift schedule derived from
//! [`StarkParams`](crate::params::StarkParams) so that integrators can mirror the
//! prover's domain adjustments.
//!
//! The implementation in this module intentionally favours readability and
//! auditability over raw performance.  All hashing is performed using the
//! deterministic pseudo-BLAKE3 helper implemented locally so that the crate can
//! remain `no-std` friendly and avoid external dependencies.  The goal is to
//! provide a reference implementation that matches the specification captured in
//! the project documentation.

mod batch;
pub mod config;
mod folding;
mod layer;
mod proof;
mod prover;
pub mod types;
mod verifier;

pub(crate) use crate::hash::{pseudo_blake3, PseudoBlake3Xof};
pub use batch::{BatchDigest, BatchQueryPosition, BatchSeed, FriBatch, FriBatchVerificationApi};
pub use folding::{
    binary_fold, coset_shift_schedule, next_domain_size, parent_index, phi, FoldingLayer,
    FoldingLayout, LayerCommitment, BINARY_FOLD_ARITY,
};
pub(crate) use layer::FriLayer;
pub use proof::{
    derive_query_plan_id, DeepOodsProof, FriProof, FriQueryLayerProof, FriQueryProof, FriVerifier,
};
pub use prover::fri_prove;
pub use types::{
    FriError, FriParamsView, FriProofVersion, FriSecurityLevel, FriTranscriptSeed, SerKind,
};
pub use verifier::fri_verify;

use crate::field::FieldElement;
use crate::hash::hash;

/// Prime modulus used by the Goldilocks field.
const MODULUS: u128 = FieldElement::MODULUS.value as u128;

/// Adds two field elements using canonical modular arithmetic.
#[inline]
pub(crate) fn fe_add(a: FieldElement, b: FieldElement) -> FieldElement {
    let sum = (a.0 as u128 + b.0 as u128) % MODULUS;
    FieldElement(sum as u64)
}

/// Subtracts `b` from `a` modulo the field modulus.
#[inline]
#[allow(dead_code)]
pub(crate) fn fe_sub(a: FieldElement, b: FieldElement) -> FieldElement {
    let lhs = a.0 as i128;
    let rhs = b.0 as i128;
    let modulus = MODULUS as i128;
    let mut diff = lhs - rhs;
    diff %= modulus;
    if diff < 0 {
        diff += modulus;
    }
    FieldElement(diff as u64)
}

/// Multiplies two field elements.
#[inline]
pub(crate) fn fe_mul(a: FieldElement, b: FieldElement) -> FieldElement {
    let product = (a.0 as u128 * b.0 as u128) % MODULUS;
    FieldElement(product as u64)
}

/// Squares a field element.
#[inline]
#[allow(dead_code)]
pub(crate) fn fe_square(value: FieldElement) -> FieldElement {
    fe_mul(value, value)
}

/// Exponentiates a field element using square-and-multiply.
#[allow(dead_code)]
pub(crate) fn fe_pow(mut base: FieldElement, mut exponent: u64) -> FieldElement {
    let mut result = FieldElement::ONE;
    while exponent > 0 {
        if exponent & 1 == 1 {
            result = fe_mul(result, base);
        }
        base = fe_square(base);
        exponent >>= 1;
    }
    result
}

/// Converts a 32-byte pseudo-hash into a field element.
pub(crate) fn field_from_hash(bytes: &[u8; 32]) -> FieldElement {
    let mut acc = 0u128;
    for (i, chunk) in bytes.chunks(8).enumerate() {
        if i == 4 {
            break;
        }
        let mut buf = [0u8; 8];
        buf[..chunk.len()].copy_from_slice(chunk);
        let value = u64::from_le_bytes(buf);
        acc = (acc << 64) ^ value as u128;
        acc %= MODULUS;
    }
    FieldElement(acc as u64)
}

/// Helper converting a field element into canonical little-endian bytes.
#[inline]
pub(crate) fn field_to_bytes(value: &FieldElement) -> [u8; 8] {
    value.0.to_le_bytes()
}

/// Hashes a field element into a leaf digest using the canonical leaf framing.
#[inline]
pub(crate) fn hash_leaf(value: &FieldElement) -> [u8; 32] {
    let mut payload = Vec::with_capacity(12);
    payload.extend_from_slice(&(8u32.to_le_bytes()));
    payload.extend_from_slice(&field_to_bytes(value));
    hash(&payload).into()
}

/// Hashes two child digests into their parent digest.
#[inline]
pub(crate) fn hash_internal(children: &[[u8; 32]; 2]) -> [u8; 32] {
    let mut payload = Vec::with_capacity(64);
    for child in children {
        payload.extend_from_slice(child);
    }
    hash(&payload).into()
}
