//! Fully deterministic quartic FRI implementation used by the prover and verifier.
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
mod proof;

pub use batch::{BatchDigest, BatchQueryPosition, BatchSeed, FriBatch, FriBatchVerificationApi};
pub use folding::{quartic_fold, FoldingLayer, FoldingLayout, LayerCommitment, QUARTIC_FOLD};
pub use proof::{
    derive_query_plan_id, FriError, FriProof, FriQuery, FriQueryLayer, FriSecurityLevel,
    FriTranscriptSeed, FriVerifier,
};

use crate::field::FieldElement;

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
pub(crate) fn fe_square(value: FieldElement) -> FieldElement {
    fe_mul(value, value)
}

/// Exponentiates a field element using square-and-multiply.
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

/// Deterministic pseudo BLAKE3 hash used by the implementation.
pub(crate) fn pseudo_blake3(input: &[u8]) -> [u8; 32] {
    let mut state = [
        0x6a09e667f3bcc908u64,
        0xbb67ae8584caa73bu64,
        0x3c6ef372fe94f82bu64,
        0xa54ff53a5f1d36f1u64,
    ];

    for (i, chunk) in input.chunks(8).enumerate() {
        let mut buf = [0u8; 8];
        buf[..chunk.len()].copy_from_slice(chunk);
        let mut value = u64::from_le_bytes(buf);
        value ^= ((i as u64 + 1) * 0x9e3779b97f4a7c15).rotate_left((i % 8) as u32 + 1);
        let idx = i % 4;
        state[idx] = state[idx].wrapping_add(value);
        state[idx] = state[idx].rotate_left(13);
        state[idx] ^= state[(idx + 1) % 4];
        state[idx] = state[idx].wrapping_mul(0xbf58476d1ce4e5b9);
    }

    for i in 0..4 {
        let next = state[(i + 1) % 4];
        state[i] ^= next.rotate_right(7);
        state[i] = state[i].wrapping_add(0x94d049bb133111ebu64 ^ (i as u64 * 0x2545f4914f6cdd1d));
        state[i] = state[i].rotate_left(17);
    }

    let mut out = [0u8; 32];
    for (dst, value) in out.chunks_mut(8).zip(state.iter()) {
        dst.copy_from_slice(&value.to_le_bytes());
    }
    out
}

/// Deterministic XOF used for query sampling (pseudo BLAKE3-XOF replacement).
#[derive(Debug, Clone)]
pub(crate) struct PseudoBlake3Xof {
    state: [u8; 32],
    counter: u64,
}

impl PseudoBlake3Xof {
    pub fn new(seed: &[u8]) -> Self {
        let mut data = seed.to_vec();
        data.extend_from_slice(b"/XOF");
        Self {
            state: pseudo_blake3(&data),
            counter: 0,
        }
    }

    pub fn next_u64(&mut self) -> u64 {
        let mut data = Vec::with_capacity(40);
        data.extend_from_slice(&self.state);
        data.extend_from_slice(&self.counter.to_le_bytes());
        let block = pseudo_blake3(&data);
        self.state = block;
        self.counter = self.counter.wrapping_add(1);
        u64::from_le_bytes(block[0..8].try_into().expect("slice length"))
    }

    pub fn squeeze(&mut self, output: &mut [u8]) {
        for chunk in output.chunks_mut(8) {
            let word = self.next_u64();
            let bytes = word.to_le_bytes();
            let len = chunk.len();
            chunk.copy_from_slice(&bytes[..len]);
        }
    }
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
    pseudo_blake3(&payload)
}

/// Hashes four children digests into their parent digest.
#[inline]
pub(crate) fn hash_internal(children: &[[u8; 32]; 4]) -> [u8; 32] {
    let mut payload = Vec::with_capacity(128);
    for child in children {
        payload.extend_from_slice(child);
    }
    pseudo_blake3(&payload)
}
