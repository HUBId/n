use core::convert::TryInto;
use core::fmt;

use serde::{Deserialize, Serialize};

/// Error surfaced by deterministic hashing helpers when slice conversions fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeterministicHashError {
    /// Conversion from a slice into a fixed-size array failed.
    SliceConversion {
        /// Length expected by the conversion routine.
        expected: usize,
    },
}

impl fmt::Display for DeterministicHashError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DeterministicHashError::SliceConversion { expected } => {
                write!(f, "failed to convert slice into array of length {expected}")
            }
        }
    }
}

impl std::error::Error for DeterministicHashError {}

/// Internal deterministic hash value produced by the pseudo-BLAKE3 helper.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Hash {
    bytes: [u8; 32],
}

impl Hash {
    /// Constructs a hash value from raw bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    /// Returns the canonical byte representation of the digest.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// Consumes the hash and returns the underlying byte array.
    pub const fn into_bytes(self) -> [u8; 32] {
        self.bytes
    }

    /// Returns a helper that formats the digest as lowercase hexadecimal.
    pub fn to_hex(&self) -> HexOutput {
        HexOutput(self.bytes)
    }
}

impl From<[u8; 32]> for Hash {
    fn from(bytes: [u8; 32]) -> Self {
        Self::from_bytes(bytes)
    }
}

impl From<Hash> for [u8; 32] {
    fn from(hash: Hash) -> Self {
        hash.into_bytes()
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash(0x{})", self.to_hex())
    }
}

/// Hexadecimal representation of a deterministic digest.
#[derive(Clone, Copy)]
pub struct HexOutput([u8; 32]);

impl fmt::Display for HexOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0.iter() {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

impl fmt::Debug for HexOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// Deterministic streaming helper mirroring the `blake3::Hasher` interface.
#[derive(Default, Clone)]
pub struct Hasher {
    buffer: Vec<u8>,
}

impl Hasher {
    /// Creates a new deterministic hasher instance.
    pub fn new() -> Self {
        Self { buffer: Vec::new() }
    }

    /// Absorbs additional bytes into the hasher state.
    pub fn update(&mut self, bytes: &[u8]) {
        self.buffer.extend_from_slice(bytes);
    }

    /// Finalises the hasher and returns a 32-byte digest.
    pub fn finalize(self) -> Hash {
        hash(&self.buffer)
    }

    /// Finalises the hasher into an extendable output reader.
    pub fn finalize_xof(self) -> OutputReader {
        OutputReader {
            xof: PseudoBlake3Xof::from_state(pseudo_blake3(&self.buffer)),
        }
    }
}

/// Extendable output reader mirroring the `blake3::OutputReader` API.
#[derive(Debug, Clone)]
pub struct OutputReader {
    xof: PseudoBlake3Xof,
}

impl OutputReader {
    /// Fills the provided buffer with deterministic bytes from the XOF stream.
    ///
    /// Returns an error if the underlying slice conversion fails.
    pub fn fill(&mut self, output: &mut [u8]) -> Result<(), DeterministicHashError> {
        self.xof.squeeze(output)
    }
}

/// Computes a deterministic 32-byte hash of the provided payload.
pub fn hash(input: &[u8]) -> Hash {
    Hash::from(pseudo_blake3(input))
}

/// Deterministic pseudo BLAKE3 hash used throughout the crate.
pub fn pseudo_blake3(input: &[u8]) -> [u8; 32] {
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
        value ^= ((i as u64 + 1).wrapping_mul(0x9e3779b97f4a7c15)).rotate_left((i % 8) as u32 + 1);
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

/// Deterministic XOF used as a pseudo BLAKE3-XOF replacement.
#[derive(Debug, Clone)]
pub struct PseudoBlake3Xof {
    state: [u8; 32],
    counter: u64,
}

impl PseudoBlake3Xof {
    /// Creates a new XOF instance from an arbitrary seed.
    pub fn new(seed: &[u8]) -> Self {
        let mut data = seed.to_vec();
        data.extend_from_slice(b"/XOF");
        Self {
            state: pseudo_blake3(&data),
            counter: 0,
        }
    }

    /// Creates a new XOF starting from an existing 32-byte hash state.
    pub fn from_state(state: [u8; 32]) -> Self {
        Self { state, counter: 0 }
    }

    /// Returns the next 64 bits from the deterministic stream.
    ///
    /// This operation is infallible for well-formed inputs but returns an error if the
    /// pseudo-BLAKE3 block cannot be converted into an 8-byte array.
    pub fn next_u64(&mut self) -> Result<u64, DeterministicHashError> {
        let mut data = Vec::with_capacity(40);
        data.extend_from_slice(&self.state);
        data.extend_from_slice(&self.counter.to_le_bytes());
        let block = pseudo_blake3(&data);
        self.state = block;
        self.counter = self.counter.wrapping_add(1);
        let bytes: [u8; 8] = block[0..8]
            .try_into()
            .map_err(|_| DeterministicHashError::SliceConversion { expected: 8 })?;
        Ok(u64::from_le_bytes(bytes))
    }

    /// Fills the provided buffer with bytes from the stream.
    ///
    /// Returns an error if the next word cannot be produced.
    pub fn squeeze(&mut self, output: &mut [u8]) -> Result<(), DeterministicHashError> {
        for chunk in output.chunks_mut(8) {
            let word = self.next_u64()?;
            let bytes = word.to_le_bytes();
            let len = chunk.len();
            chunk.copy_from_slice(&bytes[..len]);
        }
        Ok(())
    }
}
