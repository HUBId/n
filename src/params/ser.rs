use super::types::{
    ChallengeBounds, Endianness, FieldKind, FriFolding, FriParams, HashFamily, HashKind, LdeOrder,
    LdeParams, MerkleArity, MerkleParams, ProofParams, SecurityBudget, TranscriptParams,
};
use super::StarkParams;

/// Canonical binary serialisation for [`StarkParams`].
///
/// | Offset | Field | Encoding |
/// |--------|-------|----------|
/// | 0..2 | `params_version` | `u16` little-endian |
/// | 2..4 | `field` | `u16` discriminant |
/// | 4..5 | `hash.family` | `u8` discriminant |
/// | 5..7 | `hash.parameter_id` | `u16` little-endian |
/// | 7..11 | `lde.blowup` | `u32` little-endian |
/// | 11..12 | `lde.order` | `u8` discriminant |
/// | 12..20 | `lde.coset_tag` | `u64` little-endian |
/// | 20..21 | `fri.r` | `u8` |
/// | 21..23 | `fri.queries` | `u16` little-endian |
/// | 23..25 | `fri.domain_log2` | `u16` little-endian |
/// | 25..26 | `fri.folding` | `u8` discriminant |
/// | 26..27 | `fri.num_layers` | `u8` |
/// | 27..28 | `merkle.leaf_encoding` | `u8` discriminant |
/// | 28..29 | `merkle.leaf_width` | `u8` |
/// | 29..30 | `merkle.arity` | `u8` value (2 or 4) |
/// | 30..38 | `merkle.domain_sep` | `u64` little-endian |
/// | 38..46 | `transcript.protocol_tag` | `u64` little-endian |
/// | 46..78 | `transcript.seed` | 32 raw bytes |
/// | 78..79 | `transcript.challenge_bounds.minimum` | `u8` |
/// | 79..80 | `transcript.challenge_bounds.maximum` | `u8` |
/// | 80..82 | `proof.version` | `u16` little-endian |
/// | 82..86 | `proof.max_size_kb` | `u32` little-endian |
/// | 86..88 | `security.target_bits` | `u16` little-endian |
/// | 88..89 | `security.soundness_slack_bits` | `u8` |
///
/// The layout intentionally avoids padding and ensures that byte-for-byte
/// equality implies identical parameter sets.
///
/// Serialisation error kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SerKind {
    /// Input ended before all fields could be read.
    UnexpectedEnd { field: &'static str },
    /// Encountered an unknown discriminant value.
    InvalidDiscriminant { field: &'static str, value: u16 },
    /// Additional bytes were present after consuming the structure.
    TrailingBytes { expected: usize, remaining: usize },
}

/// Serialises the parameter set into canonical bytes.
pub fn serialize_params(params: &StarkParams) -> Vec<u8> {
    let mut out = Vec::with_capacity(89);
    out.extend_from_slice(&params.params_version().to_le_bytes());
    out.extend_from_slice(&params.field().code().to_le_bytes());
    out.push(params.hash().family().code());
    out.extend_from_slice(&params.hash().parameter_id().to_le_bytes());
    out.extend_from_slice(&params.lde().blowup.to_le_bytes());
    out.push(params.lde().order.code());
    out.extend_from_slice(&params.lde().coset_tag.to_le_bytes());
    out.push(params.fri().r);
    out.extend_from_slice(&params.fri().queries.to_le_bytes());
    out.extend_from_slice(&params.fri().domain_log2.to_le_bytes());
    out.push(params.fri().folding.code());
    out.push(params.fri().num_layers);
    out.push(params.merkle().leaf_encoding.code());
    out.push(params.merkle().leaf_width);
    out.push(params.merkle().arity.code());
    out.extend_from_slice(&params.merkle().domain_sep.to_le_bytes());
    out.extend_from_slice(&params.transcript().protocol_tag.to_le_bytes());
    out.extend_from_slice(&params.transcript().seed);
    out.push(params.transcript().challenge_bounds.minimum);
    out.push(params.transcript().challenge_bounds.maximum);
    out.extend_from_slice(&params.proof().version.to_le_bytes());
    out.extend_from_slice(&params.proof().max_size_kb.to_le_bytes());
    out.extend_from_slice(&params.security().target_bits.to_le_bytes());
    out.push(params.security().soundness_slack_bits);
    out
}

/// Deserialises a parameter set from canonical bytes.
pub fn deserialize_params(bytes: &[u8]) -> Result<StarkParams, SerKind> {
    let mut cursor = Cursor::new(bytes);
    let params_version = cursor.take_u16("params_version")?;
    let field_code = cursor.take_u16("field")?;
    let field = FieldKind::from_code(field_code).ok_or(SerKind::InvalidDiscriminant {
        field: "field",
        value: field_code,
    })?;
    let family_code = cursor.take_u8("hash.family")?;
    let family = HashFamily::from_code(family_code).ok_or(SerKind::InvalidDiscriminant {
        field: "hash.family",
        value: family_code as u16,
    })?;
    let hash_param = cursor.take_u16("hash.parameter_id")?;
    let hash = HashKind::from_codes(family, hash_param);
    let lde_blowup = cursor.take_u32("lde.blowup")?;
    let lde_order_code = cursor.take_u8("lde.order")?;
    let lde_order = LdeOrder::from_code(lde_order_code).ok_or(SerKind::InvalidDiscriminant {
        field: "lde.order",
        value: lde_order_code as u16,
    })?;
    let lde_coset = cursor.take_u64("lde.coset_tag")?;
    let fri_r = cursor.take_u8("fri.r")?;
    let fri_queries = cursor.take_u16("fri.queries")?;
    let fri_domain = cursor.take_u16("fri.domain_log2")?;
    let fri_folding_code = cursor.take_u8("fri.folding")?;
    let fri_folding =
        FriFolding::from_code(fri_folding_code).ok_or(SerKind::InvalidDiscriminant {
            field: "fri.folding",
            value: fri_folding_code as u16,
        })?;
    let fri_layers = cursor.take_u8("fri.num_layers")?;
    let merkle_encoding_code = cursor.take_u8("merkle.leaf_encoding")?;
    let merkle_encoding =
        Endianness::from_code(merkle_encoding_code).ok_or(SerKind::InvalidDiscriminant {
            field: "merkle.leaf_encoding",
            value: merkle_encoding_code as u16,
        })?;
    let merkle_leaf_width = cursor.take_u8("merkle.leaf_width")?;
    let merkle_arity_code = cursor.take_u8("merkle.arity")?;
    let merkle_arity =
        MerkleArity::from_code(merkle_arity_code).ok_or(SerKind::InvalidDiscriminant {
            field: "merkle.arity",
            value: merkle_arity_code as u16,
        })?;
    let merkle_domain_sep = cursor.take_u64("merkle.domain_sep")?;
    let transcript_protocol = cursor.take_u64("transcript.protocol_tag")?;
    let transcript_seed = cursor.take_array::<32>("transcript.seed")?;
    let transcript_ch_min = cursor.take_u8("transcript.challenge_bounds.minimum")?;
    let transcript_ch_max = cursor.take_u8("transcript.challenge_bounds.maximum")?;
    let proof_version = cursor.take_u16("proof.version")?;
    let proof_max_size = cursor.take_u32("proof.max_size_kb")?;
    let security_target = cursor.take_u16("security.target_bits")?;
    let security_slack = cursor.take_u8("security.soundness_slack_bits")?;

    if cursor.remaining() != 0 {
        return Err(SerKind::TrailingBytes {
            expected: cursor.position,
            remaining: cursor.remaining(),
        });
    }

    Ok(StarkParams {
        params_version,
        field,
        hash,
        lde: LdeParams {
            blowup: lde_blowup,
            order: lde_order,
            coset_tag: lde_coset,
        },
        fri: FriParams {
            r: fri_r,
            queries: fri_queries,
            domain_log2: fri_domain,
            folding: fri_folding,
            num_layers: fri_layers,
        },
        merkle: MerkleParams {
            leaf_encoding: merkle_encoding,
            leaf_width: merkle_leaf_width,
            arity: merkle_arity,
            domain_sep: merkle_domain_sep,
        },
        transcript: TranscriptParams {
            protocol_tag: transcript_protocol,
            seed: transcript_seed,
            challenge_bounds: ChallengeBounds {
                minimum: transcript_ch_min,
                maximum: transcript_ch_max,
            },
        },
        proof: ProofParams {
            version: proof_version,
            max_size_kb: proof_max_size,
        },
        security: SecurityBudget {
            target_bits: security_target,
            soundness_slack_bits: security_slack,
        },
    })
}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn take_u8(&mut self, field: &'static str) -> Result<u8, SerKind> {
        if self.position + 1 > self.bytes.len() {
            return Err(SerKind::UnexpectedEnd { field });
        }
        let value = self.bytes[self.position];
        self.position += 1;
        Ok(value)
    }

    fn take_u16(&mut self, field: &'static str) -> Result<u16, SerKind> {
        if self.position + 2 > self.bytes.len() {
            return Err(SerKind::UnexpectedEnd { field });
        }
        let value = u16::from_le_bytes([self.bytes[self.position], self.bytes[self.position + 1]]);
        self.position += 2;
        Ok(value)
    }

    fn take_u32(&mut self, field: &'static str) -> Result<u32, SerKind> {
        if self.position + 4 > self.bytes.len() {
            return Err(SerKind::UnexpectedEnd { field });
        }
        let value = u32::from_le_bytes([
            self.bytes[self.position],
            self.bytes[self.position + 1],
            self.bytes[self.position + 2],
            self.bytes[self.position + 3],
        ]);
        self.position += 4;
        Ok(value)
    }

    fn take_u64(&mut self, field: &'static str) -> Result<u64, SerKind> {
        if self.position + 8 > self.bytes.len() {
            return Err(SerKind::UnexpectedEnd { field });
        }
        let value = u64::from_le_bytes([
            self.bytes[self.position],
            self.bytes[self.position + 1],
            self.bytes[self.position + 2],
            self.bytes[self.position + 3],
            self.bytes[self.position + 4],
            self.bytes[self.position + 5],
            self.bytes[self.position + 6],
            self.bytes[self.position + 7],
        ]);
        self.position += 8;
        Ok(value)
    }

    fn take_array<const N: usize>(&mut self, field: &'static str) -> Result<[u8; N], SerKind> {
        if self.position + N > self.bytes.len() {
            return Err(SerKind::UnexpectedEnd { field });
        }
        let mut out = [0u8; N];
        out.copy_from_slice(&self.bytes[self.position..self.position + N]);
        self.position += N;
        Ok(out)
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.position)
    }
}
