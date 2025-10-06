//! Proof envelope implementation and serialization helpers.
//!
//! The module implements the canonical byte layout mandated by the
//! specification.  Both prover and verifier share this code to ensure that the
//! same length prefixes, digests and field orderings are used throughout the
//! pipeline.

use std::convert::TryInto;

use crate::config::{AirSpecId, ParamDigest};
#[cfg(test)]
use crate::fri::FriProof;
pub use crate::proof::ser::{
    compute_commitment_digest, compute_integrity_digest, serialize_public_inputs,
};
use crate::proof::ser::{
    decode_proof_kind, deserialize_fri_proof, encode_proof_kind, serialize_fri_proof,
};
use crate::proof::types::{
    FriParametersMirror, MerkleProofBundle, Openings, OutOfDomainOpening, Proof, Telemetry,
    VerifyError, PROOF_VERSION,
};
use crate::utils::serialization::DigestBytes;

impl Proof {
    /// Serialises the proof into a byte vector using the canonical layout.
    pub fn to_bytes(&self) -> Vec<u8> {
        let payload = self.serialize_payload();
        let header_bytes = self.serialize_header(&payload);
        let integrity = compute_integrity_digest(&header_bytes, &payload);

        let mut bytes = Vec::with_capacity(
            header_bytes.len() + payload.len() + DigestBytes::default().bytes.len(),
        );
        bytes.extend_from_slice(&header_bytes);
        bytes.extend_from_slice(&payload);
        bytes.extend_from_slice(&integrity);
        bytes
    }

    /// Parses an envelope from a byte slice, validating all length prefixes and
    /// integrity digests along the way.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, VerifyError> {
        let mut cursor = Cursor::new(bytes);

        let proof_version = cursor.read_u16()?;
        if proof_version != PROOF_VERSION {
            return Err(VerifyError::UnsupportedVersion(proof_version));
        }

        let kind_byte = cursor.read_u8()?;
        let proof_kind = decode_proof_kind(kind_byte)?;

        let param_digest = ParamDigest(DigestBytes {
            bytes: cursor.read_digest()?,
        });
        let air_spec_id = AirSpecId(DigestBytes {
            bytes: cursor.read_digest()?,
        });

        let public_input_len = cursor.read_u32()? as usize;
        let public_inputs = cursor.read_vec(public_input_len)?;
        let commitment_digest = DigestBytes {
            bytes: cursor.read_digest()?,
        };

        let header_length = cursor.read_u32()?;
        let body_length = cursor.read_u32()?;

        let header_bytes_consumed = cursor.offset();
        let expected_header_length = (3 + 32 + 32 + 4 + public_input_len + 32 + 4 + 4) as u32;
        if expected_header_length != header_length {
            return Err(VerifyError::HeaderLengthMismatch {
                declared: header_length,
                actual: expected_header_length,
            });
        }
        if header_bytes_consumed as u32 != header_length {
            return Err(VerifyError::HeaderLengthMismatch {
                declared: header_length,
                actual: header_bytes_consumed as u32,
            });
        }

        if body_length < DigestBytes::default().bytes.len() as u32 {
            return Err(VerifyError::BodyLengthMismatch {
                declared: body_length,
                actual: body_length,
            });
        }

        let body_bytes = cursor.read_vec(body_length as usize)?;
        if cursor.remaining() != 0 {
            return Err(VerifyError::UnexpectedEndOfBuffer(
                "trailing_header_bytes".to_string(),
            ));
        }

        if body_bytes.len() != body_length as usize {
            return Err(VerifyError::BodyLengthMismatch {
                declared: body_length,
                actual: body_bytes.len() as u32,
            });
        }

        if body_bytes.len() < DigestBytes::default().bytes.len() {
            return Err(VerifyError::BodyLengthMismatch {
                declared: body_length,
                actual: body_bytes.len() as u32,
            });
        }

        let (payload, integrity_bytes) = body_bytes.split_at(body_bytes.len() - 32);
        let integrity_digest: [u8; 32] = integrity_bytes.try_into().unwrap();

        let mut payload_cursor = Cursor::new(payload);
        let core_root = payload_cursor.read_digest()?;
        let aux_root = payload_cursor.read_digest()?;
        let fri_layer_count = payload_cursor.read_u32()? as usize;
        let mut fri_layer_roots = Vec::with_capacity(fri_layer_count);
        for _ in 0..fri_layer_count {
            fri_layer_roots.push(payload_cursor.read_digest()?);
        }

        let ood_count = payload_cursor.read_u32()? as usize;
        let mut ood_openings = Vec::with_capacity(ood_count);
        for _ in 0..ood_count {
            let block_len = payload_cursor.read_u32()? as usize;
            let block_bytes = payload_cursor.read_vec(block_len)?;
            let opening = OutOfDomainOpening::deserialize(&block_bytes)?;
            ood_openings.push(opening);
        }

        let fri_section_len = payload_cursor.read_u32()? as usize;
        let fri_section = payload_cursor.read_vec(fri_section_len)?;
        let fri_proof = deserialize_fri_proof(&fri_section)?;

        let fri_parameters = FriParametersMirror {
            fold: payload_cursor.read_u8()?,
            cap_degree: payload_cursor.read_u16()?,
            cap_size: payload_cursor.read_u32()?,
            query_budget: payload_cursor.read_u16()?,
        };

        if payload_cursor.remaining() != 0 {
            return Err(VerifyError::UnexpectedEndOfBuffer(
                "body_padding".to_string(),
            ));
        }

        let merkle = MerkleProofBundle {
            core_root,
            aux_root,
            fri_layer_roots,
        };

        let openings = Openings {
            out_of_domain: ood_openings,
        };

        let telemetry = Telemetry {
            header_length,
            body_length,
            fri_parameters,
            integrity_digest: DigestBytes {
                bytes: integrity_digest,
            },
        };

        let mut proof = Proof {
            version: proof_version,
            kind: proof_kind,
            param_digest,
            air_spec_id,
            public_inputs,
            commitment_digest,
            merkle,
            openings,
            fri_proof,
            telemetry,
        };

        let payload = proof.serialize_payload();
        let header_bytes = proof.serialize_header(&payload);
        let computed_integrity = compute_integrity_digest(&header_bytes, &payload);
        if computed_integrity != integrity_digest {
            return Err(VerifyError::IntegrityDigestMismatch);
        }

        proof.telemetry.integrity_digest = DigestBytes {
            bytes: integrity_digest,
        };

        Ok(proof)
    }

    pub fn serialize_header(&self, payload: &[u8]) -> Vec<u8> {
        let body_length = (payload.len() + 32) as u32;
        let header_length = (3 + 32 + 32 + 4 + self.public_inputs.len() + 32 + 4 + 4) as u32;

        let mut buffer = Vec::with_capacity(header_length as usize);
        buffer.extend_from_slice(&self.version.to_le_bytes());
        buffer.push(encode_proof_kind(self.kind));
        buffer.extend_from_slice(&self.param_digest.0.bytes);
        let air_spec = self.air_spec_id.clone().bytes();
        buffer.extend_from_slice(&air_spec.bytes);
        buffer.extend_from_slice(&(self.public_inputs.len() as u32).to_le_bytes());
        buffer.extend_from_slice(&self.public_inputs);
        buffer.extend_from_slice(&self.commitment_digest.bytes);
        buffer.extend_from_slice(&header_length.to_le_bytes());
        buffer.extend_from_slice(&body_length.to_le_bytes());
        buffer
    }

    pub fn serialize_payload(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&self.merkle.core_root);
        buffer.extend_from_slice(&self.merkle.aux_root);
        buffer.extend_from_slice(&(self.merkle.fri_layer_roots.len() as u32).to_le_bytes());
        for root in &self.merkle.fri_layer_roots {
            buffer.extend_from_slice(root);
        }

        buffer.extend_from_slice(&(self.openings.out_of_domain.len() as u32).to_le_bytes());
        for opening in &self.openings.out_of_domain {
            let encoded = opening.serialize();
            buffer.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
            buffer.extend_from_slice(&encoded);
        }

        let fri_bytes = serialize_fri_proof(&self.fri_proof);
        buffer.extend_from_slice(&(fri_bytes.len() as u32).to_le_bytes());
        buffer.extend_from_slice(&fri_bytes);

        buffer.push(self.telemetry.fri_parameters.fold);
        buffer.extend_from_slice(&self.telemetry.fri_parameters.cap_degree.to_le_bytes());
        buffer.extend_from_slice(&self.telemetry.fri_parameters.cap_size.to_le_bytes());
        buffer.extend_from_slice(&self.telemetry.fri_parameters.query_budget.to_le_bytes());
        buffer
    }
}

impl OutOfDomainOpening {
    pub(crate) fn serialize(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&self.point);
        buffer.extend_from_slice(&(self.core_values.len() as u32).to_le_bytes());
        for value in &self.core_values {
            buffer.extend_from_slice(value);
        }
        buffer.extend_from_slice(&(self.aux_values.len() as u32).to_le_bytes());
        for value in &self.aux_values {
            buffer.extend_from_slice(value);
        }
        buffer.extend_from_slice(&self.composition_value);
        buffer
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, VerifyError> {
        let mut cursor = Cursor::new(bytes);
        let point = cursor.read_digest()?;
        let core_len = cursor.read_u32()? as usize;
        let mut core_values = Vec::with_capacity(core_len);
        for _ in 0..core_len {
            core_values.push(cursor.read_digest()?);
        }
        let aux_len = cursor.read_u32()? as usize;
        let mut aux_values = Vec::with_capacity(aux_len);
        for _ in 0..aux_len {
            aux_values.push(cursor.read_digest()?);
        }
        let composition_value = cursor.read_digest()?;
        if cursor.remaining() != 0 {
            return Err(VerifyError::UnexpectedEndOfBuffer(
                "ood_padding".to_string(),
            ));
        }
        Ok(Self {
            point,
            core_values,
            aux_values,
            composition_value,
        })
    }
}

/// Thin cursor helper used by the serializer/deserializer.
struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.offset)
    }

    fn offset(&self) -> usize {
        self.offset
    }

    fn read_u8(&mut self) -> Result<u8, VerifyError> {
        if self.remaining() < 1 {
            return Err(VerifyError::UnexpectedEndOfBuffer("u8".to_string()));
        }
        let value = self.bytes[self.offset];
        self.offset += 1;
        Ok(value)
    }

    fn read_u16(&mut self) -> Result<u16, VerifyError> {
        let bytes = self.read_fixed::<2>()?;
        Ok(u16::from_le_bytes(bytes))
    }

    fn read_u32(&mut self) -> Result<u32, VerifyError> {
        let bytes = self.read_fixed::<4>()?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn read_vec(&mut self, len: usize) -> Result<Vec<u8>, VerifyError> {
        if self.remaining() < len {
            return Err(VerifyError::UnexpectedEndOfBuffer("vec".to_string()));
        }
        let slice = &self.bytes[self.offset..self.offset + len];
        self.offset += len;
        Ok(slice.to_vec())
    }

    fn read_digest(&mut self) -> Result<[u8; 32], VerifyError> {
        self.read_fixed::<32>()
    }

    fn read_fixed<const N: usize>(&mut self) -> Result<[u8; N], VerifyError> {
        if self.remaining() < N {
            return Err(VerifyError::UnexpectedEndOfBuffer("fixed".to_string()));
        }
        let mut out = [0u8; N];
        out.copy_from_slice(&self.bytes[self.offset..self.offset + N]);
        self.offset += N;
        Ok(out)
    }
}

impl Default for DigestBytes {
    fn default() -> Self {
        Self { bytes: [0u8; 32] }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        build_prover_context, compute_param_digest, ChunkingPolicy, ParamDigest, ProofKind,
        ProofSystemConfig, ThreadPoolProfile, COMMON_IDENTIFIERS, PROFILE_STANDARD_CONFIG,
        PROOF_VERSION_V1,
    };
    use crate::field::FieldElement;
    use crate::fri::FriSecurityLevel;
    use crate::proof::prover::build_envelope as build_proof_envelope;
    use crate::proof::public_inputs::{ExecutionHeaderV1, PublicInputVersion, PublicInputs};
    use crate::utils::serialization::{DigestBytes, WitnessBlob};

    fn sample_fri_proof() -> FriProof {
        let evaluations: Vec<FieldElement> =
            (0..1024).map(|i| FieldElement(i as u64 + 1)).collect();
        let seed = [7u8; 32];
        FriProof::prove(FriSecurityLevel::Standard, seed, &evaluations).expect("fri proof")
    }

    fn build_sample_proof() -> Proof {
        let fri_proof = sample_fri_proof();
        let fri_layer_roots = fri_proof.layer_roots.clone();
        let core_root = fri_layer_roots.first().copied().unwrap_or([0u8; 32]);
        let aux_root = [1u8; 32];
        let commitment_digest = compute_commitment_digest(&core_root, &aux_root, &fri_layer_roots);

        let header = ExecutionHeaderV1 {
            version: PublicInputVersion::V1,
            program_digest: DigestBytes { bytes: [2u8; 32] },
            trace_length: 1024,
            trace_width: 16,
        };
        let body_bytes: Vec<u8> = Vec::new();
        let public_inputs = PublicInputs::Execution {
            header: header.clone(),
            body: &body_bytes,
        };
        let public_input_bytes = crate::proof::ser::serialize_public_inputs(&public_inputs);

        let merkle = MerkleProofBundle {
            core_root,
            aux_root,
            fri_layer_roots,
        };

        let telemetry = Telemetry {
            header_length: 0,
            body_length: 0,
            fri_parameters: FriParametersMirror {
                fold: 2,
                cap_degree: 256,
                cap_size: fri_proof.final_polynomial.len() as u32,
                query_budget: FriSecurityLevel::Standard.query_budget() as u16,
            },
            integrity_digest: DigestBytes::default(),
        };

        let mut proof = Proof {
            version: PROOF_VERSION,
            kind: ProofKind::Tx,
            param_digest: ParamDigest(DigestBytes { bytes: [3u8; 32] }),
            air_spec_id: AirSpecId(DigestBytes { bytes: [4u8; 32] }),
            public_inputs: public_input_bytes,
            commitment_digest: DigestBytes {
                bytes: commitment_digest,
            },
            merkle,
            openings: Openings {
                out_of_domain: Vec::new(),
            },
            fri_proof,
            telemetry,
        };

        let payload = proof.serialize_payload();
        let header_bytes = proof.serialize_header(&payload);
        proof.telemetry.body_length = (payload.len() + 32) as u32;
        proof.telemetry.header_length = header_bytes.len() as u32;
        let integrity = compute_integrity_digest(&header_bytes, &payload);
        proof.telemetry.integrity_digest = DigestBytes { bytes: integrity };

        proof
    }

    fn witness_blob(len: usize) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(4 + len * 8);
        bytes.extend_from_slice(&(len as u32).to_le_bytes());
        for i in 0..len {
            bytes.extend_from_slice(&(i as u64 + 1).to_le_bytes());
        }
        bytes
    }

    #[test]
    fn proof_envelope_serialization_is_deterministic() {
        let proof_a = build_sample_proof();
        let proof_b = build_sample_proof();
        assert_eq!(proof_a.to_bytes(), proof_b.to_bytes());
    }

    #[test]
    fn proof_envelope_roundtrip_preserves_structure() {
        let proof = build_sample_proof();
        let bytes = proof.to_bytes();
        let decoded = Proof::from_bytes(&bytes).expect("roundtrip");
        assert_eq!(decoded, proof);
    }

    #[test]
    fn proof_envelope_detects_integrity_mismatch() {
        let proof = build_sample_proof();
        let mut bytes = proof.to_bytes();
        let last = bytes.last_mut().expect("non-empty proof");
        *last ^= 0x01;
        let err = Proof::from_bytes(&bytes).expect_err("integrity mismatch");
        assert_eq!(err, VerifyError::IntegrityDigestMismatch);
    }

    #[test]
    fn prover_pipeline_produces_identical_proof_bytes() {
        let profile = PROFILE_STANDARD_CONFIG.clone();
        let common = COMMON_IDENTIFIERS.clone();
        let param_digest = compute_param_digest(&profile, &common);
        let config = ProofSystemConfig {
            proof_version: PROOF_VERSION_V1,
            profile: profile.clone(),
            param_digest: param_digest.clone(),
        };
        let prover_context = build_prover_context(
            &profile,
            &common,
            &param_digest,
            ThreadPoolProfile::SingleThread,
            ChunkingPolicy {
                min_chunk_items: 64,
                max_chunk_items: 256,
                stride: 1,
            },
        );

        let body_bytes: Vec<u8> = Vec::new();
        let header = ExecutionHeaderV1 {
            version: PublicInputVersion::V1,
            program_digest: DigestBytes { bytes: [5u8; 32] },
            trace_length: 1024,
            trace_width: 16,
        };
        let public_inputs = PublicInputs::Execution {
            header: header.clone(),
            body: &body_bytes,
        };

        let witness_bytes = witness_blob(1024);
        let envelope_a = build_proof_envelope(
            &public_inputs,
            WitnessBlob {
                bytes: &witness_bytes,
            },
            &config,
            &prover_context,
        )
        .expect("first envelope");
        let envelope_b = build_proof_envelope(
            &public_inputs,
            WitnessBlob {
                bytes: &witness_bytes,
            },
            &config,
            &prover_context,
        )
        .expect("second envelope");

        assert_eq!(envelope_a.to_bytes(), envelope_b.to_bytes());
    }
}
