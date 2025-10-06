use crate::config::{AirSpecId, ParamDigest, ProofKind};
use crate::fri::FriProof;
use crate::utils::serialization::DigestBytes;
use serde::{Deserialize, Serialize};

/// Canonical proof version implemented by this crate.
pub const PROOF_VERSION: u16 = 1;

/// Fully decoded proof container mirroring the authoritative specification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proof {
    /// Declared proof version (currently `1`).
    #[serde(with = "proof_version_codec")]
    pub version: u16,
    /// Canonical proof kind stored in the envelope header.
    #[serde(with = "proof_kind_codec")]
    pub kind: ProofKind,
    /// Parameter digest binding configuration knobs.
    pub param_digest: ParamDigest,
    /// AIR specification identifier for the proof kind.
    pub air_spec_id: AirSpecId,
    /// Canonical public input encoding.
    pub public_inputs: Vec<u8>,
    /// Digest binding commitments prior to parsing the body.
    pub commitment_digest: DigestBytes,
    /// Merkle commitment bundle for core, auxiliary and FRI layers.
    pub merkle: MerkleProofBundle,
    /// Out-of-domain opening payloads.
    pub openings: Openings,
    /// FRI proof payload accompanying the envelope.
    pub fri_proof: FriProof,
    /// Telemetry frame describing declared lengths and digests.
    pub telemetry: Telemetry,
}

/// Merkle commitment bundle covering core, auxiliary and FRI layer roots.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleProofBundle {
    /// Core commitment root.
    pub core_root: [u8; 32],
    /// Auxiliary commitment root (zero if absent).
    pub aux_root: [u8; 32],
    /// FRI layer roots emitted during the prover pipeline.
    pub fri_layer_roots: Vec<[u8; 32]>,
}

/// Out-of-domain opening container.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Openings {
    /// Individual out-of-domain openings.
    pub out_of_domain: Vec<OutOfDomainOpening>,
}

/// Telemetry frame exposing declared lengths and FRI parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Telemetry {
    /// Declared header length (used for sanity checks).
    pub header_length: u32,
    /// Declared body length (includes integrity digest).
    pub body_length: u32,
    /// Optional mirror of the FRI parameters encoded in the proof body.
    pub fri_parameters: FriParametersMirror,
    /// Integrity digest covering the header bytes and body payload.
    pub integrity_digest: DigestBytes,
}

/// Structured verification report pairing a decoded proof with the outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyReport {
    /// Fully decoded proof container.
    pub proof: Proof,
    /// Optional verification error captured during decoding or checks.
    pub error: Option<VerifyError>,
}

/// Errors surfaced while decoding or encoding a proof envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerifyError {
    /// The proof version encoded in the header is not supported.
    UnsupportedVersion(u16),
    /// The proof kind byte does not match the canonical ordering.
    UnknownProofKind(u8),
    /// Declared header length does not match the observed byte count.
    HeaderLengthMismatch { declared: u32, actual: u32 },
    /// Declared body length does not match the observed byte count.
    BodyLengthMismatch { declared: u32, actual: u32 },
    /// The buffer ended prematurely while parsing a section.
    UnexpectedEndOfBuffer(String),
    /// Integrity digest recomputed from the payload disagreed with the header.
    IntegrityDigestMismatch,
    /// The FRI section contained invalid structure.
    InvalidFriSection(String),
    /// Encountered a non-canonical field element while decoding.
    NonCanonicalFieldElement,
}

/// Mirror of the FRI parameters stored inside the proof body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FriParametersMirror {
    /// Folding factor (fixed to two in the current implementation).
    pub fold: u8,
    /// Degree of the cap polynomial.
    pub cap_degree: u16,
    /// Size of the cap commitment.
    pub cap_size: u32,
    /// Query budget consumed during verification.
    pub query_budget: u16,
}

impl Default for FriParametersMirror {
    fn default() -> Self {
        Self {
            fold: 2,
            cap_degree: 0,
            cap_size: 0,
            query_budget: 0,
        }
    }
}

/// Out-of-domain opening description stored in the proof body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutOfDomainOpening {
    /// OOD evaluation point.
    pub point: [u8; 32],
    /// Core trace evaluations at that point.
    pub core_values: Vec<[u8; 32]>,
    /// Auxiliary evaluations.
    pub aux_values: Vec<[u8; 32]>,
    /// Composition polynomial evaluation.
    pub composition_value: [u8; 32],
}

mod proof_kind_codec {
    use super::ProofKind;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &ProofKind, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u8(encode(*value))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<ProofKind, D::Error>
    where
        D: Deserializer<'de>,
    {
        let byte = u8::deserialize(deserializer)?;
        decode(byte).map_err(serde::de::Error::custom)
    }

    fn encode(kind: ProofKind) -> u8 {
        match kind {
            ProofKind::Tx => 0,
            ProofKind::State => 1,
            ProofKind::Pruning => 2,
            ProofKind::Uptime => 3,
            ProofKind::Consensus => 4,
            ProofKind::Identity => 5,
            ProofKind::Aggregation => 6,
            ProofKind::VRF => 7,
        }
    }

    fn decode(byte: u8) -> Result<ProofKind, &'static str> {
        Ok(match byte {
            0 => ProofKind::Tx,
            1 => ProofKind::State,
            2 => ProofKind::Pruning,
            3 => ProofKind::Uptime,
            4 => ProofKind::Consensus,
            5 => ProofKind::Identity,
            6 => ProofKind::Aggregation,
            7 => ProofKind::VRF,
            _ => return Err("unknown proof kind"),
        })
    }
}

mod proof_version_codec {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &u16, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u16(*value)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<u16, D::Error>
    where
        D: Deserializer<'de>,
    {
        u16::deserialize(deserializer)
    }
}
