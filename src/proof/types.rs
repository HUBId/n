use crate::config::ParamDigest;
use crate::utils::serialization::DigestBytes;
use serde::{Deserialize, Serialize};

/// Canonical proof version implemented by this crate.
pub const PROOF_VERSION: u16 = 1;

/// Canonical number of α challenges drawn from the Fiat–Shamir transcript.
///
/// The specification fixes the composition vector to four coefficients so the
/// prover and verifier must always request exactly four challenges.
pub const PROOF_ALPHA_VECTOR_LEN: usize = 4;

/// Minimum number of out-of-domain points drawn before sealing the transcript.
///
/// The prover samples two ζ challenges to satisfy the DEEP consistency checks;
/// verifiers must reject envelopes declaring fewer OOD openings.
pub const PROOF_MIN_OOD_POINTS: usize = 2;

/// Maximum query budget a canonical proof is allowed to declare.
///
/// All shipping profiles stay within 128 FRI queries which bounds the
/// transcript sampling and telemetry reporting.
pub const PROOF_MAX_QUERY_COUNT: usize = 128;

/// Maximum cap polynomial degree recorded in the telemetry frame.
///
/// Proof builders cap this value at the advertised FRI depth range which never
/// exceeds twenty in the current specification.
pub const PROOF_TELEMETRY_MAX_CAP_DEGREE: u16 = 20;

/// Maximum final-polynomial cap size recorded in telemetry.
///
/// Query caps are limited to the canonical 128 query budget, so the telemetry
/// payload may not declare a larger commitment.
pub const PROOF_TELEMETRY_MAX_CAP_SIZE: u32 = 128;

/// Maximum query budget mirrored in the telemetry section.
///
/// The telemetry frame mirrors the configured FRI security level and is
/// bounded by the 128-query cap mandated by the specification.
pub const PROOF_TELEMETRY_MAX_QUERY_BUDGET: u16 = 128;

/// Fully decoded proof container mirroring the authoritative specification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proof {
    /// Declared proof version (currently `1`).
    #[serde(with = "proof_version_codec")]
    pub version: u16,
    /// Parameter digest binding configuration knobs.
    pub param_digest: ParamDigest,
    /// Digest binding the declared public values.
    pub public_digest: DigestBytes,
    /// Trace commitment bundle for core and auxiliary roots.
    pub trace_commitment: TraceCommitment,
    /// Optional composition polynomial commitment digest.
    pub composition_commitment: Option<DigestBytes>,
    /// Out-of-domain opening payloads.
    pub openings: Openings,
    /// Optional telemetry frame describing declared lengths and digests.
    pub telemetry: Option<Telemetry>,
}

/// Serialization failure domains for proof encoding/decoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SerKind {
    /// Top-level proof framing.
    Proof,
    /// Trace commitment section.
    TraceCommitment,
    /// Optional composition commitment digest.
    CompositionCommitment,
    /// Out-of-domain openings section.
    Openings,
    /// Telemetry frame storing auxiliary metadata.
    Telemetry,
    /// Public digest body.
    PublicDigest,
}

/// Trace commitment bundle covering core and auxiliary roots.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceCommitment {
    /// Digest binding commitments prior to parsing the body.
    pub commitment_digest: DigestBytes,
    /// Core commitment root.
    pub core_root: [u8; 32],
    /// Auxiliary commitment root (zero if absent).
    pub aux_root: [u8; 32],
}

impl TraceCommitment {
    /// Constructs a bundle from the provided roots without additional checks.
    pub fn new(commitment_digest: DigestBytes, core_root: [u8; 32], aux_root: [u8; 32]) -> Self {
        Self {
            commitment_digest,
            core_root,
            aux_root,
        }
    }
}

/// Out-of-domain opening container.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Openings {
    /// Individual out-of-domain openings.
    pub out_of_domain: Vec<OutOfDomainOpening>,
}

/// Telemetry frame exposing declared lengths and digests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Telemetry {
    /// Declared header length (used for sanity checks).
    pub header_length: u32,
    /// Declared body length (includes integrity digest).
    pub body_length: u32,
    /// Integrity digest covering the header bytes and body payload.
    pub integrity_digest: DigestBytes,
}

/// Structured verification report pairing a decoded proof with the outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyReport {
    /// Fully decoded proof container.
    pub proof: Proof,
    /// Flag indicating whether parameter hashing checks succeeded.
    #[serde(default)]
    pub params_ok: bool,
    /// Flag indicating whether public digest binding checks succeeded.
    #[serde(default)]
    pub public_digest_ok: bool,
    /// Flag indicating whether trace commitment checks succeeded.
    #[serde(default)]
    pub trace_ok: bool,
    /// Flag indicating whether composition polynomial openings matched expectations.
    #[serde(default)]
    pub composition_ok: bool,
    /// Total serialized byte length observed during verification.
    #[serde(default)]
    pub total_bytes: u64,
    /// Optional verification error captured during decoding or checks.
    pub error: Option<VerifyError>,
}

/// Errors surfaced while decoding or validating a proof envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MerkleSection {
    /// Commitment digest derived from advertised roots mismatched expectations.
    CommitmentDigest,
    /// Authentication path validation failed while replaying trace queries.
    TracePath,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerifyError {
    /// The proof version encoded in the header is not supported.
    VersionMismatch { expected: u16, actual: u16 },
    /// Declared header length does not match the observed byte count.
    HeaderLengthMismatch { declared: u32, actual: u32 },
    /// Declared body length does not match the observed byte count.
    BodyLengthMismatch { declared: u32, actual: u32 },
    /// The buffer ended prematurely while parsing a section.
    UnexpectedEndOfBuffer(String),
    /// Integrity digest recomputed from the payload disagreed with the header.
    IntegrityDigestMismatch,
    /// Encountered a non-canonical field element while decoding.
    NonCanonicalFieldElement,
    /// Parameter digest did not match the expected configuration digest.
    ParamsHashMismatch,
    /// Public digest failed decoding or did not match the expected layout.
    PublicDigestMismatch,
    /// Transcript phases were emitted out of order or with missing tags.
    TranscriptOrder,
    /// Out-of-domain openings were malformed or contained inconsistent values.
    OutOfDomainInvalid,
    /// Trace commitment verification failed for a specific section.
    MerkleVerifyFailed { section: MerkleSection },
    /// Composition polynomial exceeded declared degree bounds.
    DegreeBoundExceeded,
    /// Proof exceeded the configured maximum proof size.
    ProofTooLarge,
    /// Proof declared openings but none were provided in the payload.
    EmptyOpenings,
    /// Query indices were not strictly increasing or contained duplicates.
    IndicesDuplicate,
    /// Aggregated digest did not match the recomputed digest during batching.
    AggregationDigestMismatch,
    /// Malformed serialization encountered while decoding a proof section.
    Serialization(SerKind),
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
