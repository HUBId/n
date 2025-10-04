//! Proof envelope describing versioned byte layout and integrity bindings.
//!
//! The envelope is the canonical container that wraps every proof byte stream
//! produced by the system. Only the structure is documented; no serialization
//! helpers are provided so that implementers can integrate their own I/O layer.

use crate::config::ParamDigest;
use crate::proof::public_inputs::ProofKind;
use crate::utils::serialization::DigestBytes;

/// Specification object capturing the envelope layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProofEnvelopeSpec;

impl ProofEnvelopeSpec {
    /// Fixed order of the top-level fields (all little-endian).
    pub const FIELD_ORDER: &'static [&'static str] = &[
        "ProofVersion:u8",
        "ProofKind:u8",
        "HeaderLength:u32",
        "HeaderBytes",
        "BodyLength:u32",
        "BodyBytes",
        "IntegrityDigest:32B",
    ];

    /// Internal ordering of the header payload.
    pub const HEADER_ORDER: &'static [&'static str] = &[
        "PublicInputHeader (Phase-2 layout with length prefixes)",
        "ParamDigest:32B",
        "CommitmentDigest:32B",
    ];

    /// Internal ordering of the body payload.
    pub const BODY_ORDER: &'static [&'static str] = &[
        "Commitments: CoreRoot || AuxRoot || FRI-Layer-Roots",
        "OOD-Openings: per OOD point (coordinates + Core/Aux/Composition values)",
        "FRI-Proof: folding params, openings, queries, 4-ary Merkle paths",
    ];

    /// Initial proof version (must increment for backward incompatible changes).
    pub const INITIAL_VERSION: u8 = 1;
}

/// Structured representation of the proof envelope header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofEnvelopeHeader {
    /// Proof version as encoded in the envelope.
    pub proof_version: u8,
    /// Proof kind using canonical RPP coding.
    pub proof_kind: ProofKind,
    /// Length of the serialized header payload in bytes.
    pub header_length: u32,
    /// Phase-2 public input header bytes.
    pub public_input_header: Vec<u8>,
    /// Parameter digest binding configuration.
    pub param_digest: ParamDigest,
    /// Commitment digest binding Merkle and FRI roots.
    pub commitment_digest: DigestBytes,
}

/// Structured representation of the proof envelope body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofEnvelopeBody {
    /// Raw commitment roots (Core, Aux, FRI layers) in canonical order.
    pub commitments: Vec<DigestBytes>,
    /// Out-of-domain opening records (coordinates and values).
    pub ood_openings: Vec<OutOfDomainOpening>,
    /// FRI proof payload including folding schedule and query paths.
    pub fri_proof: FriProofPayload,
}

/// Full envelope container grouping header, body and integrity digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofEnvelope {
    /// Structured header information.
    pub header: ProofEnvelopeHeader,
    /// Body carrying commitments, openings and FRI data.
    pub body: ProofEnvelopeBody,
    /// Integrity digest computed as BLAKE3 over all bytes from ProofVersion
    /// through BodyBytes (inclusive).
    pub integrity_digest: DigestBytes,
}

/// Out-of-domain opening record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutOfDomainOpening {
    /// Evaluation point encoded in little-endian field representation.
    pub point: [u8; 32],
    /// Core trace values at the point (little-endian field encoding).
    pub core_values: Vec<[u8; 32]>,
    /// Auxiliary trace values at the point.
    pub aux_values: Vec<[u8; 32]>,
    /// Composition polynomial value at the point.
    pub composition_value: [u8; 32],
}

/// FRI proof payload in canonical order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FriProofPayload {
    /// Folding parameter description (factor = 4, depth etc.).
    pub folding_parameters: FriFoldingParameters,
    /// Openings collected per query and layer.
    pub layer_openings: Vec<FriLayerOpening>,
    /// Query positions derived from transcript seeds.
    pub query_positions: Vec<u32>,
    /// Merkle paths using 4-ary encoding with explicit index bytes.
    pub merkle_paths: Vec<FriMerklePath>,
}

/// Folding parameters for FRI recursion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FriFoldingParameters {
    /// Fold factor (fixed to 4).
    pub fold_factor: u8,
    /// Number of recursive layers.
    pub layer_count: u8,
}

/// Opening data for a specific FRI layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FriLayerOpening {
    /// Layer index (0-based, little-endian when serialized).
    pub layer_index: u8,
    /// Field values revealed at this layer.
    pub values: Vec<[u8; 32]>,
}

/// Merkle authentication path for a single query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FriMerklePath {
    /// Index bytes in range [0,3] describing sibling ordering per level.
    pub index_bytes: Vec<u8>,
    /// Sibling digests for each level (little-endian order of concatenation).
    pub sibling_digests: Vec<DigestBytes>,
}
