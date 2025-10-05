use core::fmt;

use crate::field::FieldElement;
use crate::hash::merkle::{MerkleError, MerklePathElement};

/// Transcript seed used when instantiating the FRI prover and verifier.
pub type FriTranscriptSeed = [u8; 32];

/// Security profiles supported by the FRI engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FriSecurityLevel {
    /// Standard profile with 64 queries.
    Standard,
    /// High security profile with 96 queries.
    HiSec,
    /// Throughput oriented profile with 48 queries.
    Throughput,
}

impl FriSecurityLevel {
    /// Returns the query budget associated with the profile.
    pub const fn query_budget(self) -> usize {
        match self {
            FriSecurityLevel::Standard => 64,
            FriSecurityLevel::HiSec => 96,
            FriSecurityLevel::Throughput => 48,
        }
    }

    pub(crate) fn tag(self) -> &'static str {
        match self {
            FriSecurityLevel::Standard => "STD",
            FriSecurityLevel::HiSec => "HISEC",
            FriSecurityLevel::Throughput => "THR",
        }
    }
}

/// Version tag attached to FRI proofs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FriProofVersion {
    /// Initial version of the binary FRI proof format.
    V1,
}

impl FriProofVersion {
    /// Latest supported proof version.
    pub const CURRENT: FriProofVersion = FriProofVersion::V1;
}

/// Kind markers used when reporting serialization errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SerKind {
    /// Parameters payload framing.
    Params,
    /// Proof body framing.
    Proof,
    /// Query openings payload framing.
    Query,
    /// Layer openings payload framing.
    Layer,
    /// Final polynomial encoding.
    FinalPolynomial,
}

impl fmt::Display for SerKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SerKind::Params => write!(f, "parameters"),
            SerKind::Proof => write!(f, "proof"),
            SerKind::Query => write!(f, "query"),
            SerKind::Layer => write!(f, "layer"),
            SerKind::FinalPolynomial => write!(f, "final polynomial"),
        }
    }
}

/// FRI verification errors mapped to the specification failure classes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FriError {
    /// Proof version mismatch.
    VersionMismatch {
        /// Expected proof version for the verifier.
        expected: FriProofVersion,
        /// Version declared by the proof being processed.
        actual: FriProofVersion,
    },
    /// Folding constraints were violated during verification.
    FoldingConstraintViolated {
        /// Layer index where the folding constraint failed.
        layer: usize,
    },
    /// Out-of-domain sampling failed.
    OodsInvalid,
    /// Serialization failure when decoding proof artefacts.
    Serialization(SerKind),
    /// No evaluations were provided to the prover.
    EmptyCodeword,
    /// Query position exceeded the LDE domain size.
    QueryOutOfRange {
        /// Position outside the evaluation domain.
        position: usize,
    },
    /// Merkle path was malformed (index byte mismatch or inconsistent height).
    PathInvalid {
        /// Layer where the invalid path was detected.
        layer: usize,
        /// Underlying Merkle verification error.
        reason: MerkleError,
    },
    /// Merkle layer root mismatch.
    LayerRootMismatch {
        /// Layer index that produced a different root.
        layer: usize,
    },
    /// Proof declared a different security profile.
    SecurityLevelMismatch,
    /// Proof declared an unexpected number of queries.
    QueryBudgetMismatch {
        /// Expected number of queries for the security profile.
        expected: usize,
        /// Actual number of queries provided by the proof.
        actual: usize,
    },
    /// Generic structure error (missing layer, inconsistent lengths, etc.).
    InvalidStructure(&'static str),
}

impl fmt::Display for FriError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FriError::VersionMismatch { expected, actual } => {
                write!(
                    f,
                    "proof version mismatch (expected {expected:?}, got {actual:?})"
                )
            }
            FriError::FoldingConstraintViolated { layer } => {
                write!(f, "folding constraint violated at layer {layer}")
            }
            FriError::OodsInvalid => write!(f, "out-of-domain sampling constraint failed"),
            FriError::Serialization(kind) => {
                write!(f, "failed to serialize/deserialize FRI {kind}")
            }
            FriError::EmptyCodeword => write!(f, "codeword is empty"),
            FriError::QueryOutOfRange { position } => {
                write!(f, "query position {position} outside evaluation domain")
            }
            FriError::PathInvalid { layer, reason } => {
                write!(f, "invalid Merkle path at layer {layer}: {reason}")
            }
            FriError::LayerRootMismatch { layer } => {
                write!(f, "layer {layer} root mismatch")
            }
            FriError::SecurityLevelMismatch => write!(f, "security profile mismatch"),
            FriError::QueryBudgetMismatch { expected, actual } => write!(
                f,
                "query budget mismatch (expected {expected}, got {actual})"
            ),
            FriError::InvalidStructure(reason) => write!(f, "invalid proof structure: {reason}"),
        }
    }
}

impl std::error::Error for FriError {}

/// Declarative representation of a single query opening.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FriQuery {
    /// Position sampled from the LDE domain.
    pub position: usize,
    /// Layer openings ascending from the original codeword to the residual layer.
    pub layers: Vec<FriQueryLayer>,
    /// Value revealed at the residual polynomial for this query.
    pub final_value: FieldElement,
}

/// Opening data for a specific FRI layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FriQueryLayer {
    /// Evaluation revealed at this layer.
    pub value: FieldElement,
    /// Merkle authentication path proving membership.
    pub path: Vec<MerklePathElement>,
}

/// Declarative representation of a FRI proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FriProof {
    /// Declared security profile for the proof.
    pub security_level: FriSecurityLevel,
    /// Size of the initial evaluation domain.
    pub initial_domain_size: usize,
    /// Merkle roots for each folded layer.
    pub layer_roots: Vec<[u8; 32]>,
    /// Residual polynomial evaluations.
    pub final_polynomial: Vec<FieldElement>,
    /// Digest binding the final polynomial values.
    pub final_polynomial_digest: [u8; 32],
    /// Query openings.
    pub queries: Vec<FriQuery>,
}

/// Borrowed view over the parameters required when verifying a proof.
#[derive(Debug, Clone, Copy)]
pub struct FriParamsView<'a> {
    /// Declared proof version.
    pub version: FriProofVersion,
    /// Security profile used for the proof.
    pub security_level: FriSecurityLevel,
    /// Query plan identifier derived from the security level.
    pub query_plan: &'a [u8; 32],
}
