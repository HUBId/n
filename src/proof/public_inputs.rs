//! Declarative description of public input layouts per proof kind.
//!
//! The goal of this module is to document, rather than implement, how public
//! inputs are structured across the different proof categories supported by
//! the STARK engine. Each structure captures the versioned header fields that
//! must be present before any proof specific body is interpreted.

use crate::utils::serialization::{DigestBytes, FieldElementBytes};

/// Enumerates all supported proof kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofKind {
    /// Proves a single execution trace.
    Execution,
    /// Aggregates multiple execution proofs into a compressed certificate.
    Aggregation,
    /// Wraps recursion layers for rollup scenarios.
    Recursion,
}

/// Version tag for public input headers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicInputVersion {
    /// First stable version of the documentation.
    V1,
}

/// Public input header for execution proofs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionHeaderV1 {
    /// Version of the header format.
    pub version: PublicInputVersion,
    /// Hash of the program being executed.
    pub program_digest: DigestBytes,
    /// Length of the execution trace in field elements.
    pub trace_length: u32,
    /// Selector indicating if the trace is padded.
    pub padded: bool,
}

/// Public input header for aggregation proofs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AggregationHeaderV1 {
    /// Version of the header format.
    pub version: PublicInputVersion,
    /// Digest of the aggregation circuit definition.
    pub circuit_digest: DigestBytes,
    /// Number of included leaf proofs.
    pub leaf_count: u32,
    /// Commitment to the root of the aggregation tree.
    pub root_digest: DigestBytes,
}

/// Public input header for recursion proofs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecursionHeaderV1 {
    /// Version of the header format.
    pub version: PublicInputVersion,
    /// Depth of the recursion stack.
    pub depth: u8,
    /// Digest binding the recursion boundary values.
    pub boundary_digest: DigestBytes,
    /// Field element that seeds the recursive verifier context.
    pub recursion_seed: FieldElementBytes,
}

/// Unified container for public inputs across proof kinds.
#[derive(Debug, Clone)]
pub enum PublicInputs<'a> {
    /// Execution proof layout.
    Execution {
        /// Header metadata.
        header: ExecutionHeaderV1,
        /// Body bytes (application specific data).
        body: &'a [u8],
    },
    /// Aggregation proof layout.
    Aggregation {
        /// Header metadata.
        header: AggregationHeaderV1,
        /// Serialized accumulator witnesses.
        body: &'a [u8],
    },
    /// Recursion proof layout.
    Recursion {
        /// Header metadata.
        header: RecursionHeaderV1,
        /// Serialized recursion stack body.
        body: &'a [u8],
    },
}

impl<'a> PublicInputs<'a> {
    /// Returns the declared proof kind for these public inputs.
    pub fn kind(&self) -> ProofKind {
        match self {
            Self::Execution { .. } => ProofKind::Execution,
            Self::Aggregation { .. } => ProofKind::Aggregation,
            Self::Recursion { .. } => ProofKind::Recursion,
        }
    }
}
