//! Low-degree extension parameterisation.
//!
//! This module no longer exposes imperative extension helpers but instead
//! collects the metadata required by FFT back-ends and audit tooling.  The
//! parameters describe how a trace polynomial is transformed into an evaluation
//! domain, covering blowup factors, deterministic evaluation ordering, mapping
//! conventions and chunking constraints.

/// Ordering in which evaluation points are produced by the LDE engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvaluationOrder {
    /// Natural ordering, where the first evaluation corresponds to the first
    /// coset element and the sequence progresses monotonically.
    Natural,
    /// Bit-reversed ordering to match in-place radix-2 FFT algorithms.
    BitReversed,
}

/// Endianness used when serialising polynomial coefficients into Montgomery
/// limbs for the evaluation domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoefficientEndianness {
    /// Least significant limb first (little endian).
    Little,
    /// Most significant limb first (big endian).
    Big,
}

/// Mapping strategy that explains how trace rows and columns are placed within
/// the LDE evaluation domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceToLdeMapping {
    /// Each trace row is expanded contiguously before advancing to the next
    /// row.  The LDE therefore mirrors a row-major trace layout.
    RowMajorContiguous,
    /// Trace columns are interleaved so that each column occupies a distinct
    /// coset stride.  This is typically used for high-security profiles.
    ColumnInterleaved,
}

/// Deterministic chunking rules for distributing LDE work across workers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkingDeterminism {
    /// Chunks are assigned by natural domain order; chunk `i` always contains
    /// the evaluations `i * chunk_size..(i + 1) * chunk_size`.
    DomainMajor,
    /// Chunks are allocated in a worker-major fashion where each worker is
    /// given contiguous rows before moving to the next worker id.
    WorkerMajor,
}

/// Strategy describing how the evaluation domain is partitioned deterministically.
#[derive(Debug, Clone, Copy)]
pub struct ChunkingStrategy {
    /// Number of evaluation points per deterministic chunk.
    pub chunk_size: usize,
    /// Deterministic ordering by which chunks are assigned.
    pub determinism: ChunkingDeterminism,
    /// Human readable explanation for audit logs.
    pub description: &'static str,
}

/// Parameters describing a low-degree extension profile.
#[derive(Debug, Clone, Copy)]
pub struct LowDegreeExtensionParameters {
    /// Multiplicative blowup factor applied to the trace domain.
    pub blowup_factor: usize,
    /// Ordering of the evaluation sequence.
    pub evaluation_order: EvaluationOrder,
    /// Endianness used for Montgomery representation.
    pub coefficient_endianness: CoefficientEndianness,
    /// Mapping from trace layout to the LDE domain.
    pub trace_mapping: TraceToLdeMapping,
    /// Deterministic chunking constraints.
    pub chunking: ChunkingStrategy,
}

/// Trait implemented by profiles capable of describing their parameters.
pub trait LowDegreeExtensionProfile {
    /// Returns the parameters describing this profile.
    fn parameters(&self) -> &'static LowDegreeExtensionParameters;
}

/// Standard ×8 blowup profile.
///
/// * **Evaluation order:** [`EvaluationOrder::BitReversed`] to optimise for
///   in-place radix-2 FFTs.  The first chunk therefore contains the bit-reverse
///   of indices `[0, chunk_size)`, matching historical prover expectations.
/// * **Endianness:** [`CoefficientEndianness::Little`], encoding least
///   significant limbs first as used by the trace commitment machinery.
/// * **Trace mapping:** [`TraceToLdeMapping::RowMajorContiguous`], i.e. rows are
///   extended one after another and each row contributes `blowup_factor`
///   evaluations.
/// * **Chunking:** Deterministic domain-major chunks of size equal to the
///   `blowup_factor`.  Chunk `i` therefore contains the bit-reversed indices for
///   row `i` and is stable across worker counts.
pub const PROFILE_X8: LowDegreeExtensionParameters = LowDegreeExtensionParameters {
    blowup_factor: 8,
    evaluation_order: EvaluationOrder::BitReversed,
    coefficient_endianness: CoefficientEndianness::Little,
    trace_mapping: TraceToLdeMapping::RowMajorContiguous,
    chunking: ChunkingStrategy {
        chunk_size: 8,
        determinism: ChunkingDeterminism::DomainMajor,
        description:
            "Domain-major deterministic chunks, each covering one row's bit-reversed evaluations",
    },
};

/// High-security ×16 profile used for audit-grade runs.
///
/// * **Evaluation order:** [`EvaluationOrder::Natural`] to simplify manual
///   inspection—chunk `i` begins at index `i * chunk_size` and increases
///   monotonically.
/// * **Endianness:** [`CoefficientEndianness::Little`]; even in audit mode the
///   prover persists Montgomery limbs in little-endian order to maintain
///   compatibility with transcript hashing.
/// * **Trace mapping:** [`TraceToLdeMapping::ColumnInterleaved`], ensuring that
///   each trace column occupies its own coset stride.  This minimises leakage in
///   high-security audits by separating witness columns.
/// * **Chunking:** Worker-major deterministic chunks of size `4 * blowup_factor`
///   to amortise cache penalties during audit replay.  Workers receive a
///   deterministic sequence of column-major stripes.
pub const PROFILE_HISEC_X16: LowDegreeExtensionParameters = LowDegreeExtensionParameters {
    blowup_factor: 16,
    evaluation_order: EvaluationOrder::Natural,
    coefficient_endianness: CoefficientEndianness::Little,
    trace_mapping: TraceToLdeMapping::ColumnInterleaved,
    chunking: ChunkingStrategy {
        chunk_size: 64,
        determinism: ChunkingDeterminism::WorkerMajor,
        description:
            "Worker-major deterministic stripes, four rows per worker in column-interleaved order",
    },
};

/// Collection of profiles compiled when audit instrumentation is enabled.
#[cfg(feature = "audit-lde")]
pub const AUDIT_PROFILES: &[LowDegreeExtensionParameters] = &[PROFILE_X8];

/// High-security profiles compiled only when the `audit-lde-hisec` feature is
/// enabled.  The feature depends on `audit-lde` to ensure shared reporting
/// infrastructure.
#[cfg(feature = "audit-lde-hisec")]
pub const AUDIT_PROFILE_HISEC: &[LowDegreeExtensionParameters] = &[PROFILE_HISEC_X16];
