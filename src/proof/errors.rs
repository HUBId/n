//! Error classes emitted by the verification pipeline.
//!
//! The enumeration mirrors the canonical failure names required by the
//! specification. Each variant documents the exact condition that should
//! trigger the error. No implementation logic is provided.

/// Failure classes surfaced during verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationFailure {
    /// Envelope structure was malformed (length mismatch, unsupported version).
    ErrEnvelopeMalformed,
    /// Parameter digest did not match the expected configuration digest.
    ErrParamDigestMismatch,
    /// Public inputs failed decoding or did not match the expected layout.
    ErrPublicInputMismatch,
    /// Commitment digest recomputed by the verifier disagreed with the header.
    ErrCommitmentDigestMismatch,
    /// Transcript phases were emitted out of order or with missing tags.
    ErrTranscriptOrder,
    /// Out-of-domain openings were malformed or contained inconsistent values.
    ErrOODInvalid,
    /// FRI layer root did not match the recomputed value.
    ErrFRILayerRootMismatch,
    /// Merkle authentication path invalid (sibling ordering wrong or hash mismatch).
    ErrFRIPathInvalid,
    /// Query position derived from transcript exceeded the domain bounds.
    ErrFRIQueryOutOfRange,
    /// Composition polynomial exceeded declared degree bounds.
    ErrDegreeBoundExceeded,
    /// Proof exceeded the configured maximum proof size.
    ErrProofTooLarge,
    /// Integrity digest covering header and body did not match.
    ErrIntegrityDigestMismatch,
    /// Aggregated digest did not match the recomputed digest during batching.
    ErrAggregationDigestMismatch,
}
