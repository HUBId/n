use crate::config::{AirSpecId, ParamDigest, ProofKind};
use crate::fri::FriProof;
use crate::hash::deterministic::DeterministicHashError;
use crate::ser::SerKind;
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

/// Maximum number of FRI layers committed to by a canonical proof.
///
/// Profiles advertise at most twenty folding rounds; exceeding this limit is
/// considered a malformed envelope.
pub const PROOF_MAX_FRI_LAYERS: usize = 20;

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

/// Helper wrapper bundling AIR selection and binding data for a proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompositionBinding {
    #[serde(with = "proof_kind_codec")]
    kind: ProofKind,
    air_spec_id: AirSpecId,
    public_inputs: Vec<u8>,
    composition_commit: Option<DigestBytes>,
}

impl CompositionBinding {
    /// Creates a new binding wrapper for the provided components.
    pub fn new(
        kind: ProofKind,
        air_spec_id: AirSpecId,
        public_inputs: Vec<u8>,
        composition_commit: Option<DigestBytes>,
    ) -> Self {
        Self {
            kind,
            air_spec_id,
            public_inputs,
            composition_commit,
        }
    }

    /// Returns the proof kind advertised by this binding.
    pub fn kind(&self) -> &ProofKind {
        &self.kind
    }

    /// Returns the AIR specification identifier bound to the proof.
    pub fn air_spec_id(&self) -> &AirSpecId {
        &self.air_spec_id
    }

    /// Returns the public-input payload associated with the binding.
    pub fn public_inputs(&self) -> &[u8] {
        &self.public_inputs
    }

    /// Returns a mutable reference to the public-input payload.
    pub fn public_inputs_mut(&mut self) -> &mut Vec<u8> {
        &mut self.public_inputs
    }

    /// Returns the optional composition commitment digest, if present.
    pub fn composition_commit(&self) -> Option<&DigestBytes> {
        self.composition_commit.as_ref()
    }

    /// Returns a mutable reference to the optional composition commitment digest.
    pub fn composition_commit_mut(&mut self) -> Option<&mut DigestBytes> {
        self.composition_commit.as_mut()
    }
}

/// Wrapper storing the low-level FRI proof payload for assembly helpers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FriHandle {
    fri_proof: FriProof,
}

impl FriHandle {
    /// Creates a new handle for the provided FRI proof payload.
    pub fn new(fri_proof: FriProof) -> Self {
        Self { fri_proof }
    }

    /// Returns an immutable reference to the wrapped FRI proof.
    pub fn fri_proof(&self) -> &FriProof {
        &self.fri_proof
    }

    /// Returns a mutable reference to the wrapped FRI proof.
    pub fn fri_proof_mut(&mut self) -> &mut FriProof {
        &mut self.fri_proof
    }
}

/// Fully decoded proof container mirroring the authoritative specification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proof {
    /// Declared proof version (currently `1`).
    #[serde(with = "proof_version_codec")]
    version: u16,
    /// Canonical proof kind stored in the envelope header.
    #[serde(with = "proof_kind_codec")]
    kind: ProofKind,
    /// Parameter digest binding configuration knobs.
    param_digest: ParamDigest,
    /// AIR specification identifier for the proof kind.
    air_spec_id: AirSpecId,
    /// Canonical public input encoding.
    public_inputs: Vec<u8>,
    /// Digest binding the canonical public-input payload.
    public_digest: DigestBytes,
    /// Digest mirroring the declared trace commitment.
    trace_commit: DigestBytes,
    /// Optional digest mirroring the declared composition commitment.
    composition_commit: Option<DigestBytes>,
    /// Merkle commitment bundle for core, auxiliary and FRI layers.
    merkle: MerkleProofBundle,
    /// Out-of-domain opening payloads.
    openings: Openings,
    /// FRI proof payload accompanying the envelope.
    fri_proof: FriProof,
    /// Flag signalling whether the telemetry segment is present in the payload.
    has_telemetry: bool,
    /// Telemetry frame describing declared lengths and digests.
    telemetry: Telemetry,
}

impl Proof {
    /// Returns the declared proof version stored in the envelope header.
    pub fn version(&self) -> u16 {
        self.version
    }

    /// Returns a mutable reference to the declared proof version.
    pub fn version_mut(&mut self) -> &mut u16 {
        &mut self.version
    }

    /// Returns the parameter digest binding configuration for the proof.
    pub fn param_digest(&self) -> &ParamDigest {
        &self.param_digest
    }

    /// Returns a mutable reference to the parameter digest configuration.
    pub fn param_digest_mut(&mut self) -> &mut ParamDigest {
        &mut self.param_digest
    }

    /// Returns the canonical proof kind stored in the envelope header.
    pub fn kind(&self) -> &ProofKind {
        &self.kind
    }

    /// Returns a mutable reference to the canonical proof kind.
    pub fn kind_mut(&mut self) -> &mut ProofKind {
        &mut self.kind
    }

    /// Returns the AIR specification identifier for the proof kind.
    pub fn air_spec_id(&self) -> &AirSpecId {
        &self.air_spec_id
    }

    /// Returns a mutable reference to the AIR specification identifier.
    pub fn air_spec_id_mut(&mut self) -> &mut AirSpecId {
        &mut self.air_spec_id
    }

    /// Returns the canonical public input encoding.
    pub fn public_inputs(&self) -> &[u8] {
        &self.public_inputs
    }

    /// Returns a mutable reference to the canonical public input encoding.
    pub fn public_inputs_mut(&mut self) -> &mut Vec<u8> {
        &mut self.public_inputs
    }

    /// Returns the digest binding the canonical public-input payload.
    pub fn public_digest(&self) -> &DigestBytes {
        &self.public_digest
    }

    /// Returns a mutable reference to the public-input digest binding.
    pub fn public_digest_mut(&mut self) -> &mut DigestBytes {
        &mut self.public_digest
    }

    /// Returns the digest mirroring the declared trace commitment.
    pub fn trace_commit(&self) -> &DigestBytes {
        &self.trace_commit
    }

    /// Returns a mutable reference to the trace commitment digest.
    pub fn trace_commit_mut(&mut self) -> &mut DigestBytes {
        &mut self.trace_commit
    }

    /// Returns the optional composition commitment digest, if present.
    pub fn composition_commit(&self) -> Option<&DigestBytes> {
        self.composition_commit.as_ref()
    }

    /// Returns a mutable reference to the optional composition commitment digest.
    pub fn composition_commit_mut(&mut self) -> Option<&mut DigestBytes> {
        self.composition_commit.as_mut()
    }

    /// Returns the Merkle commitment bundle for the proof.
    pub fn merkle(&self) -> &MerkleProofBundle {
        &self.merkle
    }

    /// Returns a mutable reference to the Merkle commitment bundle.
    pub fn merkle_mut(&mut self) -> &mut MerkleProofBundle {
        &mut self.merkle
    }

    /// Returns the out-of-domain opening payloads.
    pub fn openings(&self) -> &Openings {
        &self.openings
    }

    /// Returns a mutable reference to the out-of-domain opening payloads.
    pub fn openings_mut(&mut self) -> &mut Openings {
        &mut self.openings
    }

    /// Returns the FRI proof payload accompanying the envelope.
    pub fn fri_proof(&self) -> &FriProof {
        &self.fri_proof
    }

    /// Returns a mutable reference to the FRI proof payload accompanying the envelope.
    pub fn fri_proof_mut(&mut self) -> &mut FriProof {
        &mut self.fri_proof
    }

    /// Returns `true` when the proof payload contains telemetry data.
    pub fn has_telemetry(&self) -> bool {
        self.has_telemetry
    }

    /// Sets the telemetry presence flag for the proof payload.
    pub fn set_has_telemetry(&mut self, value: bool) {
        self.has_telemetry = value;
    }

    /// Returns the telemetry frame describing declared lengths and digests.
    pub fn telemetry(&self) -> &Telemetry {
        &self.telemetry
    }

    /// Returns a mutable reference to the telemetry frame.
    pub fn telemetry_mut(&mut self) -> &mut Telemetry {
        &mut self.telemetry
    }

    /// Reassembles a proof from the provided building blocks.
    #[allow(clippy::too_many_arguments)]
    pub fn from_parts(
        version: u16,
        param_digest: ParamDigest,
        public_digest: DigestBytes,
        trace_commit: DigestBytes,
        binding: CompositionBinding,
        openings: OpeningsDescriptor,
        fri: FriHandle,
        telemetry: TelemetryOption,
    ) -> Self {
        let CompositionBinding {
            kind,
            air_spec_id,
            public_inputs,
            composition_commit,
        } = binding;
        let OpeningsDescriptor { merkle, openings } = openings;
        let FriHandle { fri_proof } = fri;
        let TelemetryOption {
            has_telemetry,
            telemetry,
        } = telemetry;

        Self {
            version,
            kind,
            param_digest,
            air_spec_id,
            public_inputs,
            public_digest,
            trace_commit,
            composition_commit,
            merkle,
            openings,
            fri_proof,
            has_telemetry,
            telemetry,
        }
    }
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

impl MerkleProofBundle {
    /// Constructs a bundle from the provided roots without additional checks.
    pub fn new(core_root: [u8; 32], aux_root: [u8; 32], fri_layer_roots: Vec<[u8; 32]>) -> Self {
        Self {
            core_root,
            aux_root,
            fri_layer_roots,
        }
    }

    /// Assembles a bundle and validates that the provided FRI proof advertises
    /// compatible layer roots. The layer ordering must be identical.
    pub fn from_fri_proof(
        core_root: [u8; 32],
        aux_root: [u8; 32],
        fri_proof: &crate::fri::FriProof,
    ) -> Result<Self, VerifyError> {
        let bundle = Self::new(core_root, aux_root, fri_proof.layer_roots.clone());
        bundle.ensure_consistency(fri_proof)?;
        Ok(bundle)
    }

    /// Ensures that the bundle roots match the ones advertised by the FRI
    /// proof. Callers may use this helper when the bundle is constructed from
    /// individual roots to verify that the redundant data is internally
    /// consistent.
    pub fn ensure_consistency(&self, fri_proof: &crate::fri::FriProof) -> Result<(), VerifyError> {
        if self.fri_layer_roots != fri_proof.layer_roots {
            return Err(VerifyError::MerkleVerifyFailed {
                section: MerkleSection::FriRoots,
            });
        }

        Ok(())
    }
}

/// Wrapper collecting the Merkle bundle and opening payloads for assembly helpers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpeningsDescriptor {
    merkle: MerkleProofBundle,
    openings: Openings,
}

impl OpeningsDescriptor {
    /// Constructs a descriptor from the provided Merkle bundle and openings payload.
    pub fn new(merkle: MerkleProofBundle, openings: Openings) -> Self {
        Self { merkle, openings }
    }

    /// Returns the wrapped Merkle commitment bundle.
    pub fn merkle(&self) -> &MerkleProofBundle {
        &self.merkle
    }

    /// Returns a mutable reference to the wrapped Merkle commitment bundle.
    pub fn merkle_mut(&mut self) -> &mut MerkleProofBundle {
        &mut self.merkle
    }

    /// Returns the wrapped out-of-domain opening payloads.
    pub fn openings(&self) -> &Openings {
        &self.openings
    }

    /// Returns a mutable reference to the wrapped out-of-domain opening payloads.
    pub fn openings_mut(&mut self) -> &mut Openings {
        &mut self.openings
    }
}

/// Out-of-domain opening container.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Openings {
    /// Trace Merkle openings covering core trace queries.
    pub trace: TraceOpenings,
    /// Optional composition openings (mirrors the trace structure).
    pub composition: Option<CompositionOpenings>,
    /// Individual out-of-domain openings.
    pub out_of_domain: Vec<OutOfDomainOpening>,
}

/// Merkle opening data covering trace commitments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceOpenings {
    /// Query indices sampled from the FRI transcript.
    pub indices: Vec<u32>,
    /// Leaf payloads revealed for each queried index.
    pub leaves: Vec<Vec<u8>>,
    /// Authentication paths proving membership for each query.
    pub paths: Vec<MerkleAuthenticationPath>,
}

/// Merkle opening data covering composition commitments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompositionOpenings {
    /// Query indices sampled from the FRI transcript.
    pub indices: Vec<u32>,
    /// Leaf payloads revealed for each queried index.
    pub leaves: Vec<Vec<u8>>,
    /// Authentication paths proving membership for each query.
    pub paths: Vec<MerkleAuthenticationPath>,
}

/// Authentication path for a Merkle opening.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleAuthenticationPath {
    /// Sequence of nodes from the leaf to the root.
    pub nodes: Vec<MerklePathNode>,
}

/// Single node within an authentication path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerklePathNode {
    /// Position of the caller node within the parent (`0` for left, `1` for right).
    pub index: u8,
    /// Sibling digest paired with the caller node at this level.
    pub sibling: [u8; 32],
}

/// Telemetry frame exposing declared lengths and FRI parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
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

/// Wrapper combining the telemetry presence flag with the telemetry payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TelemetryOption {
    has_telemetry: bool,
    telemetry: Telemetry,
}

impl TelemetryOption {
    /// Creates a wrapper describing whether telemetry data is present.
    pub fn new(has_telemetry: bool, telemetry: Telemetry) -> Self {
        Self {
            has_telemetry,
            telemetry,
        }
    }

    /// Returns `true` when telemetry data is available.
    pub fn has_telemetry(&self) -> bool {
        self.has_telemetry
    }

    /// Mutably updates the telemetry presence flag.
    pub fn set_has_telemetry(&mut self, value: bool) {
        self.has_telemetry = value;
    }

    /// Returns the telemetry payload associated with the proof.
    pub fn telemetry(&self) -> &Telemetry {
        &self.telemetry
    }

    /// Returns a mutable reference to the telemetry payload.
    pub fn telemetry_mut(&mut self) -> &mut Telemetry {
        &mut self.telemetry
    }
}

/// Structured verification report pairing a decoded proof with the outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyReport {
    /// Fully decoded proof container.
    pub proof: Proof,
    /// Flag indicating whether parameter hashing checks succeeded.
    #[serde(default)]
    pub params_ok: bool,
    /// Flag indicating whether public input binding checks succeeded.
    #[serde(default)]
    pub public_ok: bool,
    /// Flag indicating whether Merkle commitment checks succeeded.
    #[serde(default)]
    pub merkle_ok: bool,
    /// Flag indicating whether the FRI verifier accepted the proof.
    #[serde(default)]
    pub fri_ok: bool,
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
    /// FRI layer roots emitted by the prover did not line up with the Merkle bundle.
    FriRoots,
    /// Authentication path validation failed while replaying FRI queries.
    FriPath,
    /// Core trace openings failed to verify against the commitment.
    TraceCommit,
    /// Composition openings failed to verify against the commitment.
    CompositionCommit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FriVerifyIssue {
    /// The verifier derived more queries than the envelope advertised or allowed.
    QueryOutOfRange,
    /// Authentication path validation failed for one of the FRI queries.
    PathInvalid,
    /// Layer roots or folding invariants failed inside the FRI verifier.
    LayerMismatch,
    /// Security level recorded in the proof did not match the verifier profile.
    SecurityLevelMismatch,
    /// The envelope declared more layers than the verifier or spec permits.
    LayerBudgetExceeded,
    /// The codeword reconstructed during FRI validation was empty or malformed.
    EmptyCodeword,
    /// The FRI proof encoded an unexpected version identifier.
    VersionMismatch,
    /// The advertised query budget disagreed with the verifier profile.
    QueryBudgetMismatch,
    /// Folding invariants or related constraints were violated.
    FoldingConstraint,
    /// The prover emitted inconsistent out-of-domain samples.
    OodsInvalid,
    /// The verifier rejected the FRI proof for another reason.
    Generic,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerifyError {
    /// The proof version encoded in the header is not supported.
    VersionMismatch { expected: u16, actual: u16 },
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
    /// Parameter digest did not match the expected configuration digest.
    ParamsHashMismatch,
    /// Public inputs failed decoding or did not match the expected layout.
    PublicInputMismatch,
    /// Digest derived from the public-input section mismatched the advertised digest.
    PublicDigestMismatch,
    /// Transcript phases were emitted out of order or with missing tags.
    TranscriptOrder,
    /// Out-of-domain openings were malformed or contained inconsistent values.
    OutOfDomainInvalid,
    /// Proof declared a Merkle scheme unsupported by the verifier.
    UnsupportedMerkleScheme,
    /// Merkle roots decoded from the payload disagreed with the header.
    RootMismatch { section: MerkleSection },
    /// Merkle verification failed for a specific section.
    MerkleVerifyFailed { section: MerkleSection },
    /// Trace leaf payload did not match the expected evaluation.
    TraceLeafMismatch,
    /// Composition leaf payload did not match the expected evaluation.
    CompositionLeafMismatch,
    /// Trace out-of-domain evaluation disagreed with the Merkle/Fri binding.
    TraceOodMismatch,
    /// Composition out-of-domain evaluation disagreed with the Merkle/Fri binding.
    CompositionOodMismatch,
    /// Composition openings disagreed with the commitments advertised in the header.
    CompositionInconsistent { reason: String },
    /// FRI verification rejected the envelope.
    FriVerifyFailed { issue: FriVerifyIssue },
    /// Composition polynomial exceeded declared degree bounds.
    DegreeBoundExceeded,
    /// Proof exceeded the configured maximum proof size (values measured in kibibytes).
    ProofTooLarge { max_kb: u32, got_kb: u32 },
    /// Proof declared openings but none were provided in the payload.
    EmptyOpenings,
    /// Query indices were not strictly increasing.
    IndicesNotSorted,
    /// Query indices contained duplicates.
    IndicesDuplicate { index: u32 },
    /// Query indices disagreed with the locally derived transcript indices.
    IndicesMismatch,
    /// Aggregated digest did not match the recomputed digest during batching.
    AggregationDigestMismatch,
    /// Malformed serialization encountered while decoding a proof section.
    Serialization(SerKind),
    /// Deterministic hashing helper failed while sampling queries.
    DeterministicHash(DeterministicHashError),
}

impl From<crate::ser::SerError> for VerifyError {
    fn from(err: crate::ser::SerError) -> Self {
        VerifyError::Serialization(err.kind())
    }
}

impl From<DeterministicHashError> for VerifyError {
    fn from(err: DeterministicHashError) -> Self {
        VerifyError::DeterministicHash(err)
    }
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
