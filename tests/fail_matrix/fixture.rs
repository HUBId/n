use rpp_stark::config::{
    build_proof_system_config, build_prover_context, build_verifier_context, compute_param_digest,
    ChunkingPolicy, ParamDigest, ProfileConfig, ProofSystemConfig, ProverContext,
    ThreadPoolProfile, VerifierContext, COMMON_IDENTIFIERS, PROFILE_STANDARD_CONFIG,
};
use rpp_stark::field::prime_field::{CanonicalSerialize, FieldElementOps};
use rpp_stark::field::FieldElement;
use rpp_stark::generate_proof;
use rpp_stark::proof::public_inputs::{
    ExecutionHeaderV1, ProofKind, PublicInputVersion, PublicInputs,
};
use rpp_stark::proof::ser::{compute_integrity_digest, serialize_proof};
use rpp_stark::proof::types::{
    CompositionBinding, FriHandle, OpeningsDescriptor, Proof, Telemetry, TelemetryOption,
};
use rpp_stark::utils::serialization::{DigestBytes, ProofBytes, WitnessBlob};
use std::convert::TryInto;

#[derive(Clone, Copy, Debug)]
pub(crate) struct HandleLayout {
    offset_idx: usize,
    offset: u32,
    len: u32,
}

impl HandleLayout {
    fn new(offset_idx: usize, offset: u32, len: u32) -> Self {
        Self {
            offset_idx,
            offset,
            len,
        }
    }

    pub(crate) fn offset(&self) -> u32 {
        self.offset
    }

    pub(crate) fn length(&self) -> u32 {
        self.len
    }

    pub(crate) fn offset_usize(&self) -> usize {
        self.offset as usize
    }

    pub(crate) fn len_usize(&self) -> usize {
        self.len as usize
    }

    pub(crate) fn offset_idx(&self) -> usize {
        self.offset_idx
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct TelemetryLayout {
    flag_idx: usize,
    handle: Option<HandleLayout>,
}

impl TelemetryLayout {
    fn new(flag_idx: usize, handle: Option<HandleLayout>) -> Self {
        Self { flag_idx, handle }
    }

    pub(crate) fn flag_idx(&self) -> usize {
        self.flag_idx
    }

    pub(crate) fn handle(&self) -> Option<HandleLayout> {
        self.handle
    }

    pub(crate) fn is_present(&self) -> bool {
        self.handle.is_some()
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct HeaderLayout {
    openings: HandleLayout,
    fri: HandleLayout,
    telemetry: TelemetryLayout,
    payload_start: usize,
}

impl HeaderLayout {
    pub(crate) fn openings(&self) -> HandleLayout {
        self.openings
    }

    pub(crate) fn fri(&self) -> HandleLayout {
        self.fri
    }

    pub(crate) fn telemetry(&self) -> TelemetryLayout {
        self.telemetry
    }

    pub(crate) fn payload_start(&self) -> usize {
        self.payload_start
    }
}

fn read_u32_le(bytes: &[u8], start: usize) -> u32 {
    u32::from_le_bytes(
        bytes[start..start + 4]
            .try_into()
            .expect("slice must have four bytes"),
    )
}

pub(crate) fn header_layout(bytes: &[u8]) -> HeaderLayout {
    let mut cursor = 0usize;
    cursor += 2; // version
    cursor += 32; // params hash
    cursor += 32; // public digest
    cursor += 32; // trace commitment

    let binding_len = read_u32_le(bytes, cursor) as usize;
    cursor += 4 + binding_len;

    let openings_offset_idx = cursor;
    let openings_offset = read_u32_le(bytes, cursor);
    cursor += 4;
    let openings_len = read_u32_le(bytes, cursor);
    cursor += 4;
    let openings = HandleLayout::new(openings_offset_idx, openings_offset, openings_len);

    let fri_offset_idx = cursor;
    let fri_offset = read_u32_le(bytes, cursor);
    cursor += 4;
    let fri_len = read_u32_le(bytes, cursor);
    cursor += 4;
    let fri = HandleLayout::new(fri_offset_idx, fri_offset, fri_len);

    let telemetry_flag_idx = cursor;
    let telemetry_flag = bytes[cursor];
    cursor += 1;

    let telemetry_handle = if telemetry_flag == 1 {
        let telemetry_offset_idx = cursor;
        let telemetry_offset = read_u32_le(bytes, cursor);
        cursor += 4;
        let telemetry_len = read_u32_le(bytes, cursor);
        cursor += 4;
        Some(HandleLayout::new(
            telemetry_offset_idx,
            telemetry_offset,
            telemetry_len,
        ))
    } else {
        None
    };

    let telemetry = TelemetryLayout::new(telemetry_flag_idx, telemetry_handle);

    HeaderLayout {
        openings,
        fri,
        telemetry,
        payload_start: cursor,
    }
}

fn mutate_header_bytes<F>(bytes: &ProofBytes, mutator: F) -> ProofBytes
where
    F: FnOnce(&mut Vec<u8>, HeaderLayout),
{
    let mut mutated = bytes.as_slice().to_vec();
    let layout = header_layout(&mutated);
    mutator(&mut mutated, layout);
    ProofBytes::new(mutated)
}

fn mutate_header_bytes_option<F>(bytes: &ProofBytes, mutator: F) -> Option<ProofBytes>
where
    F: FnOnce(&mut Vec<u8>, HeaderLayout) -> bool,
{
    let mut mutated = bytes.as_slice().to_vec();
    let layout = header_layout(&mutated);
    if mutator(&mut mutated, layout) {
        Some(ProofBytes::new(mutated))
    } else {
        None
    }
}

pub fn mismatch_openings_offset(bytes: &ProofBytes) -> ProofBytes {
    mutate_header_bytes(bytes, |buffer, layout| {
        let handle = layout.openings();
        let mut new_offset = handle.offset().saturating_add(4);
        if new_offset == handle.offset() {
            new_offset = handle.offset().wrapping_add(1);
            if new_offset == handle.offset() {
                new_offset = 1;
            }
        }
        buffer[handle.offset_idx()..handle.offset_idx() + 4]
            .copy_from_slice(&new_offset.to_le_bytes());
    })
}

pub fn mismatch_fri_offset(bytes: &ProofBytes) -> ProofBytes {
    mutate_header_bytes(bytes, |buffer, layout| {
        let handle = layout.fri();
        let mut new_offset = handle.offset().saturating_add(1);
        if new_offset == handle.offset() {
            new_offset = handle.offset().wrapping_add(2);
            if new_offset == handle.offset() {
                new_offset = 1;
            }
        }
        buffer[handle.offset_idx()..handle.offset_idx() + 4]
            .copy_from_slice(&new_offset.to_le_bytes());
    })
}

pub fn mismatch_telemetry_offset(bytes: &ProofBytes) -> Option<ProofBytes> {
    mutate_header_bytes_option(bytes, |buffer, layout| {
        let Some(handle) = layout.telemetry().handle() else {
            return false;
        };
        let mut new_offset = handle.offset().saturating_add(1);
        if new_offset == handle.offset() {
            new_offset = handle.offset().wrapping_add(2);
            if new_offset == handle.offset() {
                new_offset = 1;
            }
        }
        buffer[handle.offset_idx()..handle.offset_idx() + 4]
            .copy_from_slice(&new_offset.to_le_bytes());
        true
    })
}

pub fn mismatch_telemetry_flag(bytes: &ProofBytes) -> Option<ProofBytes> {
    mutate_header_bytes_option(bytes, |buffer, layout| {
        if !layout.telemetry().is_present() {
            return false;
        }
        buffer[layout.telemetry().flag_idx()] = 0;
        true
    })
}

const LFSR_ALPHA: u64 = 5;
const LFSR_BETA: u64 = 7;
const TRACE_LENGTH: usize = 128;
const TRACE_WIDTH: u32 = 1;
const SEED_VALUE: u64 = 3;

/// Fixture assembling a miniature execution proof tailored for failure matrix tests.
pub struct FailMatrixFixture {
    proof_bytes: ProofBytes,
    proof: Proof,
    config: ProofSystemConfig,
    prover_context: ProverContext,
    verifier_context: VerifierContext,
    header: ExecutionHeaderV1,
    body: Vec<u8>,
    witness: Vec<u8>,
}

impl FailMatrixFixture {
    /// Builds a new fixture with a minimal profile configuration.
    pub fn new() -> Self {
        let profile: ProfileConfig = PROFILE_STANDARD_CONFIG.clone();

        let common = COMMON_IDENTIFIERS.clone();
        let param_digest = compute_param_digest(&profile, &common);
        let config = build_proof_system_config(&profile, &param_digest);
        let prover_context = build_prover_context(
            &profile,
            &common,
            &param_digest,
            ThreadPoolProfile::SingleThread,
            ChunkingPolicy {
                min_chunk_items: 4,
                max_chunk_items: 32,
                stride: 1,
            },
        );
        let verifier_context = build_verifier_context(&profile, &common, &param_digest, None);

        let header = ExecutionHeaderV1 {
            version: PublicInputVersion::V1,
            program_digest: DigestBytes { bytes: [0u8; 32] },
            trace_length: TRACE_LENGTH as u32,
            trace_width: TRACE_WIDTH,
        };
        let seed = FieldElement::from(SEED_VALUE);
        let body = seed.to_bytes().expect("fixture seed must encode").to_vec();
        let witness = build_witness(seed, TRACE_LENGTH);

        let public_inputs = PublicInputs::Execution {
            header: header.clone(),
            body: &body,
        };
        let witness_blob = WitnessBlob { bytes: &witness };
        let proof_bytes = generate_proof(
            ProofKind::Execution,
            &public_inputs,
            witness_blob,
            &config,
            &prover_context,
        )
        .expect("fixture proof generation succeeds");
        let proof = Proof::from_bytes(proof_bytes.as_slice()).expect("decode fixture proof");

        Self {
            proof_bytes,
            proof,
            config,
            prover_context,
            verifier_context,
            header,
            body,
            witness,
        }
    }

    /// Returns the serialized proof bytes.
    pub fn proof_bytes(&self) -> ProofBytes {
        self.proof_bytes.clone()
    }

    /// Returns the decoded proof container.
    pub fn proof(&self) -> Proof {
        ProofParts::from_proof(&self.proof).into_proof()
    }

    /// Returns the configured proof system configuration.
    pub fn config(&self) -> ProofSystemConfig {
        self.config.clone()
    }

    /// Returns the prover context bound to the mini profile.
    pub fn prover_context(&self) -> ProverContext {
        self.prover_context.clone()
    }

    /// Returns the verifier context bound to the mini profile.
    pub fn verifier_context(&self) -> VerifierContext {
        self.verifier_context.clone()
    }

    /// Returns the canonical public inputs for the fixture.
    pub fn public_inputs(&self) -> PublicInputs<'_> {
        PublicInputs::Execution {
            header: self.header.clone(),
            body: &self.body,
        }
    }

    /// Returns the witness blob consumed by the prover.
    pub fn witness(&self) -> WitnessBlob<'_> {
        WitnessBlob {
            bytes: &self.witness,
        }
    }
}

fn build_witness(seed: FieldElement, rows: usize) -> Vec<u8> {
    let alpha = FieldElement::from(LFSR_ALPHA);
    let beta = FieldElement::from(LFSR_BETA);
    let mut column = Vec::with_capacity(rows);
    let mut state = seed;
    column.push(state);
    for _ in 1..rows {
        state = state.mul(&alpha).add(&beta);
        column.push(state);
    }

    let mut bytes = Vec::with_capacity(20 + rows * 8);
    bytes.extend_from_slice(&(rows as u32).to_le_bytes());
    bytes.extend_from_slice(&TRACE_WIDTH.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    for value in column {
        let encoded = value.to_bytes().expect("fixture witness must encode");
        bytes.extend_from_slice(&encoded);
    }
    bytes
}

fn reencode_proof(proof: &mut Proof) -> ProofBytes {
    if proof.has_telemetry() {
        let mut canonical = ProofParts::from_proof(proof).into_proof();
        let telemetry = canonical.telemetry_frame_mut();
        telemetry.set_header_length(0);
        telemetry.set_body_length(0);
        telemetry.set_integrity_digest(DigestBytes { bytes: [0u8; 32] });
        let payload = canonical
            .serialize_payload()
            .expect("serialize canonical payload");
        let header = canonical
            .serialize_header(&payload)
            .expect("serialize canonical header");
        let integrity = compute_integrity_digest(&header, &payload);
        let telemetry = proof.telemetry_frame_mut();
        telemetry.set_header_length(header.len() as u32);
        telemetry.set_body_length((payload.len() + 32) as u32);
        telemetry.set_integrity_digest(DigestBytes { bytes: integrity });
    }

    ProofBytes::new(serialize_proof(proof).expect("serialize proof"))
}

fn mutate_telemetry_with<F>(proof: &Proof, mutator: F) -> Option<ProofBytes>
where
    F: FnOnce(&mut Telemetry),
{
    if !proof.has_telemetry() {
        return None;
    }

    let mut mutated = ProofParts::from_proof(proof).into_proof();
    let _ = reencode_proof(&mut mutated);
    mutator(mutated.telemetry_frame_mut());

    Some(ProofBytes::new(
        serialize_proof(&mutated).expect("serialize mutated proof"),
    ))
}

/// Declares an incorrect telemetry header length to trigger the mismatch guard.
pub fn mismatch_telemetry_header_length(proof: &Proof) -> Option<ProofBytes> {
    mutate_telemetry_with(proof, |telemetry| {
        let declared = telemetry.header_length();
        let bumped = telemetry.header_length().saturating_add(4);
        let updated = if bumped == declared {
            declared.saturating_sub(1)
        } else {
            bumped
        };
        telemetry.set_header_length(updated);
    })
}

/// Declares an incorrect telemetry body length to trigger the mismatch guard.
pub fn mismatch_telemetry_body_length(proof: &Proof) -> Option<ProofBytes> {
    mutate_telemetry_with(proof, |telemetry| {
        let declared = telemetry.body_length();
        let bumped = telemetry.body_length().saturating_add(16);
        let updated = if bumped == declared {
            declared.saturating_sub(1)
        } else {
            bumped
        };
        telemetry.set_body_length(updated);
    })
}

/// Corrupts the telemetry integrity digest to trigger the mismatch guard.
pub fn mismatch_telemetry_integrity_digest(proof: &Proof) -> Option<ProofBytes> {
    mutate_telemetry_with(proof, |telemetry| {
        let mut digest = telemetry.integrity_digest().bytes;
        digest[0] ^= 0x01;
        telemetry.set_integrity_digest(DigestBytes { bytes: digest });
    })
}

/// Flips the proof header version field.
pub fn flip_header_version(proof: &Proof) -> ProofBytes {
    let mut parts = ProofParts::from_proof(proof);
    *parts.version_mut() ^= 1;
    let mut mutated = parts.into_proof();
    reencode_proof(&mut mutated)
}

/// Corrupts a single byte inside the parameter hash.
pub fn flip_param_digest_byte(proof: &Proof) -> ProofBytes {
    let mut parts = ProofParts::from_proof(proof);
    let mut digest = *parts.params_hash().as_bytes();
    digest[0] ^= 0x01;
    *parts.params_hash_mut() = ParamDigest(DigestBytes { bytes: digest });
    let mut mutated = parts.into_proof();
    reencode_proof(&mut mutated)
}

/// Corrupts the public digest advertised in the header.
pub fn flip_public_digest_byte(bytes: &ProofBytes) -> ProofBytes {
    let mut mutated = bytes.as_slice().to_vec();

    // Header layout mirrors `serialize_proof_header_from_lengths`.
    let mut cursor = 0usize;
    cursor += 2; // version
    cursor += 32; // params hash

    // Flip the leading byte of the canonical public digest.
    mutated[cursor] ^= 0x01;

    ProofBytes::new(mutated)
}

/// Corrupts the trace commitment digest advertised in the header.
pub fn mismatch_trace_root(bytes: &ProofBytes) -> ProofBytes {
    let mut mutated = bytes.as_slice().to_vec();

    // Header layout mirrors `serialize_proof_header_from_lengths`.
    let mut cursor = 0usize;
    cursor += 2; // version
    cursor += 32; // params hash
    cursor += 32; // public digest

    // Flip the leading byte of the declared trace commitment digest.
    mutated[cursor] ^= 0x01;

    ProofBytes::new(mutated)
}

/// Flips the leading byte of the first trace core OOD evaluation (if present).
pub fn flip_ood_trace_core_value(proof: &Proof) -> Option<MutatedProof> {
    let Some(opening) = proof.openings().out_of_domain().first() else {
        return None;
    };
    let Some(value) = opening.core_values.first() else {
        return None;
    };
    if value.is_empty() {
        return None;
    }

    Some(mutate_proof(proof, |parts| {
        if let Some(opening) = parts
            .openings_mut()
            .openings_mut()
            .out_of_domain_mut()
            .first_mut()
        {
            if let Some(value) = opening.core_values.first_mut() {
                if let Some(byte) = value.first_mut() {
                    *byte ^= 0x01;
                }
            }
        }
    }))
}

/// Flips the leading byte of the first composition OOD evaluation (if present).
pub fn flip_ood_composition_value(proof: &Proof) -> Option<MutatedProof> {
    let Some(opening) = proof.openings().out_of_domain().first() else {
        return None;
    };
    if opening.composition_value.is_empty() {
        return None;
    }

    Some(mutate_proof(proof, |parts| {
        if let Some(opening) = parts
            .openings_mut()
            .openings_mut()
            .out_of_domain_mut()
            .first_mut()
        {
            if let Some(byte) = opening.composition_value.first_mut() {
                *byte ^= 0x01;
            }
        }
    }))
}

/// Helper bundling mutated proof bytes with their decoded representation.
#[derive(Debug, Clone)]
pub struct MutatedProof {
    pub bytes: ProofBytes,
    pub proof: Proof,
}

#[derive(Debug, Clone)]
struct ProofParts {
    version: u16,
    params_hash: ParamDigest,
    public_digest: DigestBytes,
    trace_commit: DigestBytes,
    binding: CompositionBinding,
    openings: OpeningsDescriptor,
    fri: FriHandle,
    telemetry: TelemetryOption,
}

impl ProofParts {
    fn from_proof(proof: &Proof) -> Self {
        let binding = proof.composition().clone();
        let openings = proof.openings().clone();
        let fri = proof.fri().clone();
        let telemetry = proof.telemetry().clone();

        Self {
            version: proof.version(),
            params_hash: proof.params_hash().clone(),
            public_digest: proof.public_digest().clone(),
            trace_commit: proof.trace_commit().clone(),
            binding,
            openings,
            fri,
            telemetry,
        }
    }

    fn into_proof(self) -> Proof {
        Proof::from_parts(
            self.version,
            self.params_hash,
            self.public_digest,
            self.trace_commit,
            self.binding,
            self.openings,
            self.fri,
            self.telemetry,
        )
    }

    fn version_mut(&mut self) -> &mut u16 {
        &mut self.version
    }

    fn params_hash_mut(&mut self) -> &mut ParamDigest {
        &mut self.params_hash
    }

    fn params_hash(&self) -> &ParamDigest {
        &self.params_hash
    }

    fn openings(&self) -> &OpeningsDescriptor {
        &self.openings
    }

    fn openings_mut(&mut self) -> &mut OpeningsDescriptor {
        &mut self.openings
    }

    fn fri_mut(&mut self) -> &mut FriHandle {
        &mut self.fri
    }
}

fn mutate_proof<F>(proof: &Proof, mutator: F) -> MutatedProof
where
    F: FnOnce(&mut ProofParts),
{
    let mut parts = ProofParts::from_proof(proof);
    mutator(&mut parts);
    let mut mutated = parts.into_proof();
    let bytes = reencode_proof(&mut mutated);
    MutatedProof {
        bytes,
        proof: mutated,
    }
}

fn mutate_trace_indices_with<F>(proof: &Proof, mutator: F) -> MutatedProof
where
    F: FnOnce(&mut Vec<u32>),
{
    mutate_proof(proof, |parts| {
        let trace = parts.openings_mut().openings_mut().trace_mut();
        mutator(trace.indices_mut());
    })
}

fn mutate_composition_indices_with<F>(proof: &Proof, mutator: F) -> Option<MutatedProof>
where
    F: FnOnce(&mut Vec<u32>),
{
    if proof.openings().composition().is_some() {
        Some(mutate_proof(proof, |parts| {
            if let Some(composition) = parts.openings_mut().openings_mut().composition_mut() {
                mutator(composition.indices_mut());
            }
        }))
    } else {
        None
    }
}

/// Flips the first byte of the leading composition opening leaf (if present).
pub fn flip_composition_leaf_byte(proof: &Proof) -> Option<MutatedProof> {
    let Some(composition) = proof.openings().composition() else {
        return None;
    };
    let Some(leaf) = composition.leaves().first() else {
        return None;
    };
    if leaf.is_empty() {
        return None;
    }

    Some(mutate_proof(proof, |parts| {
        if let Some(composition) = parts.openings_mut().openings_mut().composition_mut() {
            if let Some(leaf) = composition.leaves_mut().first_mut() {
                if let Some(byte) = leaf.first_mut() {
                    *byte ^= 0x01;
                }
            }
        }
    }))
}

/// Swaps the first two trace query indices.
pub fn swap_trace_indices(proof: &Proof) -> MutatedProof {
    mutate_trace_indices_with(proof, |indices| {
        if indices.len() >= 2 {
            indices.swap(0, 1);
        }
    })
}

/// Swaps the first two composition query indices (if present).
pub fn swap_composition_indices(proof: &Proof) -> Option<MutatedProof> {
    mutate_composition_indices_with(proof, |indices| {
        if indices.len() >= 2 {
            indices.swap(0, 1);
        }
    })
}

/// Duplicates the leading trace index to trigger the duplicate check.
pub fn duplicate_trace_index(proof: &Proof) -> MutatedProof {
    mutate_trace_indices_with(proof, |indices| {
        if indices.len() >= 2 {
            indices[1] = indices[0];
        }
    })
}

/// Duplicates the leading composition index to trigger the duplicate check.
pub fn duplicate_composition_index(proof: &Proof) -> Option<MutatedProof> {
    mutate_composition_indices_with(proof, |indices| {
        if indices.len() >= 2 {
            indices[1] = indices[0];
        }
    })
}

/// Replaces all trace indices with values outside of the expected range.
pub fn mismatch_trace_indices(proof: &Proof) -> MutatedProof {
    mutate_trace_indices_with(proof, |indices| {
        let base = 1_000_000u32;
        for (offset, value) in indices.iter_mut().enumerate() {
            *value = base.saturating_add(offset as u32);
        }
    })
}

/// Replaces all composition indices with values outside of the expected range.
pub fn mismatch_composition_indices(proof: &Proof) -> Option<MutatedProof> {
    mutate_composition_indices_with(proof, |indices| {
        let base = 1_000_000u32;
        for (offset, value) in indices.iter_mut().enumerate() {
            *value = base.saturating_add(offset as u32);
        }
    })
}

/// Corrupts the leading node within the first trace Merkle authentication path.
pub fn corrupt_merkle_path(proof: &Proof) -> MutatedProof {
    mutate_proof(proof, |parts| {
        if let Some(path) = parts
            .openings_mut()
            .openings_mut()
            .trace_mut()
            .paths_mut()
            .first_mut()
        {
            if let Some(node) = path.nodes_mut().first_mut() {
                node.index = u8::MAX;
                node.sibling[0] ^= 0xFF;
            }
        }
    })
}

/// Shortens the trace authentication paths, creating a vector length mismatch.
pub fn truncate_trace_paths(proof: &Proof) -> MutatedProof {
    mutate_proof(proof, |parts| {
        if !parts.openings().openings().trace().paths().is_empty() {
            parts
                .openings_mut()
                .openings_mut()
                .trace_mut()
                .paths_mut()
                .pop();
        }
    })
}

/// Offsets the leading FRI fold challenge by one to violate folding constraints.
pub fn perturb_fri_fold_challenge(proof: &Proof) -> MutatedProof {
    mutate_proof(proof, |parts| {
        if let Some(challenge) = parts.fri_mut().fri_proof_mut().fold_challenges.get_mut(0) {
            *challenge = challenge.add(&FieldElement::ONE);
        }
    })
}
