use rpp_stark::config::{
    AirSpecId, ProofKind as ConfigProofKind, ProofSystemConfig, VerifierContext,
};
use rpp_stark::fri::{FriProof, FriSecurityLevel};
use rpp_stark::proof::envelope::ProofBuilder;
use rpp_stark::proof::public_inputs::PublicInputs;
use rpp_stark::proof::ser::{serialize_proof, SerError};
use rpp_stark::proof::types::{
    FriTelemetry, MerkleProofBundle, Openings, Proof, Telemetry, VerifyError, VerifyReport,
    PROOF_VERSION,
};
use rpp_stark::proof::verify;
use rpp_stark::utils::serialization::{DigestBytes, ProofBytes};

#[test]
fn proof_types_can_be_instantiated() {
    let merkle = MerkleProofBundle {
        trace_cap: [0u8; 32],
        composition_cap: [0u8; 32],
        fri_layers: Vec::new(),
    };
    let openings = Openings { trace: Vec::new() };
    let telemetry = Telemetry {
        header_bytes: 0,
        body_bytes: 0,
        fri: FriTelemetry::default(),
        integrity_hash: DigestBytes::default(),
    };
    let fri_proof = FriProof::new(
        FriSecurityLevel::Standard,
        1,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        [0u8; 32],
        Vec::new(),
    )
    .expect("empty skeleton proof");

    let proof = Proof {
        proof_version: PROOF_VERSION,
        proof_kind: ConfigProofKind::Tx,
        params_hash: [0u8; 32],
        air_spec_id: AirSpecId(DigestBytes::default()),
        public_inputs: Vec::new(),
        commitment_digest: DigestBytes::default(),
        merkle: merkle.clone(),
        openings: openings.clone(),
        fri_proof: fri_proof.clone(),
        telemetry: telemetry.clone(),
    };

    let _report = VerifyReport {
        proof: proof.clone(),
        params_ok: false,
        public_ok: false,
        merkle_ok: false,
        fri_ok: false,
        composition_ok: false,
        total_bytes: 0,
        error: Some(VerifyError::ParamsHashMismatch),
    };

    let _builder = ProofBuilder::new()
        .with_proof(proof.clone())
        .with_merkle(merkle)
        .with_openings(openings)
        .with_telemetry(telemetry);

    let _serializer: fn(&Proof) -> Result<Vec<u8>, SerError> = serialize_proof;

    type VerifyFn = fn(
        ConfigProofKind,
        &PublicInputs<'_>,
        &ProofBytes,
        &ProofSystemConfig,
        &VerifierContext,
    ) -> Result<VerifyReport, VerifyError>;
    let _verify: VerifyFn = verify;

    // Ensure `FriProof` remains accessible for downstream callers.
    let _ = fri_proof;
}
