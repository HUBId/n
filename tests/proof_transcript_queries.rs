#[path = "fail_matrix/fixture.rs"]
mod fail_matrix_fixture;

use fail_matrix_fixture::FailMatrixFixture;
use rpp_stark::config::ProofKind;
use rpp_stark::hash::Blake2sXof;
use rpp_stark::proof::params::canonical_stark_params;
use rpp_stark::proof::ser::serialize_public_inputs;
use rpp_stark::proof::transcript::{Transcript, TranscriptBlockContext, TranscriptHeader};
use rpp_stark::proof::types::{PROOF_ALPHA_VECTOR_LEN, PROOF_MIN_OOD_POINTS};

#[test]
fn queries_local_generation_matches_openings() {
    let fixture = FailMatrixFixture::new();
    let proof = fixture.proof();
    let context = fixture.verifier_context();
    let public_inputs = fixture.public_inputs();

    // Ensure we're working with the expected proof kind.
    let proof_kind = *proof.kind();
    assert_eq!(proof_kind, ProofKind::Tx, "fixture kind");

    let air_spec_id = context.profile.air_spec_ids.get(proof_kind).clone();

    let mut transcript = Transcript::new(TranscriptHeader {
        version: context.common_ids.transcript_version_id.clone(),
        poseidon_param_id: context.profile.poseidon_param_id.clone(),
        air_spec_id: air_spec_id.clone(),
        proof_kind,
        params_hash: context.param_digest.clone(),
    })
    .expect("transcript header");

    let public_inputs_bytes =
        serialize_public_inputs(&public_inputs).expect("serialize public inputs");
    transcript
        .absorb_public_inputs(&public_inputs_bytes)
        .expect("absorb public inputs");

    let trace_commit = proof.trace_commit().bytes;
    let composition_commit = proof.composition_commit().map(|commit| commit.bytes);
    transcript
        .absorb_commitment_roots(trace_commit, composition_commit)
        .expect("absorb commitments");
    transcript
        .absorb_air_spec_id(air_spec_id)
        .expect("absorb air spec");
    transcript
        .absorb_block_context(None::<TranscriptBlockContext>)
        .expect("absorb block context");

    let mut challenges = transcript.finalize().expect("finalize transcript");
    let _alpha = challenges
        .draw_alpha_vector(PROOF_ALPHA_VECTOR_LEN)
        .expect("alpha vector");
    let _ood_points = challenges
        .draw_ood_points(PROOF_MIN_OOD_POINTS)
        .expect("ood points");
    let _ood_seed = challenges.draw_ood_seed().expect("ood seed");
    let _fri_seed = challenges.draw_fri_seed().expect("fri seed");

    for (layer_index, _) in proof.merkle().fri_layer_roots().iter().enumerate() {
        let _ = challenges
            .draw_fri_eta(layer_index)
            .expect("fri eta challenge");
    }

    let query_seed = challenges.draw_query_seed().expect("query seed");

    let stark_params = canonical_stark_params(&context.profile);
    let query_count = stark_params.fri().queries as usize;
    let domain_size = proof.fri_proof().initial_domain_size;

    assert!(domain_size > 0, "domain size must be positive");
    let mut sampler = Blake2sXof::new(&query_seed);
    let target = core::cmp::min(query_count, domain_size);
    let mut seen = vec![false; domain_size];
    let mut expected = Vec::with_capacity(target);
    while expected.len() < target {
        let word = sampler.next_u64().expect("xof draw");
        let position = (word % (domain_size as u64)) as usize;
        if !seen[position] {
            seen[position] = true;
            expected.push(position as u32);
        }
    }
    expected.sort_unstable();

    let openings_indices = proof.openings().trace().indices().to_vec();
    assert_eq!(
        expected, openings_indices,
        "transcript-derived indices match openings"
    );
}
