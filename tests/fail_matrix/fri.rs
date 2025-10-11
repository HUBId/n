use insta::assert_debug_snapshot;
use rpp_stark::config::ProofKind as ConfigProofKind;
use rpp_stark::proof::types::{FriVerifyIssue, MerkleSection, VerifyError};
use rpp_stark::proof::verifier::verify;

use super::{perturb_fri_fold_challenge, FailMatrixFixture};

#[test]
fn fri_rejects_fold_challenge_tampering() {
    let fixture = FailMatrixFixture::new();
    let mutated = perturb_fri_fold_challenge(&fixture.proof());

    let public_inputs = fixture.public_inputs();
    let config = fixture.config();
    let context = fixture.verifier_context();

    let report = verify(
        ConfigProofKind::Tx,
        &public_inputs,
        &mutated.bytes,
        &config,
        &context,
    )
    .expect("verification report must be produced");

    let error = report.error.expect("expected verification failure");
    let issue = match error {
        VerifyError::FriVerifyFailed { issue } => Some(issue),
        _ => None,
    };

    assert_debug_snapshot!("fri_rejects_fold_challenge_tampering_error", error);
    assert_debug_snapshot!("fri_rejects_fold_challenge_tampering_issue", issue);
    assert_debug_snapshot!(
        "fri_rejects_fold_challenge_tampering_challenges",
        mutated.proof.fri_proof().fold_challenges.clone()
    );

    assert!(
        matches!(
            error,
            VerifyError::FriVerifyFailed {
                issue: FriVerifyIssue::FoldingConstraint
            } | VerifyError::FriVerifyFailed { .. }
                | VerifyError::MerkleVerifyFailed {
                    section: MerkleSection::FriPath
                }
        ),
        "unexpected verification error: {error:?}"
    );
}
