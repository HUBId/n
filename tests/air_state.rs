use rpp_stark::air::errors::AirErrorKind;
use rpp_stark::air::proofs::{StateAirProfile, StateOperation, StateSelectorWindows, StateWitness};
use rpp_stark::air::StatePublicInputs;

fn sample_witness() -> StateWitness {
    StateWitness {
        pre_state: vec![(1, 10)],
        post_state: vec![(1, 12)],
        operations: vec![StateOperation {
            tag: 1,
            key: 1,
            value_old: 10,
            value_new: 12,
        }],
        selectors: StateSelectorWindows {
            scan_rows: 1,
            finalize_rows: 1,
        },
    }
}

fn prepare_inputs(witness: &StateWitness) -> StatePublicInputs {
    StateAirProfile::derive_public_inputs(witness)
}

pub mod tests {
    use super::*;

    #[test]
    fn multiset_consistency_accept_ok() {
        let witness = sample_witness();
        let inputs = prepare_inputs(&witness);
        StateAirProfile::evaluate_trace(&witness, &inputs).expect("accept");
    }

    #[test]
    fn invalid_op_tag_rejected() {
        let mut witness = sample_witness();
        witness.operations[0].tag = 9;
        let inputs = prepare_inputs(&witness);
        let err = StateAirProfile::evaluate_trace(&witness, &inputs).unwrap_err();
        assert_eq!(err, AirErrorKind::ErrStateOpTag);
    }

    #[test]
    fn format_violation_rejected() {
        let mut witness = sample_witness();
        witness.operations[0].key = 1u64 << 48;
        let inputs = prepare_inputs(&witness);
        let err = StateAirProfile::evaluate_trace(&witness, &inputs).unwrap_err();
        assert_eq!(err, AirErrorKind::ErrStateFormat);
    }

    #[test]
    fn trivial_update_rejected() {
        let mut witness = sample_witness();
        witness.operations[0].value_new = witness.operations[0].value_old;
        let inputs = prepare_inputs(&witness);
        let err = StateAirProfile::evaluate_trace(&witness, &inputs).unwrap_err();
        assert_eq!(err, AirErrorKind::ErrStateUpdateTrivial);
    }

    #[test]
    fn permutation_mismatch_rejected() {
        let mut witness = sample_witness();
        witness.post_state = vec![(2, 12)];
        let inputs = prepare_inputs(&witness);
        let err = StateAirProfile::evaluate_trace(&witness, &inputs).unwrap_err();
        assert_eq!(err, AirErrorKind::ErrStatePermutation);
    }

    #[test]
    fn selector_violation_rejected() {
        let mut witness = sample_witness();
        witness.selectors.finalize_rows = 0;
        let inputs = prepare_inputs(&witness);
        let err = StateAirProfile::evaluate_trace(&witness, &inputs).unwrap_err();
        assert_eq!(err, AirErrorKind::ErrStateSelector);
    }

    #[test]
    fn boundary_digest_mismatch_rejected() {
        let witness = sample_witness();
        let mut inputs = prepare_inputs(&witness);
        inputs.pre_state_root = [1u8; 32];
        let err = StateAirProfile::evaluate_trace(&witness, &inputs).unwrap_err();
        assert_eq!(err, AirErrorKind::ErrStateBoundary);
    }
}
