use rpp_stark::air::errors::AirErrorKind;
use rpp_stark::air::proofs::{
    PruningAirProfile, PruningEntry, PruningOperation, PruningSelectorWindows, PruningWitness,
};
use rpp_stark::air::PruningPublicInputs;

fn sample_witness() -> PruningWitness {
    let old_entries = vec![
        PruningEntry { key: 1, value: 10 },
        PruningEntry { key: 2, value: 20 },
    ];
    let operations = vec![
        PruningOperation {
            entry: old_entries[0],
            keep: true,
            drop: false,
        },
        PruningOperation {
            entry: old_entries[1],
            keep: false,
            drop: true,
        },
    ];
    PruningWitness {
        old_entries,
        new_entries: vec![PruningEntry { key: 1, value: 10 }],
        operations,
        selectors: PruningSelectorWindows {
            filter_rows: 2,
            finalize_rows: 1,
        },
    }
}

fn prepare_inputs(witness: &PruningWitness) -> PruningPublicInputs {
    PruningAirProfile::derive_public_inputs(witness)
}

pub mod tests {
    use super::*;

    #[test]
    fn partition_correct_accept_ok() {
        let witness = sample_witness();
        let inputs = prepare_inputs(&witness);
        PruningAirProfile::evaluate_trace(&witness, &inputs).expect("accept");
    }

    #[test]
    fn partition_mismatch_rejected() {
        let mut witness = sample_witness();
        witness.operations[1].entry = PruningEntry { key: 9, value: 9 };
        let inputs = prepare_inputs(&witness);
        let err = PruningAirProfile::evaluate_trace(&witness, &inputs).unwrap_err();
        assert_eq!(err, AirErrorKind::ErrPrunePartition);
    }

    #[test]
    fn format_violation_rejected() {
        let mut witness = sample_witness();
        witness.old_entries[0].key = 1u64 << 48;
        let inputs = prepare_inputs(&witness);
        let err = PruningAirProfile::evaluate_trace(&witness, &inputs).unwrap_err();
        assert_eq!(err, AirErrorKind::ErrPruneFormat);
    }

    #[test]
    fn policy_flag_violation_rejected() {
        let mut witness = sample_witness();
        witness.operations[0].drop = true;
        let inputs = prepare_inputs(&witness);
        let err = PruningAirProfile::evaluate_trace(&witness, &inputs).unwrap_err();
        assert_eq!(err, AirErrorKind::ErrPrunePolicy);
    }

    #[test]
    fn permutation_mismatch_rejected() {
        let mut witness = sample_witness();
        witness.new_entries = vec![PruningEntry { key: 2, value: 20 }];
        let inputs = prepare_inputs(&witness);
        let err = PruningAirProfile::evaluate_trace(&witness, &inputs).unwrap_err();
        assert_eq!(err, AirErrorKind::ErrPrunePermutation);
    }

    #[test]
    fn selector_violation_rejected() {
        let mut witness = sample_witness();
        witness.selectors.finalize_rows = 0;
        let inputs = prepare_inputs(&witness);
        let err = PruningAirProfile::evaluate_trace(&witness, &inputs).unwrap_err();
        assert_eq!(err, AirErrorKind::ErrPruneSelector);
    }

    #[test]
    fn boundary_digest_mismatch_rejected() {
        let witness = sample_witness();
        let mut inputs = prepare_inputs(&witness);
        inputs.recovery_anchor = [2u8; 32];
        let err = PruningAirProfile::evaluate_trace(&witness, &inputs).unwrap_err();
        assert_eq!(err, AirErrorKind::ErrPruneBoundary);
    }
}
