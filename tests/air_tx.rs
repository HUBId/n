use rpp_stark::air::errors::AirErrorKind;
use rpp_stark::air::proofs::{
    TransactionAirProfile, TransactionSelectorWindows, TransactionWitness,
};
use rpp_stark::air::TransactionPublicInputs;

fn sample_witness() -> TransactionWitness {
    TransactionWitness {
        inputs: vec![7, 5],
        outputs: vec![7],
        fee: 5,
        nonce: 42,
        selectors: TransactionSelectorWindows {
            input_rows: 2,
            output_rows: 1,
            finalize_rows: 1,
        },
        accumulator_digest: [0u8; 32],
    }
}

fn prepare_inputs(
    mut witness: TransactionWitness,
) -> (TransactionWitness, TransactionPublicInputs) {
    let digest = TransactionAirProfile::derive_public_inputs(&witness);
    witness.accumulator_digest = digest.tx_id;
    (witness, digest)
}

pub mod tests {
    use super::*;

    #[test]
    fn balance_holds_accept_ok() {
        let (witness, inputs) = prepare_inputs(sample_witness());
        TransactionAirProfile::evaluate_trace(&witness, &inputs).expect("accept");
    }

    #[test]
    fn balance_mismatch_rejected() {
        let mut witness = sample_witness();
        witness.outputs = vec![7, 6];
        witness.selectors.output_rows = 2;
        let (mut witness, mut inputs) = prepare_inputs(witness);
        inputs.output_commit_root = [1u8; 32]; // keep mismatch hidden to reach balance check first
        witness.accumulator_digest = inputs.tx_id;
        let err = TransactionAirProfile::evaluate_trace(&witness, &inputs).unwrap_err();
        assert_eq!(err, AirErrorKind::ErrTxBalance);
    }

    #[test]
    fn amount_out_of_range_rejected() {
        let mut witness = sample_witness();
        witness.inputs[0] = 1u128 << 64;
        let (witness, inputs) = prepare_inputs(witness);
        let err = TransactionAirProfile::evaluate_trace(&witness, &inputs).unwrap_err();
        assert_eq!(err, AirErrorKind::ErrTxRange);
    }

    #[test]
    fn permutation_mismatch_rejected() {
        let mut witness = sample_witness();
        witness.outputs = vec![6];
        witness.fee = 6;
        let (mut witness, inputs) = prepare_inputs(witness);
        witness.accumulator_digest = inputs.tx_id;
        let err = TransactionAirProfile::evaluate_trace(&witness, &inputs).unwrap_err();
        assert_eq!(err, AirErrorKind::ErrTxPermMismatch);
    }

    #[test]
    fn selector_mismatch_rejected() {
        let mut witness = sample_witness();
        witness.selectors.finalize_rows = 0;
        let (mut witness, inputs) = prepare_inputs(witness);
        witness.accumulator_digest = inputs.tx_id;
        let err = TransactionAirProfile::evaluate_trace(&witness, &inputs).unwrap_err();
        assert_eq!(err, AirErrorKind::ErrTxSelector);
    }

    #[test]
    fn hash_binding_violation_rejected() {
        let (mut witness, inputs) = prepare_inputs(sample_witness());
        witness.accumulator_digest = [9u8; 32];
        let err = TransactionAirProfile::evaluate_trace(&witness, &inputs).unwrap_err();
        assert_eq!(err, AirErrorKind::ErrTxHashBind);
    }

    #[test]
    fn boundary_mismatch_rejected() {
        let (witness, mut inputs) = prepare_inputs(sample_witness());
        inputs.fee = 3u64.to_le_bytes();
        let err = TransactionAirProfile::evaluate_trace(&witness, &inputs).unwrap_err();
        assert_eq!(err, AirErrorKind::ErrTxBoundary);
    }
}
