//! Transaction-AIR-Profil.
//!
//! Dieses Profil prueft Salden, Fees und Formatregeln einer UTXO-artigen
//! Transaktion. Die Pfadpruefung gegen externe BLAKE3-Merklebaeume findet ausserhalb
//! der AIR statt (Transcript-Bindung); innerhalb der AIR werden nur feldbasierte
//! Commitments via Poseidon gefuehrt. Integratoren muessen die in der Feinspezifikation
//! geforderten Tests abdecken: Bilanzgleichheit (positiv/negativ), Permutationsgleichheit
//! von Inputs/Outputs inklusive Fee, Range-Verletzungen fuer Betraege/Fee/Nonce,
//! Selektor- und Boundary-Brueche sowie deterministische Proof-Bytes fuer identische
//! Eingaben.

use super::ProofAirKind;
use crate::air::errors::AirErrorKind;
use crate::air::inputs::TransactionPublicInputs;
use crate::hash::Hasher;

/// Beschreibt die Selektorfenster einer Transaktionsspur.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransactionSelectorWindows {
    /// Anzahl der Zeilen in der Input-Phase.
    pub input_rows: usize,
    /// Anzahl der Zeilen in der Output-Phase.
    pub output_rows: usize,
    /// Anzahl der Zeilen in der Finalize-Phase (>= 1 fuer die Abschlusszeile).
    pub finalize_rows: usize,
}

impl TransactionSelectorWindows {
    fn total_rows(self) -> usize {
        self.input_rows + self.output_rows + self.finalize_rows
    }
}

impl Default for TransactionSelectorWindows {
    fn default() -> Self {
        Self {
            input_rows: 0,
            output_rows: 0,
            finalize_rows: 1,
        }
    }
}

/// Minimaler Zeugen fuer das Transaktionsprofil.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionWitness {
    /// Feldkodierte Input-Betraege (u128 zur Validierung der Range).
    pub inputs: Vec<u128>,
    /// Feldkodierte Output-Betraege.
    pub outputs: Vec<u128>,
    /// Gesamtgebuehr.
    pub fee: u128,
    /// Nonce gemäss Public Inputs.
    pub nonce: u64,
    /// Selektorfenster fuer Input/Output/Finalize.
    pub selectors: TransactionSelectorWindows,
    /// Poseidon-/Hash-Akkumulator der Spur (32 Byte, LE).
    pub accumulator_digest: [u8; 32],
}

impl TransactionWitness {
    /// Erstellt einen neutralen Zeugen ohne Werte.
    pub fn empty() -> Self {
        Self {
            inputs: Vec::new(),
            outputs: Vec::new(),
            fee: 0,
            nonce: 0,
            selectors: TransactionSelectorWindows::default(),
            accumulator_digest: [0u8; 32],
        }
    }
}

fn hash_amounts(tag: &str, values: &[u64]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(tag.as_bytes());
    hasher.update(&(values.len() as u32).to_le_bytes());
    for value in values {
        hasher.update(&value.to_le_bytes());
    }
    hasher.finalize().into_bytes()
}

fn hash_transaction(tx: &TransactionWitness) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(b"RPP-TX-AIR");
    hasher.update(&(tx.inputs.len() as u32).to_le_bytes());
    for value in &tx.inputs {
        hasher.update(&(*value as u64).to_le_bytes());
    }
    hasher.update(&(tx.outputs.len() as u32).to_le_bytes());
    for value in &tx.outputs {
        hasher.update(&(*value as u64).to_le_bytes());
    }
    hasher.update(&(tx.fee as u64).to_le_bytes());
    hasher.update(&tx.nonce.to_le_bytes());
    hasher.finalize().into_bytes()
}

fn multiset(values: &[u64]) -> Vec<u64> {
    let mut data = values.to_vec();
    data.sort_unstable();
    data
}

fn u64_from_le_bytes(bytes: &[u8; 8]) -> u64 {
    u64::from_le_bytes(*bytes)
}

fn range_check_amount(value: u128) -> Result<u64, AirErrorKind> {
    if value >= (1u128 << 64) {
        Err(AirErrorKind::ErrTxRange)
    } else {
        Ok(value as u64)
    }
}

/// AIR-Skelett fuer Transaktionsbeweise.
pub struct TransactionAirProfile;
impl TransactionAirProfile {
    /// Zugehoerige Beweisart.
    pub const KIND: ProofAirKind = ProofAirKind::Transaction;
    /// Maximale Spurbreite fuer das Standardprofil (Core+Aux+Selector <= 56).
    pub const TRACE_WIDTH_MAX: usize = 56;
    /// Maximale Schrittanzahl fuer Batches (`2^20`).
    pub const TRACE_STEPS_MAX: usize = 1 << 20;
    /// Core-Register in kanonischer Reihenfolge.
    pub const CORE_REGISTERS: &'static [&'static str] = &[
        "sum_in",
        "sum_out",
        "fee_acc",
        "nonce_acc",
        "acc_poseidon",
        "input_item_acc",
        "output_item_acc",
        "io_index",
    ];
    /// Aux-Register fuer Zerlegungen, Carries und Lookup-Hilfen.
    pub const AUX_REGISTERS: &'static [&'static str] = &[
        "input_amount_limb_lo",
        "input_amount_limb_hi",
        "output_amount_limb_lo",
        "output_amount_limb_hi",
        "fee_limb_lo",
        "fee_limb_hi",
        "nonce_limb_lo",
        "nonce_limb_hi",
        "grand_product_z",
        "range_helper",
    ];
    /// Selektor-Spalten (deterministisch aus dem Zeilenindex).
    pub const SELECTOR_REGISTERS: &'static [&'static str] = &[
        "sigma_first",
        "sigma_last",
        "sigma_io_in",
        "sigma_io_out",
        "sigma_finalize",
    ];
    /// Public-Input-Bindung (LE-Serialisierung, Phase-2-Reihenfolge).
    pub const PUBLIC_INPUTS: &'static [&'static str] = &[
        "TxID[32]",
        "InputCommitRoot[32]",
        "OutputCommitRoot[32]",
        "Fee[u64]",
        "Nonce[u64]",
    ];
    /// Boundary-Anker (Start/Ende) in Bindungsreihenfolge.
    pub const BOUNDARY_CONSTRAINTS: &'static [&'static str] = &[
        "sigma_first * sum_in = 0",
        "sigma_first * sum_out = 0",
        "sigma_first * fee_acc = 0",
        "sigma_first * nonce_acc = 0",
        "sigma_last * (sum_in - sum_out - Fee) = 0",
        "sigma_last * (fee_acc - Fee) = 0",
        "sigma_last * (nonce_acc - Nonce) = 0",
        "sigma_last * (acc_poseidon - PoseidonDigestFromPI) = 0",
    ];
    /// Beschreibung der Transition-Phasen.
    pub const TRANSITION_PHASES: &'static [&'static str] = &[
        "sigma_io_in: addiert Input-Betraege zu sum_in",
        "sigma_io_out: addiert Output-Betraege zu sum_out",
        "sigma_finalize: fixiert Fee/Nonce und prueft Balance",
    ];
    /// Lookups und Permutationsargumente.
    pub const LOOKUPS: &'static [&'static str] = &[
        "range_64bit_amount",
        "range_64bit_fee",
        "range_64bit_nonce",
        "permutation_inputs_equals_outputs_plus_fee",
    ];
    /// OOD-Oeffnungen (Register + Komposition).
    pub const OOD_OPENINGS: &'static [&'static str] = &[
        "sum_in",
        "sum_out",
        "fee_acc",
        "nonce_acc",
        "acc_poseidon",
        "grand_product_z",
        "composition_polynomial",
    ];
    /// Grad-Hinweise fuer Constraints.
    pub const DEGREE_HINT: &'static str =
        "Additionen & Selektor-Maskierung Grad <=2; Range & Grand-Product Grad < LDE-Bound";
    /// Fehlermeldungen, die dieses Profil signalisiert.
    pub const FAILURE_MODES: &'static [&'static str] = &[
        "ErrTxBalance",
        "ErrTxRange",
        "ErrTxPermMismatch",
        "ErrTxSelector",
        "ErrTxHashBind",
        "ErrTxBoundary",
    ];
    /// Beschreibung deterministischer Selektoren.
    pub const SELECTOR_FORMULAS: &'static [&'static str] = &[
        "sigma_first(i) = 1 falls i = 0, sonst 0",
        "sigma_last(i) = 1 falls i = T-1, sonst 0",
        "sigma_io_in(i) = 1 fuer Zeilen der Input-Phase, sonst 0",
        "sigma_io_out(i) = 1 fuer Zeilen der Output-Phase, sonst 0",
        "sigma_finalize(i) = 1 fuer das Abschlussfenster, sonst 0",
        "sigma_io_in + sigma_io_out + sigma_finalize = 1 und Produkte sind 0",
    ];

    /// Fuehrt eine konkrete Constraint-Evaluierung fuer einen gegebenen Zeugen aus.
    pub fn evaluate_trace(
        witness: &TransactionWitness,
        public_inputs: &TransactionPublicInputs,
    ) -> Result<(), AirErrorKind> {
        if witness.selectors.finalize_rows == 0 {
            return Err(AirErrorKind::ErrTxSelector);
        }
        let expected_rows = witness.inputs.len() + witness.outputs.len() + 1;
        if witness.selectors.total_rows() != expected_rows {
            return Err(AirErrorKind::ErrTxSelector);
        }

        let fee_public = u64_from_le_bytes(&public_inputs.fee);
        let nonce_public = u64_from_le_bytes(&public_inputs.nonce);

        let mut sum_in: u128 = 0;
        let mut sum_out: u128 = 0;

        let mut input_amounts = Vec::with_capacity(witness.inputs.len());
        for amount in &witness.inputs {
            let canonical = range_check_amount(*amount)?;
            sum_in += canonical as u128;
            input_amounts.push(canonical);
        }

        let mut output_amounts = Vec::with_capacity(witness.outputs.len());
        for amount in &witness.outputs {
            let canonical = range_check_amount(*amount)?;
            sum_out += canonical as u128;
            output_amounts.push(canonical);
        }

        let fee = range_check_amount(witness.fee)? as u128;

        if fee as u64 != fee_public {
            return Err(AirErrorKind::ErrTxBoundary);
        }
        if witness.nonce != nonce_public {
            return Err(AirErrorKind::ErrTxBoundary);
        }

        if sum_in != sum_out + fee {
            return Err(AirErrorKind::ErrTxBalance);
        }

        let mut rhs = output_amounts.clone();
        rhs.push(fee as u64);
        if multiset(&input_amounts) != multiset(&rhs) {
            return Err(AirErrorKind::ErrTxPermMismatch);
        }

        let inputs_root = hash_amounts("TX:inputs", &input_amounts);
        if inputs_root != public_inputs.input_commit_root {
            return Err(AirErrorKind::ErrTxBoundary);
        }
        let outputs_root = hash_amounts("TX:outputs", &output_amounts);
        if outputs_root != public_inputs.output_commit_root {
            return Err(AirErrorKind::ErrTxBoundary);
        }

        let digest = hash_transaction(witness);
        if digest != public_inputs.tx_id {
            return Err(AirErrorKind::ErrTxBoundary);
        }
        if witness.accumulator_digest != digest {
            return Err(AirErrorKind::ErrTxHashBind);
        }

        Ok(())
    }

    /// Leitet deterministische Public Inputs aus einem Zeugen ab.
    pub fn derive_public_inputs(witness: &TransactionWitness) -> TransactionPublicInputs {
        let fee = range_check_amount(witness.fee).unwrap_or(0).to_le_bytes();
        let nonce = witness.nonce.to_le_bytes();
        let input_amounts: Vec<u64> = witness
            .inputs
            .iter()
            .filter_map(|&v| range_check_amount(v).ok())
            .collect();
        let output_amounts: Vec<u64> = witness
            .outputs
            .iter()
            .filter_map(|&v| range_check_amount(v).ok())
            .collect();
        TransactionPublicInputs {
            tx_id: hash_transaction(witness),
            input_commit_root: hash_amounts("TX:inputs", &input_amounts),
            output_commit_root: hash_amounts("TX:outputs", &output_amounts),
            fee,
            nonce,
        }
    }
}
