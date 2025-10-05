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
}
