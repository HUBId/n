//! Transaction-AIR-Profil.
//!
//! Dieses Profil prueft Salden, Fees und Formatregeln einer UTXO-artigen
//! Transaktion. Die Pfadpruefung gegen externe BLAKE3-Merklebaeume findet ausserhalb
//! der AIR statt (Transcript-Bindung); innerhalb der AIR werden nur feldbasierte
//! Commitments via Poseidon gefuehrt.

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
        "permutation_running",
        "range_helper",
    ];
    /// Selektor-Spalten (deterministisch aus dem Zeilenindex).
    pub const SELECTOR_REGISTERS: &'static [&'static str] = &[
        "is_first",
        "is_last",
        "phase_io",
        "phase_acc",
        "phase_finalize",
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
        "sum_in(0) = 0",
        "sum_out(0) = 0",
        "fee_acc(0) = 0",
        "nonce_acc(0) = NonceStart",
        "sum_in(T-1) - sum_out(T-1) - Fee = 0",
        "nonce_acc(T-1) = Nonce",
        "acc_poseidon(T-1) = PoseidonDigestFromPI",
    ];
    /// Beschreibung der Transition-Phasen.
    pub const TRANSITION_PHASES: &'static [&'static str] = &[
        "phase_io: Inputs addieren, Outputs subtrahieren",
        "phase_acc: Rolling Poseidon fuer feldkodierte Listen",
        "phase_finalize: Balance & Fee Gleichungen",
    ];
    /// Lookups und Permutationsargumente.
    pub const LOOKUPS: &'static [&'static str] = &[
        "range_64bit_amount",
        "permutation_inputs_equals_outputs_plus_fee",
    ];
    /// OOD-Oeffnungen (Register + Komposition).
    pub const OOD_OPENINGS: &'static [&'static str] = &[
        "sum_in",
        "sum_out",
        "fee_acc",
        "acc_poseidon",
        "composition_polynomial",
    ];
    /// Grad-Hinweise fuer Constraints.
    pub const DEGREE_HINT: &'static str =
        "Additionen & Selektor-Maskierung Grad <=2; Lookup/Permutation Grad < LDE-Bound";
    /// Fehlermeldungen, die dieses Profil signalisiert.
    pub const FAILURE_MODES: &'static [&'static str] =
        &["ErrTxBalance", "ErrTxNonce", "ErrTxAccumulator"];
    /// Beschreibung deterministischer Selektoren.
    pub const SELECTOR_FORMULAS: &'static [&'static str] = &[
        "is_first(i) = 1 falls i=0, sonst 0",
        "is_last(i) = 1 falls i = T-1, sonst 0",
        "phase_io(i) = 1 innerhalb des Input/Output-Fensters, sonst 0",
        "phase_acc(i) = 1 fuer Poseidon-Absorptionsschritte",
        "phase_finalize(i) = 1 nur auf den letzten Zeilen",
    ];
}
