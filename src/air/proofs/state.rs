//! State-Transition-AIR-Profil.
//!
//! Bindet deterministische Zustandsaenderungen an Pre-/Post-Roots und ein
//! Diff-Commitment. Externe BLAKE3-Pfade werden ausschliesslich ueber das
//! Transcript verifiziert; die AIR arbeitet mit feldkodierten Aggregatoren.

use super::ProofAirKind;

/// AIR-Skelett fuer State-Beweise.
pub struct StateAirProfile;
impl StateAirProfile {
    /// Zugehoerige Beweisart.
    pub const KIND: ProofAirKind = ProofAirKind::State;
    /// Maximale Spurbreite fuer das Standardprofil (<=72 Spalten).
    pub const TRACE_WIDTH_MAX: usize = 72;
    /// Maximale Schrittanzahl (`2^22`).
    pub const TRACE_STEPS_MAX: usize = 1 << 22;
    /// Core-Register in kanonischer Reihenfolge.
    pub const CORE_REGISTERS: &'static [&'static str] = &[
        "acc_pre",
        "acc_post",
        "delta_acc",
        "apply_flag",
        "key_acc",
        "value_acc",
        "scan_index",
    ];
    /// Aux-Register fuer Zerlegungen und Lookup-Hilfen.
    pub const AUX_REGISTERS: &'static [&'static str] = &[
        "key_limb_0",
        "key_limb_1",
        "key_limb_2",
        "value_limb_0",
        "value_limb_1",
        "value_limb_2",
        "sign_flag",
        "permutation_running",
    ];
    /// Selektoren (deterministisch aus Zeilenindex und Profil-Konstanten).
    pub const SELECTOR_REGISTERS: &'static [&'static str] =
        &["is_first", "is_last", "phase_scan", "phase_apply"];
    /// Public-Input-Reihenfolge (LE-Layout).
    pub const PUBLIC_INPUTS: &'static [&'static str] =
        &["PreStateRoot[32]", "PostStateRoot[32]", "DiffDigest[32]"];
    /// Boundary-Regeln mit Bindung an Public Inputs.
    pub const BOUNDARY_CONSTRAINTS: &'static [&'static str] = &[
        "acc_pre(0) = PreStateDigest_arith",
        "acc_post(T-1) = PostStateDigest_arith",
        "delta_acc(T-1) = DiffDigest_arith",
    ];
    /// Transition-Phasen.
    pub const TRANSITION_PHASES: &'static [&'static str] = &[
        "phase_scan: scannt geordnete Key/Value-Paare und aktualisiert acc_pre/acc_post",
        "phase_apply: erzwingt Einfuegen/Ersetzen/Loeschen via apply_flag",
    ];
    /// Lookup- und Permutationsargumente.
    pub const LOOKUPS: &'static [&'static str] = &[
        "permutation_pre_plus_diff_equals_post",
        "range_key_format",
        "range_value_format",
    ];
    /// OOD-Oeffnungen.
    pub const OOD_OPENINGS: &'static [&'static str] =
        &["acc_pre", "acc_post", "delta_acc", "composition_polynomial"];
    /// Grad-Hinweise.
    pub const DEGREE_HINT: &'static str =
        "Lineare Aggregation Grad <=2; Permutationsargument Grad < LDE-Bound";
    /// Fehlermodi dieses Profils.
    pub const FAILURE_MODES: &'static [&'static str] =
        &["ErrStateDeltaMismatch", "ErrStatePermutation"];
    /// Selektorformeln.
    pub const SELECTOR_FORMULAS: &'static [&'static str] = &[
        "is_first(i) = 1 falls i=0",
        "is_last(i) = 1 falls i=T-1",
        "phase_scan(i) = 1 fuer alle Scan-Zeilen gem. Profil-Konstanten",
        "phase_apply(i) = 1 auf Zeilen, in denen apply_flag wirkt",
    ];
}
