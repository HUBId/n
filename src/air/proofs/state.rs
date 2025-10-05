//! State-Transition-AIR-Profil.
//!
//! Bindet deterministische Zustandsaenderungen an Pre-/Post-Roots sowie an ein
//! Diff-Commitment. Die Feinspezifikation unterscheidet zwei deterministische
//! Phasen (Scan/Finalize) und modelliert pro Trace-Zeile genau eine Operation
//! aus {INS, UPD, DEL}. Key- und Value-Werte werden feldkodiert; externe
//! BLAKE3-Pfade erscheinen nur im Transcript. Das Profil verlangt Tests fuer
//! reine Insert-/Delete-/Update-Serien (akzeptierend) sowie fuer fehlerhafte
//! Permutationen, Formate, Op-Tags, triviale Updates und Boundary-Verletzungen.

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
        "A_pre", "A_post", "A_diff", "K", "V_old", "V_new", "Op_tag", "H_acc",
    ];
    /// Aux-Register fuer Zerlegungen und Lookup-Hilfen.
    pub const AUX_REGISTERS: &'static [&'static str] = &[
        "key_limb_lo",
        "key_limb_hi",
        "value_old_lo",
        "value_old_hi",
        "value_new_lo",
        "value_new_hi",
        "null_flag",
        "delta_helper",
        "grand_product_z",
    ];
    /// Selektoren (deterministisch aus Zeilenindex und Profil-Konstanten).
    pub const SELECTOR_REGISTERS: &'static [&'static str] = &["sigma_scan", "sigma_finalize"];
    /// Public-Input-Reihenfolge (LE-Layout).
    pub const PUBLIC_INPUTS: &'static [&'static str] =
        &["PreStateRoot[32]", "PostStateRoot[32]", "DiffDigest[32]"];
    /// Boundary-Regeln mit Bindung an Public Inputs.
    pub const BOUNDARY_CONSTRAINTS: &'static [&'static str] = &[
        "sigma_scan(0) * (A_pre - PreStateDigest) = 0",
        "sigma_finalize(T-1) * (A_post - PostStateDigest) = 0",
        "sigma_finalize(T-1) * (A_diff - DiffDigest) = 0",
        "grand_product_z(0) = 1",
        "grand_product_z(T-1) = 1",
    ];
    /// Transition-Phasen.
    pub const TRANSITION_PHASES: &'static [&'static str] = &[
        "phi_pre: absorbiert (K, V_old) in A_pre",
        "phi_diff: absorbiert (Op_tag, K, V_old, V_new) in A_diff",
        "phi_post: absorbiert (K, V_new) in A_post",
        "grand_product: koppelt A_pre und A_diff gegen A_post via β,γ,δ",
        "sigma_finalize: haelt A_pre/A_post/A_diff/K/V_* konstant",
    ];
    /// Lookup- und Permutationsargumente.
    pub const LOOKUPS: &'static [&'static str] = &[
        "op_tag_in_{INS,UPD,DEL}",
        "range_key_format",
        "range_value_format",
        "null_representation",
        "update_non_trivial",
        "grand_product_pre_plus_diff_equals_post",
    ];
    /// OOD-Oeffnungen.
    pub const OOD_OPENINGS: &'static [&'static str] = &[
        "A_pre",
        "A_post",
        "A_diff",
        "grand_product_z",
        "composition_polynomial",
    ];
    /// Grad-Hinweise.
    pub const DEGREE_HINT: &'static str =
        "Linearitaet Grad <=2; Grand-Product & Permutation Grad < LDE-Bound";
    /// Fehlermodi dieses Profils.
    pub const FAILURE_MODES: &'static [&'static str] = &[
        "ErrStateBoundary",
        "ErrStateOpTag",
        "ErrStateFormat",
        "ErrStateUpdateTrivial",
        "ErrStatePermutation",
        "ErrStateSelector",
    ];
    /// Selektorformeln.
    pub const SELECTOR_FORMULAS: &'static [&'static str] = &[
        "sigma_scan(i) * sigma_finalize(i) = 0",
        "sigma_scan(i) + sigma_finalize(i) = 1",
        "sigma_scan(0) = 1 und sigma_finalize(T-1) = 1",
    ];
}
