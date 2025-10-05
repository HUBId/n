//! Pruning-AIR-Profil.
//!
//! Modelliert deterministisches Entfernen oder Verdichten von Daten. Die
//! Wiederherstellbarkeit wird ueber einen extern gebundenen Anchor garantiert;
//! Merkle-Pfade verbleiben ausserhalb der AIR (Transcript-Bindung).

use super::ProofAirKind;

/// AIR-Skelett fuer Pruning-Beweise.
pub struct PruningAirProfile;
impl PruningAirProfile {
    /// Zugehoerige Beweisart.
    pub const KIND: ProofAirKind = ProofAirKind::Pruning;
    /// Maximale Spurbreite (<=48).
    pub const TRACE_WIDTH_MAX: usize = 48;
    /// Maximale Schrittanzahl (`2^21`).
    pub const TRACE_STEPS_MAX: usize = 1 << 21;
    /// Core-Register.
    pub const CORE_REGISTERS: &'static [&'static str] = &[
        "A_old",
        "A_new",
        "A_anchor",
        "E_key",
        "E_val",
        "keep_flag",
        "drop_flag",
    ];
    /// Aux-Register fuer Zerlegungen und Grand-Product.
    pub const AUX_REGISTERS: &'static [&'static str] = &[
        "key_limb_lo",
        "key_limb_hi",
        "value_limb_lo",
        "value_limb_hi",
        "policy_helper",
        "grand_product_z",
    ];
    /// Selektoren.
    pub const SELECTOR_REGISTERS: &'static [&'static str] = &[
        "sigma_first",
        "sigma_last",
        "sigma_filter",
        "sigma_finalize",
    ];
    /// Public Inputs (LE).
    pub const PUBLIC_INPUTS: &'static [&'static str] = &[
        "OldPruneDigest[32]",
        "NewPruneDigest[32]",
        "RecoveryAnchor[32]",
    ];
    /// Boundary-Regeln.
    pub const BOUNDARY_CONSTRAINTS: &'static [&'static str] = &[
        "sigma_first * (A_old - OldPruneDigest) = 0",
        "sigma_first * (grand_product_z - 1) = 0",
        "sigma_last * (A_old - OldPruneDigest) = 0",
        "sigma_last * (A_new - NewPruneDigest) = 0",
        "sigma_last * (A_anchor - RecoveryAnchor) = 0",
        "sigma_last * (grand_product_z - 1) = 0",
    ];
    /// Transition-Phasen.
    pub const TRANSITION_PHASES: &'static [&'static str] = &[
        "sigma_filter: Partition (keep/drop) und Akkumulator-Updates",
        "grand_product: Multiset-Bindung old ↔ keep ∪ drop",
        "sigma_finalize: Konstanz der Akkumulatoren und des Grand-Products",
    ];
    /// Lookup-/Permutation-Argumente.
    pub const LOOKUPS: &'static [&'static str] = &[
        "range_key_format",
        "range_value_format",
        "policy_to_flags_deterministic",
        "permutation_old_equals_keep_union_drop",
    ];
    /// OOD-Oeffnungen.
    pub const OOD_OPENINGS: &'static [&'static str] = &[
        "A_old",
        "A_new",
        "A_anchor",
        "grand_product_z",
        "composition_polynomial",
    ];
    /// Grad-Hinweis.
    pub const DEGREE_HINT: &'static str =
        "Lineare Filter-Regeln Grad <=2; Permutation Grad < LDE-Bound";
    /// Fehlermodi.
    pub const FAILURE_MODES: &'static [&'static str] = &[
        "ErrPruneBoundary",
        "ErrPrunePartition",
        "ErrPruneFormat",
        "ErrPrunePolicy",
        "ErrPrunePermutation",
        "ErrPruneSelector",
    ];
    /// Selektorformeln.
    pub const SELECTOR_FORMULAS: &'static [&'static str] = &[
        "sigma_first(i) = 1 ⇔ i = 0",
        "sigma_last(i) = 1 ⇔ i = T-1",
        "sigma_filter(i) + sigma_finalize(i) = 1",
        "sigma_filter(i) * sigma_finalize(i) = 0",
    ];
}
