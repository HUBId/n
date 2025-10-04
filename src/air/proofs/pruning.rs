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
        "acc_old",
        "acc_new",
        "acc_anchor",
        "keep_flag",
        "drop_flag",
        "element_index",
    ];
    /// Aux-Register fuer Zerlegungen.
    pub const AUX_REGISTERS: &'static [&'static str] = &[
        "segment_tag",
        "range_helper",
        "permutation_running",
        "anchor_helper",
    ];
    /// Selektoren.
    pub const SELECTOR_REGISTERS: &'static [&'static str] =
        &["is_first", "is_last", "phase_filter", "phase_anchor"];
    /// Public Inputs (LE).
    pub const PUBLIC_INPUTS: &'static [&'static str] = &[
        "OldPruneDigest[32]",
        "NewPruneDigest[32]",
        "RecoveryAnchor[32]",
    ];
    /// Boundary-Regeln.
    pub const BOUNDARY_CONSTRAINTS: &'static [&'static str] = &[
        "acc_old(0) = OldPruneDigest_arith",
        "acc_new(T-1) = NewPruneDigest_arith",
        "acc_anchor(T-1) = RecoveryAnchor_arith",
    ];
    /// Transition-Phasen.
    pub const TRANSITION_PHASES: &'static [&'static str] = &[
        "phase_filter: keep/drop Entscheidung, Multiset-Bindung",
        "phase_anchor: Weitergabe gedroppter Elemente in acc_anchor",
    ];
    /// Lookup-/Permutation-Argumente.
    pub const LOOKUPS: &'static [&'static str] = &[
        "permutation_old_equals_keep_union_drop",
        "range_segment_format",
    ];
    /// OOD-Oeffnungen.
    pub const OOD_OPENINGS: &'static [&'static str] =
        &["acc_old", "acc_new", "acc_anchor", "composition_polynomial"];
    /// Grad-Hinweis.
    pub const DEGREE_HINT: &'static str =
        "Lineare Filter-Regeln Grad <=2; Permutation Grad < LDE-Bound";
    /// Fehlermodi.
    pub const FAILURE_MODES: &'static [&'static str] = &["ErrPruneAnchor"];
    /// Selektorformeln.
    pub const SELECTOR_FORMULAS: &'static [&'static str] = &[
        "is_first(i) = 1 falls i=0",
        "is_last(i) = 1 falls i=T-1",
        "phase_filter(i) = 1 waehrend des Keep/Drop-Segments",
        "phase_anchor(i) = 1 fuer Zeilen, die den Anchor aktualisieren",
    ];
}
