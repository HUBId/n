//! VRF-AIR-Profil (post-quantum, RLWE-basiert).
//!
//! Modelliert die korrekte Auswertung einer RLWE-basierten PRF sowie die Bindung
//! des geheimen Schluessels an ein Commitment. Das resultierende Feld-Element `y`
//! wird ausserhalb der AIR zu einem 32-Byte VRF-Output expandiert. Externe
//! Commitments (z. B. fuer `pk`) werden ueber das Transcript gebunden.

use super::ProofAirKind;

/// AIR-Skelett fuer VRF-Beweise.
pub struct VrfAirProfile;
impl VrfAirProfile {
    /// Zugehoerige Beweisart.
    pub const KIND: ProofAirKind = ProofAirKind::Vrf;
    /// Maximale Spurbreite (<=96).
    pub const TRACE_WIDTH_MAX: usize = 96;
    /// Maximale Schrittanzahl (`2^19`).
    pub const TRACE_STEPS_MAX: usize = 1 << 19;
    /// Core-Register (NTT-freundliche Akkumulatoren und Commit-Spiegel).
    pub const CORE_REGISTERS: &'static [&'static str] = &[
        "poly_a_ntt",
        "poly_b_ntt",
        "poly_result_ntt",
        "poly_result_coeff",
        "acc_pk",
        "acc_y",
        "phase_flag",
    ];
    /// Aux-Register fuer Zerlegungen und Indexierung.
    pub const AUX_REGISTERS: &'static [&'static str] = &[
        "index_helper",
        "twiddle_limb",
        "modulus_fragment",
        "range_helper",
        "decomposition_flag",
    ];
    /// Selektoren.
    pub const SELECTOR_REGISTERS: &'static [&'static str] = &[
        "is_first",
        "is_last",
        "phase_ntt",
        "phase_mul",
        "phase_intt",
        "phase_commit",
        "phase_finalize",
    ];
    /// Public Inputs (LE-Layout, Reihenfolge).
    pub const PUBLIC_INPUTS: &'static [&'static str] = &[
        "pk_commitment[? bytes, LE]",
        "input_x[field/bytes, LE]",
        "PRF-ParamDigest[32]",
    ];
    /// Boundary-Regeln.
    pub const BOUNDARY_CONSTRAINTS: &'static [&'static str] = &[
        "acc_pk(0) = 0",
        "acc_y(0) = 0",
        "acc_pk(T-1) = pk_commitment_arith",
        "acc_y(T-1) = y_arith",
    ];
    /// Transition-Phasen.
    pub const TRANSITION_PHASES: &'static [&'static str] = &[
        "phase_ntt: Vorwaerts-NTT ueber poly_a_ntt/poly_b_ntt",
        "phase_mul: komponentenweise Multiplikation und Maskierung",
        "phase_intt: Ruecktransformation zur Koeffizientenbasis",
        "phase_commit: Bindung encode(s) -> pk_commit",
        "phase_finalize: Bindung des Ergebnisses an Public Inputs",
    ];
    /// Lookup-/Tabellenverweise.
    pub const LOOKUPS: &'static [&'static str] =
        &["ntt_twiddle_table", "modulus_range", "index_bounds"];
    /// OOD-Oeffnungen.
    pub const OOD_OPENINGS: &'static [&'static str] =
        &["acc_y", "acc_pk", "composition_polynomial"];
    /// Grad-Hinweis.
    pub const DEGREE_HINT: &'static str =
        "Produktgleichungen fuer Poly-Multiplikation Grad <=3; Selektor-Maskierung <=2";
    /// Fehlermodi.
    pub const FAILURE_MODES: &'static [&'static str] = &["ErrVrfPhaseMismatch"];
    /// Selektorformeln.
    pub const SELECTOR_FORMULAS: &'static [&'static str] = &[
        "is_first(i) = 1 falls i=0",
        "is_last(i) = 1 falls i=T-1",
        "phase_ntt(i) = 1 fuer Zeilen im Vorwaerts-NTT-Block",
        "phase_mul(i) = 1 fuer Zeilen der komponentenweisen Multiplikation",
        "phase_intt(i) = 1 fuer Ruecktransformation",
        "phase_commit(i) = 1 fuer Commitment-Bindung",
        "phase_finalize(i) = 1 fuer Abschlusszeilen",
    ];
}
