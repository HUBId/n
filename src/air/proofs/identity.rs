//! Identity-AIR-Profil.
//!
//! Bindet attestierte Policy-Eintraege an einen Poseidon-basierten Digest und
//! verknuepft diesen mit Aussteller/Subject-IDs. Externe Commitments bleiben an
//! das Transcript gebunden.

use super::ProofAirKind;

/// AIR-Skelett fuer Identitaetsbeweise.
pub struct IdentityAirProfile;
impl IdentityAirProfile {
    /// Zugehoerige Beweisart.
    pub const KIND: ProofAirKind = ProofAirKind::Identity;
    /// Maximale Spurbreite (<=28).
    pub const TRACE_WIDTH_MAX: usize = 28;
    /// Maximale Schrittanzahl (`2^17`).
    pub const TRACE_STEPS_MAX: usize = 1 << 17;
    /// Core-Register.
    pub const CORE_REGISTERS: &'static [&'static str] = &[
        "acc_policy",
        "attest_counter",
        "issuer_digest",
        "subject_digest",
    ];
    /// Aux-Register.
    pub const AUX_REGISTERS: &'static [&'static str] =
        &["policy_key_limb", "policy_value_limb", "range_helper"];
    /// Selektoren.
    pub const SELECTOR_REGISTERS: &'static [&'static str] =
        &["is_first", "is_last", "phase_absorb", "phase_finalize"];
    /// Public Inputs (LE).
    pub const PUBLIC_INPUTS: &'static [&'static str] = &[
        "IssuerID[32]",
        "SubjectID[32]",
        "AttestSlot[u64]",
        "PolicyHash[32]",
    ];
    /// Boundary-Regeln.
    pub const BOUNDARY_CONSTRAINTS: &'static [&'static str] = &[
        "acc_policy(0) = 0",
        "attest_counter(0) = 0",
        "attest_counter(T-1) = AttestSlot",
        "acc_policy(T-1) = PolicyHash_arith",
    ];
    /// Transition-Phasen.
    pub const TRANSITION_PHASES: &'static [&'static str] = &[
        "phase_absorb: Poseidon-Absorption feldkodierter Policy-Eintraege",
        "phase_finalize: Bindung an Public Inputs und Selektoren",
    ];
    /// Lookup-Argumente.
    pub const LOOKUPS: &'static [&'static str] = &["policy_key_range", "policy_value_format"];
    /// OOD-Oeffnungen.
    pub const OOD_OPENINGS: &'static [&'static str] = &["acc_policy", "composition_polynomial"];
    /// Grad-Hinweis.
    pub const DEGREE_HINT: &'static str =
        "Poseidon-Abschnitte Grad <=3; Selektor-Maskierung Grad <=2";
    /// Fehlermodi.
    pub const FAILURE_MODES: &'static [&'static str] = &["ErrIdentityPolicy"];
    /// Selektorformeln.
    pub const SELECTOR_FORMULAS: &'static [&'static str] = &[
        "is_first(i) = 1 falls i=0",
        "is_last(i) = 1 falls i=T-1",
        "phase_absorb(i) = 1 waehrend Poseidon-Absorptionsschritten",
        "phase_finalize(i) = 1 auf Abschlusszeilen",
    ];
}
