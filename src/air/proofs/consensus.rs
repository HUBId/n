//! Consensus-AIR-Profil.
//!
//! Verknuepft rundenbezogene Metadaten mit einem Committee-Commitment und
//! zaehlt ein deterministisches Quorum. Externe Commitments (z. B. fuer
//! Mitgliederlisten) werden ueber Transcript-Digests gebunden.

use super::ProofAirKind;

/// AIR-Skelett fuer Konsensbeweise.
pub struct ConsensusAirProfile;
impl ConsensusAirProfile {
    /// Zugehoerige Beweisart.
    pub const KIND: ProofAirKind = ProofAirKind::Consensus;
    /// Maximale Spurbreite (<=36).
    pub const TRACE_WIDTH_MAX: usize = 36;
    /// Maximale Schrittanzahl (`2^18`).
    pub const TRACE_STEPS_MAX: usize = 1 << 18;
    /// Core-Register.
    pub const CORE_REGISTERS: &'static [&'static str] =
        &["vote_acc", "quorum_acc", "slot_acc", "committee_digest_acc"];
    /// Aux-Register.
    pub const AUX_REGISTERS: &'static [&'static str] = &[
        "member_id_limb",
        "signature_fragment",
        "permutation_running",
    ];
    /// Selektoren.
    pub const SELECTOR_REGISTERS: &'static [&'static str] =
        &["is_first", "is_last", "phase_tally", "phase_finalize"];
    /// Public Inputs (LE).
    pub const PUBLIC_INPUTS: &'static [&'static str] = &[
        "Round[u64]",
        "CommitteeRoot[32]",
        "Quorum[u16]",
        "Slot[u16]",
    ];
    /// Boundary-Regeln.
    pub const BOUNDARY_CONSTRAINTS: &'static [&'static str] = &[
        "quorum_acc(0) = 0",
        "slot_acc(0) = 0",
        "slot_acc(T-1) = Slot",
        "quorum_acc(T-1) = Quorum",
        "committee_digest_acc(T-1) = CommitteeRoot_arith",
    ];
    /// Transition-Phasen.
    pub const TRANSITION_PHASES: &'static [&'static str] = &[
        "phase_tally: akzeptierte Stimmen in vote_acc/quorum_acc aggregieren",
        "phase_finalize: Round/Slot-Bindung und Committee-Konsistenz",
    ];
    /// Lookup-/Permutation-Argumente.
    pub const LOOKUPS: &'static [&'static str] = &["validator_id_table", "vote_format_range"];
    /// OOD-Oeffnungen.
    pub const OOD_OPENINGS: &'static [&'static str] =
        &["quorum_acc", "vote_acc", "composition_polynomial"];
    /// Grad-Hinweis.
    pub const DEGREE_HINT: &'static str =
        "Lineare Quorum-Akkumulation Grad <=2; Tabellen-Lookups Grad gemaess Schema";
    /// Fehlermodi.
    pub const FAILURE_MODES: &'static [&'static str] = &["ErrConsensusQuorum"];
    /// Selektorformeln.
    pub const SELECTOR_FORMULAS: &'static [&'static str] = &[
        "is_first(i) = 1 falls i=0",
        "is_last(i) = 1 falls i=T-1",
        "phase_tally(i) = 1 fuer Zeilen mit gueltigen Stimmen",
        "phase_finalize(i) = 1 auf Abschlusszeilen",
    ];
}
