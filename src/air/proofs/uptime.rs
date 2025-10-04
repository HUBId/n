//! Uptime-AIR-Profil.
//!
//! Bindet Heartbeat-Ereignisse eines Knotens an ein neues Uptime-Commitment.
//! Externe Commitments (z. B. BLAKE3-Merkle) werden ueber Transcript und
//! Commitment-Digests gebunden, nicht innerhalb der AIR simuliert.

use super::ProofAirKind;

/// AIR-Skelett fuer Uptime-Beweise.
pub struct UptimeAirProfile;
impl UptimeAirProfile {
    /// Zugehoerige Beweisart.
    pub const KIND: ProofAirKind = ProofAirKind::Uptime;
    /// Maximale Spurbreite (<=30).
    pub const TRACE_WIDTH_MAX: usize = 30;
    /// Maximale Schrittanzahl (`2^18`).
    pub const TRACE_STEPS_MAX: usize = 1 << 18;
    /// Core-Register.
    pub const CORE_REGISTERS: &'static [&'static str] =
        &["acc_uptime", "slot_counter", "presence_bit", "epoch_hint"];
    /// Aux-Register.
    pub const AUX_REGISTERS: &'static [&'static str] = &[
        "slot_range_helper",
        "epoch_range_helper",
        "node_id_fragment",
    ];
    /// Selektoren.
    pub const SELECTOR_REGISTERS: &'static [&'static str] =
        &["is_first", "is_last", "phase_tick", "phase_finalize"];
    /// Public Inputs (LE).
    pub const PUBLIC_INPUTS: &'static [&'static str] = &[
        "NodeID[32]",
        "Epoch[u64]",
        "Slot[u16]",
        "PrevUptimeRoot[32]",
    ];
    /// Boundary-Regeln.
    pub const BOUNDARY_CONSTRAINTS: &'static [&'static str] = &[
        "acc_uptime(0) = PrevUptimeDigest_arith",
        "slot_counter(0) = 0",
        "slot_counter(T-1) = Slot",
        "acc_uptime(T-1) = NewUptimeDigest_from_transcript",
    ];
    /// Transition-Phasen.
    pub const TRANSITION_PHASES: &'static [&'static str] = &[
        "phase_tick: inkrementiert slot_counter und absorbiert presence_bit",
        "phase_finalize: bindet NodeID/Epoch/Slot an Output-Commitment",
    ];
    /// Lookup-Argumente.
    pub const LOOKUPS: &'static [&'static str] =
        &["range_slot_u16", "range_epoch_u64", "node_id_format"];
    /// OOD-Oeffnungen.
    pub const OOD_OPENINGS: &'static [&'static str] =
        &["acc_uptime", "slot_counter", "composition_polynomial"];
    /// Grad-Hinweis.
    pub const DEGREE_HINT: &'static str =
        "Lineare Updates Grad <=2; Range-Lookups Grad gemaess Tabellen";
    /// Fehlermodi.
    pub const FAILURE_MODES: &'static [&'static str] = &["ErrUptimeSlot"];
    /// Selektorformeln.
    pub const SELECTOR_FORMULAS: &'static [&'static str] = &[
        "is_first(i) = 1 falls i=0",
        "is_last(i) = 1 falls i=T-1",
        "phase_tick(i) = 1 fuer alle Heartbeat-Zeilen",
        "phase_finalize(i) = 1 auf dem Abschlussfenster",
    ];
}
