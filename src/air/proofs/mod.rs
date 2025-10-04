//! AIR-Profile fuer alle Beweisarten von `rpp-stark`.
//!
//! Die Dokumentation in den Untermodulen fasst die Registeraufteilung,
//! Boundary- und Uebergangsbedingungen, Lookup-Argumente sowie die
//! verpflichtenden OOD-Oeffnungen zusammen. Implementierungen muessen die
//! globalen Regeln einhalten: Spalten-major Speicherordnung, dichte Traces mit
//! Schrittweite 1, deterministische Selektoren und lineare Kompositionen ueber
//! unabhaengige Herausforderungen (`alpha`).

mod aggregation;
mod consensus;
mod identity;
mod pruning;
mod state;
mod transaction;
mod uptime;
mod vrf;

pub use aggregation::AggregationAirProfile;
pub use consensus::ConsensusAirProfile;
pub use identity::IdentityAirProfile;
pub use pruning::PruningAirProfile;
pub use state::StateAirProfile;
pub use transaction::TransactionAirProfile;
pub use uptime::UptimeAirProfile;
pub use vrf::VrfAirProfile;

use super::traits::TraceGroup;

/// Auflistung aller unterstuetzten AIR-Arten.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofAirKind {
    /// Identitaets-AIR (Phase 4/5 Bindung der Policy).
    Identity,
    /// Transaktions-AIR fuer UTXO-Bilanzen.
    Transaction,
    /// Uptime-AIR fuer Heartbeat-Protokolle.
    Uptime,
    /// Konsens-AIR fuer Quorum-Pruefungen.
    Consensus,
    /// State-Uebergangs-AIR.
    State,
    /// Pruning-AIR fuer deterministische Verdichtung.
    Pruning,
    /// Aggregations-AIR (optional, fuer zukuenftige Rekursion).
    Aggregation,
    /// VRF-AIR fuer PQ-feste PRF-Beweise.
    Vrf,
}

/// Commitment-Reihenfolge ueber Registergruppen.
pub const COMMITMENT_ORDER: &[TraceGroup] = &[TraceGroup::Core, TraceGroup::Auxiliary];
