//! Aggregations-AIR-Profil (optional, zukuenftige Rekursion).
//!
//! Modelliert die feldbasierte Bindung einer geordneten Liste von Proof-Digests
//! an einen Aggregat-Digest. Externe Commitments fuer Unterbeweise bleiben an
//! das Transcript gebunden; innerhalb der AIR werden nur arithmetische Spiegel
//! gefuehrt.

use super::ProofAirKind;

/// AIR-Skelett fuer Aggregationsbeweise.
pub struct AggregationAirProfile;
impl AggregationAirProfile {
    /// Zugehoerige Beweisart.
    pub const KIND: ProofAirKind = ProofAirKind::Aggregation;
    /// Maximale Spurbreite (<=20).
    pub const TRACE_WIDTH_MAX: usize = 20;
    /// Maximale Schrittanzahl (`2^16`).
    pub const TRACE_STEPS_MAX: usize = 1 << 16;
    /// Core-Register.
    pub const CORE_REGISTERS: &'static [&'static str] = &["acc_digests", "digest_index"];
    /// Aux-Register.
    pub const AUX_REGISTERS: &'static [&'static str] = &["digest_fragment", "range_helper"];
    /// Selektoren.
    pub const SELECTOR_REGISTERS: &'static [&'static str] =
        &["is_first", "is_last", "phase_absorb", "phase_finalize"];
    /// Public Inputs (LE).
    pub const PUBLIC_INPUTS: &'static [&'static str] = &[
        "AggregatVersion[u8]",
        "Count[u32]",
        "ProofDigests[Count * 32]",
    ];
    /// Boundary-Regeln.
    pub const BOUNDARY_CONSTRAINTS: &'static [&'static str] = &[
        "acc_digests(0) = 0",
        "digest_index(0) = 0",
        "digest_index(T-1) = Count",
        "acc_digests(T-1) = AggregatDigest_from_transcript",
    ];
    /// Transition-Phasen.
    pub const TRANSITION_PHASES: &'static [&'static str] = &[
        "phase_absorb: Poseidon-Absorption der Proof-Digests",
        "phase_finalize: Bindung an Aggregat-Version und Count",
    ];
    /// Lookup-Argumente.
    pub const LOOKUPS: &'static [&'static str] = &["digest_sequence_order"];
    /// OOD-Oeffnungen.
    pub const OOD_OPENINGS: &'static [&'static str] = &["acc_digests", "composition_polynomial"];
    /// Grad-Hinweis.
    pub const DEGREE_HINT: &'static str =
        "Poseidon-Absorption Grad <=3; lineare Bindungen Grad <=2";
    /// Fehlermodi (derzeit keine spezifischen neben Basiskontrollen).
    pub const FAILURE_MODES: &'static [&'static str] = &[];
    /// Selektorformeln.
    pub const SELECTOR_FORMULAS: &'static [&'static str] = &[
        "is_first(i) = 1 falls i=0",
        "is_last(i) = 1 falls i=T-1",
        "phase_absorb(i) = 1 fuer Digest-Absorption",
        "phase_finalize(i) = 1 fuer Abschlusszeilen",
    ];
}
