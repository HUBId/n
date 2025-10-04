//! Trace- und Kontextbeschreibungen fuer AIR-Instanzen.
//!
//! Dieses Modul dokumentiert, wie Spuren aufgebaut werden und welche Metadaten
//! eine konkrete [`AirSpec`](crate::air::traits::AirSpec) bereitstellen muss.
//! Die Strukturen sind rein beschreibend und enthalten keinerlei
//! Evaluierungslogik. Alle Felder folgen der Little-Endian Serialisierung.

use super::traits::TraceGroup;

/// Beschreibt die dichte Ausfuehrungsspur einer AIR-Instanz.
///
/// * `width` zaehlt die Gesamtzahl aller Registerspalten (Core + Aux + Selektoren).
/// * `steps` definiert die Spurlaenge in Schritten; Schrittweite ist strikt `1`.
/// * `registers` listet alle Register in kanonischer Reihenfolge (zuerst Core,
///   danach Aux, zuletzt Selektoren). Jeder Eintrag enthaelt Offsets, damit
///   Speicherblöcke nachvollziehbar bleiben.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceInfo {
    /// Gesamtbreite des Traces in Spalten.
    pub width: usize,
    /// Anzahl der Schritte in der dichten Spur.
    pub steps: usize,
    /// Kanonische Beschreibung saemtlicher Register.
    pub registers: Vec<TraceRegister>,
}

/// Beschreibt ein einzelnes Register innerhalb der Spur.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceRegister {
    /// Eindeutiger Index (0-basierend) innerhalb des Register-Arrays.
    pub column: usize,
    /// Gruppenzugehoerigkeit des Registers.
    pub group: TraceGroup,
    /// Byte-Offset bezogen auf den Anfang des jeweiligen Gruppenspeichers
    /// (column-major, LE-Serialisierung).
    pub group_offset: usize,
}

/// Offset der Trace-Domäne relativ zum Einheitswurzelgenerator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TraceDomainOffset {
    /// Rohbytes der Offset-Repräsentation im LE-Format.
    pub le_bytes: [u8; 32],
}

/// Digest einer deterministischen FRI-Planinstanz.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FriPlanDigest {
    /// 32 Byte BLAKE2s-kompatibler Digest im LE-Format.
    pub le_bytes: [u8; 32],
}

/// Kontextbeschreibung, die jede [`AirSpec`](crate::air::traits::AirSpec)
/// zur Verfügung stellen muss.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AirContext {
    /// Spur- und Registerinformationen in kanonischer Ordnung.
    pub trace: TraceInfo,
    /// Höchstgrad der Kompositionspolynome.
    pub composition_degree: usize,
    /// Maximalgrad einzelner Randbedingungen.
    pub boundary_degree: usize,
    /// Maximalgrad einzelner Uebergangsbedingungen.
    pub transition_degree: usize,
    /// Anzahl der verlangten OOD-Punkte (>= 2 laut Spezifikation).
    pub ood_points: usize,
    /// Faktor für die Low-Degree-Extension.
    pub lde_factor: usize,
    /// Offset der Trace-Domäne für Core- und Aux-Gruppen.
    pub domain_offset: TraceDomainOffset,
    /// Digest des FRI-Plans für die Beweisinstanz.
    pub fri_plan: FriPlanDigest,
    /// Deterministische Gruppenzuordnung für Commitments.
    pub group_digests: Vec<ParameterDigest>,
}

use super::ids::ParameterDigest;
