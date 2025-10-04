//! Typisierte Container fuer Public Inputs aller Beweisarten.
//!
//! Die Container bilden exakt die in Phase 2 festgelegte Serialisierung ab
//! (Little-Endian, Spalten-major). Jede Struktur implementiert das Markertrait
//! [`PublicInputs`], das von [`AirSpec`](crate::air::traits::AirSpec)
//! instanzen verwendet wird.

/// Markertrait ohne Methoden zur Kennzeichnung von Public-Input-Containern.
pub trait PublicInputs: Send + Sync {}

/// Public Inputs fuer Identitaetsbeweise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityPublicInputs {
    /// LE-kodierte Kennung des Ausstellers (`IssuerID`, 32 Byte).
    pub issuer_id: [u8; 32],
    /// LE-kodierte Kennung des Subjekts (`SubjectID`, 32 Byte).
    pub subject_id: [u8; 32],
    /// Ausstellungs-Slot (LE-u64), bindet die Attest-Guelitigkeit an Phase 6.
    pub attest_slot: [u8; 8],
    /// Policy-Digest (LE, 32 Byte) fuer die gebundene Attribut-Policy.
    pub policy_hash: [u8; 32],
}
impl PublicInputs for IdentityPublicInputs {}

/// Public Inputs fuer Transaktionsbeweise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionPublicInputs {
    /// LE-kodierter Transaktionshash.
    pub tx_id: [u8; 32],
    /// Wurzel des Input-Commitment-Baums.
    pub input_commit_root: [u8; 32],
    /// Wurzel des Output-Commitment-Baums.
    pub output_commit_root: [u8; 32],
    /// LE-kodierte Fee.
    pub fee: [u8; 8],
    /// LE-kodierter Nonce-Wert.
    pub nonce: [u8; 8],
}
impl PublicInputs for TransactionPublicInputs {}

/// Public Inputs fuer Uptime-Beweise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UptimePublicInputs {
    /// Knoteninfix (LE, 32 Byte) der gebundenen Uptime-Sequenz.
    pub node_id: [u8; 32],
    /// Epochennummer (LE-u64) laut Beacon-Chain.
    pub epoch: [u8; 8],
    /// Slotnummer (LE-u16) fuer das letzte Heartbeat-Event.
    pub slot: [u8; 2],
    /// Commitment auf den bisherigen Uptime-Zustand (32 Byte, LE).
    pub prev_uptime_root: [u8; 32],
}
impl PublicInputs for UptimePublicInputs {}

/// Public Inputs fuer Konsensbeweise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsensusPublicInputs {
    /// Rundenzaehler (LE-u64), bindet die Phase 5-Metadaten.
    pub round: [u8; 8],
    /// Committee-Root (32 Byte, LE) fuer die validierten Stimmrechte.
    pub committee_root: [u8; 32],
    /// Quorum-Schwelle (LE-u16) laut Sicherheitsparametern.
    pub quorum: [u8; 2],
    /// Slotnummer (LE-u16) fuer den Konsensschritt.
    pub slot: [u8; 2],
}
impl PublicInputs for ConsensusPublicInputs {}

/// Public Inputs fuer State-Uebergangsbeweise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatePublicInputs {
    /// Merkle-Root des Vorzustands.
    pub pre_state_root: [u8; 32],
    /// Merkle-Root des Nachzustands.
    pub post_state_root: [u8; 32],
    /// Digest der Zustandsdifferenz (LE-Format).
    pub diff_digest: [u8; 32],
}
impl PublicInputs for StatePublicInputs {}

/// Public Inputs fuer Pruning-Beweise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PruningPublicInputs {
    /// Digest des alten Pruning-Zustands.
    pub old_prune_digest: [u8; 32],
    /// Digest des neuen Pruning-Zustands.
    pub new_prune_digest: [u8; 32],
    /// Recovery-Anker fuer nachgelagerte Beweise.
    pub recovery_anchor: [u8; 32],
}
impl PublicInputs for PruningPublicInputs {}

/// Public Inputs fuer Aggregationsbeweise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AggregationPublicInputs {
    /// Aggregations-Versionsbyte (LE-u8) fuer Rueckwaertskompatibilitaet.
    pub aggregate_version: u8,
    /// Anzahl der enthaltenen Unterbeweise (LE-u32).
    pub count: [u8; 4],
    /// Geordnete Liste der Proof-Digests (LE-serialisierte 32-Byte-Werte).
    pub proof_digests: Vec<[u8; 32]>,
}
impl PublicInputs for AggregationPublicInputs {}

/// Public Inputs fuer VRF-Beweise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VrfPublicInputs {
    /// Commitment-Bytes des oeffentlichen Schluessels (`pk`), LE-serialisiert.
    pub pk_commitment: Vec<u8>,
    /// Eingabe `x` des PRF (Feld- oder Byte-Repräsentation, LE-Layout).
    pub input_x: Vec<u8>,
    /// Digest der PRF-Parameter (32 Byte, LE), bindet Phase-6-Konfigurationen.
    pub prf_param_digest: [u8; 32],
}
impl PublicInputs for VrfPublicInputs {}
