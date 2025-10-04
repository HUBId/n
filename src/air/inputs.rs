//! Typisierte Container fuer Public Inputs aller Beweisarten.
//!
//! Die Container bilden exakt die in Phase 2 festgelegte Serialisierung ab
//! (Little-Endian, Spalten-major). Jede Struktur implementiert das Markertrait
//! [`PublicInputs`], das von [`AirSpec`](crate::air::traits::AirSpec)
//! instanzen verwendet wird.

/// Markertrait ohne Methoden zur Kennzeichnung von Public-Input-Containern.
pub trait PublicInputs: Send + Sync {}

/// Public Inputs fuer Identity-Beweise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityPublicInputs {
    /// Commitment auf die Identitaetsattribute (z. B. Merkle-Root).
    pub identity_commitment: [u8; 32],
    /// Seriennummer fuer Revocations (LE-serialisiert).
    pub revocation_counter: [u8; 8],
    /// Aktive Gültigkeitsperiode (Start-Ende im LE-Format).
    pub validity_window: [u8; 16],
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
    /// Validatoren-ID im LE-Format.
    pub validator_id: [u8; 16],
    /// Epochennummer.
    pub epoch: [u8; 8],
    /// Bitmap fuer Online/Offline-Slots (LE-kodiert, feste Länge 32 Byte).
    pub uptime_bitmap: [u8; 32],
}
impl PublicInputs for UptimePublicInputs {}

/// Public Inputs fuer Konsensbeweise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsensusPublicInputs {
    /// Round-ID im LE-Format.
    pub round_number: [u8; 8],
    /// Digest des vorgeschlagenen Blocks.
    pub proposal_digest: [u8; 32],
    /// Aggregiertes Abstimmungsergebnis.
    pub vote_aggregation: [u8; 32],
    /// Commitment auf das Validatoren-Set.
    pub validator_set_digest: [u8; 32],
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
    /// Commitment auf den Batch der eingehenden Beweise.
    pub batch_commitment: [u8; 32],
    /// Anzahl der aggregierten Beweise (LE-kodiert).
    pub proof_count: [u8; 8],
    /// Kumulierte Gewichtung der Aggregation.
    pub cumulative_weight: [u8; 16],
}
impl PublicInputs for AggregationPublicInputs {}
