//! AIR-Profile fuer alle Beweisarten.
//!
//! Jede Struktur in diesem Modul dokumentiert die Registeraufteilung, die
//! verwendeten Boundary-Anker, Transition-Phasen, Lookup-Argumente sowie die
//! Ordnung der OOD-Eroeffnungen. Die Werte sind so gewaehlt, dass die Beweise
//! moeglichst schmal und kurz bleiben.

use super::traits::TraceGroup;

/// Auflistung aller unterstuetzten AIR-Arten.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofAirKind {
    Identity,
    Transaction,
    Uptime,
    Consensus,
    State,
    Pruning,
    Aggregation,
}

/// Profileinstellungen fuer Identity-Beweise.
pub struct IdentityAirProfile;
impl IdentityAirProfile {
    /// Zugehoerige Beweisart.
    pub const KIND: ProofAirKind = ProofAirKind::Identity;
    /// Anzahl der Schritte (dicht, Schrittweite 1).
    pub const TRACE_STEPS: usize = 4096;
    /// Core-Register in kanonischer Reihenfolge.
    pub const CORE_REGISTERS: &'static [&'static str] = &[
        "id_state_lo",
        "id_state_hi",
        "attr_accumulator",
        "challenge_state",
        "public_key_x",
        "public_key_y",
    ];
    /// Aux-Register fuer Range-Checks und Tabellenbindungen.
    pub const AUX_REGISTERS: &'static [&'static str] =
        &["range_decomp_lo", "range_decomp_hi", "carry_flag"];
    /// Selektoren fuer Phasensteuerung.
    pub const SELECTOR_REGISTERS: &'static [&'static str] = &["is_first", "is_last", "round_mod_4"];
    /// Boundary-Anker (Start/Ende) in Bindungsreihenfolge.
    pub const BOUNDARY_ANCHORS: &'static [&'static str] = &[
        "identity_commitment_binding",
        "revocation_counter_start",
        "revocation_counter_end",
    ];
    /// Reihenfolge der Transition-Phasen.
    pub const TRANSITION_PHASES: &'static [&'static str] =
        &["poseidon_absorb", "poseidon_sbox", "poseidon_mix"];
    /// Lookup-Argumente (Range-Tabellen fuer Attribute).
    pub const LOOKUPS: &'static [&'static str] = &["attribute_range"];
    /// Reihenfolge der gebundenen Public Inputs.
    pub const PUBLIC_INPUT_BINDING: &'static [&'static str] = &[
        "identity_commitment",
        "revocation_counter",
        "validity_window",
    ];
    /// OOD-Oeffnungen (Register + Komposition).
    pub const OOD_OPENINGS: &'static [&'static str] =
        &["core_registers", "aux_registers", "composition_polynomial"];
}

/// Profileinstellungen fuer Transaktionsbeweise.
pub struct TransactionAirProfile;
impl TransactionAirProfile {
    pub const KIND: ProofAirKind = ProofAirKind::Transaction;
    pub const TRACE_STEPS: usize = 8192;
    pub const CORE_REGISTERS: &'static [&'static str] = &[
        "hash_state_0",
        "hash_state_1",
        "hash_state_2",
        "hash_state_3",
        "balance_acc",
        "input_sum",
        "output_sum",
        "fee_acc",
        "nonce_acc",
        "io_flag",
        "merkle_branch_lo",
        "merkle_branch_hi",
    ];
    pub const AUX_REGISTERS: &'static [&'static str] = &[
        "range_decomp_16",
        "range_decomp_32",
        "carry_balance",
        "opcode_table_bind",
        "permutation_running",
        "lookup_running",
        "copy_flag",
        "sponge_randomizer",
    ];
    pub const SELECTOR_REGISTERS: &'static [&'static str] =
        &["is_first", "is_last", "absorb_window", "round_mod_8"];
    pub const BOUNDARY_ANCHORS: &'static [&'static str] = &[
        "tx_id_anchor",
        "input_commit_root_anchor",
        "output_commit_root_anchor",
        "fee_anchor",
        "nonce_anchor",
    ];
    pub const TRANSITION_PHASES: &'static [&'static str] = &[
        "hash_absorb",
        "hash_sbox",
        "hash_mix",
        "balance_enforcement",
        "permutation_link",
    ];
    pub const LOOKUPS: &'static [&'static str] = &["range_64", "allowed_opcodes", "utxo_shape"];
    pub const PUBLIC_INPUT_BINDING: &'static [&'static str] = &[
        "tx_id",
        "input_commit_root",
        "output_commit_root",
        "fee",
        "nonce",
    ];
    pub const OOD_OPENINGS: &'static [&'static str] = &[
        "core_registers",
        "aux_registers",
        "permutation_argument",
        "composition_polynomial",
    ];
}

/// Profileinstellungen fuer Uptime-Beweise.
pub struct UptimeAirProfile;
impl UptimeAirProfile {
    pub const KIND: ProofAirKind = ProofAirKind::Uptime;
    pub const TRACE_STEPS: usize = 2048;
    pub const CORE_REGISTERS: &'static [&'static str] = &[
        "epoch_counter",
        "slot_index",
        "uptime_accumulator",
        "hash_state",
    ];
    pub const AUX_REGISTERS: &'static [&'static str] = &["bitmap_split_lo", "bitmap_split_hi"];
    pub const SELECTOR_REGISTERS: &'static [&'static str] = &["is_first", "is_last", "round_mod_2"];
    pub const BOUNDARY_ANCHORS: &'static [&'static str] =
        &["epoch_binding", "validator_id_binding"];
    pub const TRANSITION_PHASES: &'static [&'static str] = &["slot_absorb", "slot_update"];
    pub const LOOKUPS: &'static [&'static str] = &["bitmap_range"];
    pub const PUBLIC_INPUT_BINDING: &'static [&'static str] =
        &["validator_id", "epoch", "uptime_bitmap"];
    pub const OOD_OPENINGS: &'static [&'static str] =
        &["core_registers", "aux_registers", "composition_polynomial"];
}

/// Profileinstellungen fuer Konsensbeweise.
pub struct ConsensusAirProfile;
impl ConsensusAirProfile {
    pub const KIND: ProofAirKind = ProofAirKind::Consensus;
    pub const TRACE_STEPS: usize = 4096;
    pub const CORE_REGISTERS: &'static [&'static str] = &[
        "proposal_state",
        "vote_state",
        "threshold_acc",
        "signature_acc",
        "round_hash_lo",
        "round_hash_hi",
        "validator_pointer",
        "io_flag",
    ];
    pub const AUX_REGISTERS: &'static [&'static str] = &[
        "range_threshold",
        "lookup_vote",
        "carry_signature",
        "permutation_validator",
    ];
    pub const SELECTOR_REGISTERS: &'static [&'static str] =
        &["is_first", "is_last", "absorb_window", "round_mod_4"];
    pub const BOUNDARY_ANCHORS: &'static [&'static str] = &[
        "round_number_anchor",
        "proposal_digest_anchor",
        "vote_aggregation_anchor",
        "validator_set_anchor",
    ];
    pub const TRANSITION_PHASES: &'static [&'static str] = &[
        "proposal_absorb",
        "vote_absorb",
        "aggregation_mix",
        "validator_permutation",
    ];
    pub const LOOKUPS: &'static [&'static str] = &["validator_table", "signature_range"];
    pub const PUBLIC_INPUT_BINDING: &'static [&'static str] = &[
        "round_number",
        "proposal_digest",
        "vote_aggregation",
        "validator_set_digest",
    ];
    pub const OOD_OPENINGS: &'static [&'static str] = &[
        "core_registers",
        "aux_registers",
        "permutation_argument",
        "composition_polynomial",
    ];
}

/// Profileinstellungen fuer State-Uebergangsbeweise.
pub struct StateAirProfile;
impl StateAirProfile {
    pub const KIND: ProofAirKind = ProofAirKind::State;
    pub const TRACE_STEPS: usize = 4096;
    pub const CORE_REGISTERS: &'static [&'static str] = &[
        "state_hash_lo",
        "state_hash_hi",
        "transition_acc",
        "diff_acc",
        "merkle_path_lo",
        "merkle_path_hi",
        "io_flag",
        "clock",
        "challenge_acc",
        "update_counter",
    ];
    pub const AUX_REGISTERS: &'static [&'static str] = &[
        "range_diff",
        "carry_diff",
        "lookup_opcode",
        "lookup_value",
        "permutation_balance",
    ];
    pub const SELECTOR_REGISTERS: &'static [&'static str] = &["is_first", "is_last", "round_mod_4"];
    pub const BOUNDARY_ANCHORS: &'static [&'static str] = &[
        "pre_state_root_anchor",
        "post_state_root_anchor",
        "diff_digest_anchor",
    ];
    pub const TRANSITION_PHASES: &'static [&'static str] =
        &["state_absorb", "state_apply", "state_commit"];
    pub const LOOKUPS: &'static [&'static str] = &["state_opcode", "value_range"];
    pub const PUBLIC_INPUT_BINDING: &'static [&'static str] =
        &["pre_state_root", "post_state_root", "diff_digest"];
    pub const OOD_OPENINGS: &'static [&'static str] =
        &["core_registers", "aux_registers", "composition_polynomial"];
}

/// Profileinstellungen fuer Pruning-Beweise.
pub struct PruningAirProfile;
impl PruningAirProfile {
    pub const KIND: ProofAirKind = ProofAirKind::Pruning;
    pub const TRACE_STEPS: usize = 2048;
    pub const CORE_REGISTERS: &'static [&'static str] = &[
        "prune_state",
        "recovery_state",
        "anchor_forward",
        "hash_lo",
        "hash_hi",
        "io_flag",
    ];
    pub const AUX_REGISTERS: &'static [&'static str] = &[
        "range_anchor",
        "lookup_prune",
        "carry_flag",
        "permutation_anchor",
    ];
    pub const SELECTOR_REGISTERS: &'static [&'static str] = &["is_first", "is_last"];
    pub const BOUNDARY_ANCHORS: &'static [&'static str] = &[
        "old_prune_digest_anchor",
        "new_prune_digest_anchor",
        "recovery_anchor_binding",
    ];
    pub const TRANSITION_PHASES: &'static [&'static str] = &["prune_absorb", "anchor_update"];
    pub const LOOKUPS: &'static [&'static str] = &["prune_table"];
    pub const PUBLIC_INPUT_BINDING: &'static [&'static str] =
        &["old_prune_digest", "new_prune_digest", "recovery_anchor"];
    pub const OOD_OPENINGS: &'static [&'static str] =
        &["core_registers", "aux_registers", "composition_polynomial"];
}

/// Profileinstellungen fuer Aggregationsbeweise.
pub struct AggregationAirProfile;
impl AggregationAirProfile {
    pub const KIND: ProofAirKind = ProofAirKind::Aggregation;
    pub const TRACE_STEPS: usize = 1024;
    pub const CORE_REGISTERS: &'static [&'static str] = &[
        "aggregate_commit_lo",
        "aggregate_commit_hi",
        "weight_acc",
        "proof_counter",
        "fri_digest_lo",
        "fri_digest_hi",
        "io_flag",
        "challenge_hash",
    ];
    pub const AUX_REGISTERS: &'static [&'static str] = &[
        "range_weight",
        "carry_weight",
        "lookup_proof_id",
        "lookup_alpha",
        "permutation_commit",
        "randomizer_flag",
    ];
    pub const SELECTOR_REGISTERS: &'static [&'static str] =
        &["is_first", "is_last", "absorb_window", "round_mod_4"];
    pub const BOUNDARY_ANCHORS: &'static [&'static str] = &[
        "batch_commitment_anchor",
        "proof_count_anchor",
        "cumulative_weight_anchor",
    ];
    pub const TRANSITION_PHASES: &'static [&'static str] =
        &["batch_absorb", "batch_mix", "weight_enforce"];
    pub const LOOKUPS: &'static [&'static str] = &["proof_id_table", "alpha_table"];
    pub const PUBLIC_INPUT_BINDING: &'static [&'static str] =
        &["batch_commitment", "proof_count", "cumulative_weight"];
    pub const OOD_OPENINGS: &'static [&'static str] = &[
        "core_registers",
        "aux_registers",
        "permutation_argument",
        "composition_polynomial",
    ];
}

/// Liefert die Reihenfolge, in der Registergruppen fuer Commitments serialisiert werden.
pub const COMMITMENT_ORDER: &[TraceGroup] = &[TraceGroup::Core, TraceGroup::Auxiliary];
