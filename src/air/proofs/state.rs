//! State-Transition-AIR-Profil.
//!
//! Bindet deterministische Zustandsaenderungen an Pre-/Post-Roots sowie an ein
//! Diff-Commitment. Die Feinspezifikation unterscheidet zwei deterministische
//! Phasen (Scan/Finalize) und modelliert pro Trace-Zeile genau eine Operation
//! aus {INS, UPD, DEL}. Key- und Value-Werte werden feldkodiert; externe
//! BLAKE3-Pfade erscheinen nur im Transcript. Das Profil verlangt Tests fuer
//! reine Insert-/Delete-/Update-Serien (akzeptierend) sowie fuer fehlerhafte
//! Permutationen, Formate, Op-Tags, triviale Updates und Boundary-Verletzungen.

use super::ProofAirKind;
use crate::air::errors::AirErrorKind;
use crate::air::inputs::StatePublicInputs;
use crate::hash::Hasher;
use std::collections::BTreeMap;

const KEY_MAX: u64 = (1u64 << 48) - 1;
const VALUE_MAX: u64 = (1u64 << 48) - 1;

/// Kanonische Tags fuer State-Operationen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateOpTag {
    /// Fuegt einen neuen Key/Value Eintrag hinzu.
    Insert,
    /// Aktualisiert einen bestehenden Key.
    Update,
    /// Entfernt einen Key aus dem Zustand.
    Delete,
}

impl StateOpTag {
    fn from_raw(raw: u8) -> Result<Self, AirErrorKind> {
        match raw {
            0 => Ok(StateOpTag::Insert),
            1 => Ok(StateOpTag::Update),
            2 => Ok(StateOpTag::Delete),
            _ => Err(AirErrorKind::ErrStateOpTag),
        }
    }
}

/// Einzelne State-Operation im Trace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateOperation {
    /// Rohes Tag-Encoding (0=INS,1=UPD,2=DEL).
    pub tag: u8,
    /// Feldkodierter Key.
    pub key: u64,
    /// Alter Wert (fuer DEL/UPD relevant).
    pub value_old: u64,
    /// Neuer Wert (fuer INS/UPD relevant).
    pub value_new: u64,
}

/// Selektorfenster fuer State-Trace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StateSelectorWindows {
    /// Anzahl Scan-Zeilen.
    pub scan_rows: usize,
    /// Anzahl Finalize-Zeilen (>=1).
    pub finalize_rows: usize,
}

impl StateSelectorWindows {
    fn total_rows(self) -> usize {
        self.scan_rows + self.finalize_rows
    }
}

impl Default for StateSelectorWindows {
    fn default() -> Self {
        Self {
            scan_rows: 0,
            finalize_rows: 1,
        }
    }
}

/// Zeuge fuer das State-Profil.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateWitness {
    /// Vorszustand als Liste eindeutiger Key/Value-Paare.
    pub pre_state: Vec<(u64, u64)>,
    /// Nachzustand als Liste eindeutiger Key/Value-Paare.
    pub post_state: Vec<(u64, u64)>,
    /// Aufeinander folgende Operationen.
    pub operations: Vec<StateOperation>,
    /// Selektorfenster fuer Scan/Finalize.
    pub selectors: StateSelectorWindows,
}

fn hash_state(tag: &str, entries: &[(u64, u64)]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(tag.as_bytes());
    hasher.update(&(entries.len() as u32).to_le_bytes());
    for (key, value) in entries {
        hasher.update(&key.to_le_bytes());
        hasher.update(&value.to_le_bytes());
    }
    hasher.finalize().into_bytes()
}

fn hash_operations(ops: &[StateOperation]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(b"RPP-STATE-OPS");
    hasher.update(&(ops.len() as u32).to_le_bytes());
    for op in ops {
        hasher.update(&[op.tag]);
        hasher.update(&op.key.to_le_bytes());
        hasher.update(&op.value_old.to_le_bytes());
        hasher.update(&op.value_new.to_le_bytes());
    }
    hasher.finalize().into_bytes()
}

fn validate_key_value(key: u64, value: u64) -> Result<(), AirErrorKind> {
    if key > KEY_MAX || value > VALUE_MAX {
        Err(AirErrorKind::ErrStateFormat)
    } else {
        Ok(())
    }
}

fn sort_state(entries: &[(u64, u64)]) -> Vec<(u64, u64)> {
    let mut sorted = entries.to_vec();
    sorted.sort_unstable();
    sorted
}

/// AIR-Skelett fuer State-Beweise.
pub struct StateAirProfile;
impl StateAirProfile {
    /// Zugehoerige Beweisart.
    pub const KIND: ProofAirKind = ProofAirKind::State;
    /// Maximale Spurbreite fuer das Standardprofil (<=72 Spalten).
    pub const TRACE_WIDTH_MAX: usize = 72;
    /// Maximale Schrittanzahl (`2^22`).
    pub const TRACE_STEPS_MAX: usize = 1 << 22;
    /// Core-Register in kanonischer Reihenfolge.
    pub const CORE_REGISTERS: &'static [&'static str] = &[
        "A_pre", "A_post", "A_diff", "K", "V_old", "V_new", "Op_tag", "H_acc",
    ];
    /// Aux-Register fuer Zerlegungen und Lookup-Hilfen.
    pub const AUX_REGISTERS: &'static [&'static str] = &[
        "key_limb_lo",
        "key_limb_hi",
        "value_old_lo",
        "value_old_hi",
        "value_new_lo",
        "value_new_hi",
        "null_flag",
        "delta_helper",
        "grand_product_z",
    ];
    /// Selektoren (deterministisch aus Zeilenindex und Profil-Konstanten).
    pub const SELECTOR_REGISTERS: &'static [&'static str] = &["sigma_scan", "sigma_finalize"];
    /// Public-Input-Reihenfolge (LE-Layout).
    pub const PUBLIC_INPUTS: &'static [&'static str] =
        &["PreStateRoot[32]", "PostStateRoot[32]", "DiffDigest[32]"];
    /// Boundary-Regeln mit Bindung an Public Inputs.
    pub const BOUNDARY_CONSTRAINTS: &'static [&'static str] = &[
        "sigma_scan(0) * (A_pre - PreStateDigest) = 0",
        "sigma_finalize(T-1) * (A_post - PostStateDigest) = 0",
        "sigma_finalize(T-1) * (A_diff - DiffDigest) = 0",
        "grand_product_z(0) = 1",
        "grand_product_z(T-1) = 1",
    ];
    /// Transition-Phasen.
    pub const TRANSITION_PHASES: &'static [&'static str] = &[
        "phi_pre: absorbiert (K, V_old) in A_pre",
        "phi_diff: absorbiert (Op_tag, K, V_old, V_new) in A_diff",
        "phi_post: absorbiert (K, V_new) in A_post",
        "grand_product: koppelt A_pre und A_diff gegen A_post via β,γ,δ",
        "sigma_finalize: haelt A_pre/A_post/A_diff/K/V_* konstant",
    ];
    /// Lookup- und Permutationsargumente.
    pub const LOOKUPS: &'static [&'static str] = &[
        "op_tag_in_{INS,UPD,DEL}",
        "range_key_format",
        "range_value_format",
        "null_representation",
        "update_non_trivial",
        "grand_product_pre_plus_diff_equals_post",
    ];
    /// OOD-Oeffnungen.
    pub const OOD_OPENINGS: &'static [&'static str] = &[
        "A_pre",
        "A_post",
        "A_diff",
        "grand_product_z",
        "composition_polynomial",
    ];
    /// Grad-Hinweise.
    pub const DEGREE_HINT: &'static str =
        "Linearitaet Grad <=2; Grand-Product & Permutation Grad < LDE-Bound";
    /// Fehlermodi dieses Profils.
    pub const FAILURE_MODES: &'static [&'static str] = &[
        "ErrStateBoundary",
        "ErrStateOpTag",
        "ErrStateFormat",
        "ErrStateUpdateTrivial",
        "ErrStatePermutation",
        "ErrStateSelector",
    ];
    /// Selektorformeln.
    pub const SELECTOR_FORMULAS: &'static [&'static str] = &[
        "sigma_scan(i) * sigma_finalize(i) = 0",
        "sigma_scan(i) + sigma_finalize(i) = 1",
        "sigma_scan(0) = 1 und sigma_finalize(T-1) = 1",
    ];

    /// Fuehrt die dokumentierten Konsistenzpruefungen fuer einen State-Zeugen aus.
    pub fn evaluate_trace(
        witness: &StateWitness,
        public_inputs: &StatePublicInputs,
    ) -> Result<(), AirErrorKind> {
        if witness.selectors.finalize_rows == 0 {
            return Err(AirErrorKind::ErrStateSelector);
        }
        if witness.selectors.scan_rows != witness.operations.len() {
            return Err(AirErrorKind::ErrStateSelector);
        }
        if witness.selectors.total_rows() != witness.operations.len() + 1 {
            return Err(AirErrorKind::ErrStateSelector);
        }

        for &(key, value) in &witness.pre_state {
            validate_key_value(key, value)?;
        }
        for &(key, value) in &witness.post_state {
            validate_key_value(key, value)?;
        }

        let mut state: BTreeMap<u64, u64> = witness.pre_state.iter().cloned().collect();

        for op in &witness.operations {
            let tag = StateOpTag::from_raw(op.tag)?;
            validate_key_value(op.key, op.value_old)?;
            validate_key_value(op.key, op.value_new)?;
            match tag {
                StateOpTag::Insert => {
                    if op.value_new == 0 || op.value_old != 0 {
                        return Err(AirErrorKind::ErrStateFormat);
                    }
                    if state.contains_key(&op.key) {
                        return Err(AirErrorKind::ErrStatePermutation);
                    }
                    state.insert(op.key, op.value_new);
                }
                StateOpTag::Update => {
                    if op.value_new == op.value_old {
                        return Err(AirErrorKind::ErrStateUpdateTrivial);
                    }
                    let entry = state
                        .get_mut(&op.key)
                        .ok_or(AirErrorKind::ErrStatePermutation)?;
                    if *entry != op.value_old {
                        return Err(AirErrorKind::ErrStatePermutation);
                    }
                    *entry = op.value_new;
                }
                StateOpTag::Delete => {
                    if op.value_old == 0 || op.value_new != 0 {
                        return Err(AirErrorKind::ErrStateFormat);
                    }
                    let entry = state
                        .remove(&op.key)
                        .ok_or(AirErrorKind::ErrStatePermutation)?;
                    if entry != op.value_old {
                        return Err(AirErrorKind::ErrStatePermutation);
                    }
                }
            }
        }

        let mut final_state: Vec<(u64, u64)> = state.into_iter().collect();
        final_state.sort_unstable();
        if final_state != sort_state(&witness.post_state) {
            return Err(AirErrorKind::ErrStatePermutation);
        }

        if hash_state("STATE:pre", &witness.pre_state) != public_inputs.pre_state_root {
            return Err(AirErrorKind::ErrStateBoundary);
        }
        if hash_state("STATE:post", &witness.post_state) != public_inputs.post_state_root {
            return Err(AirErrorKind::ErrStateBoundary);
        }
        if hash_operations(&witness.operations) != public_inputs.diff_digest {
            return Err(AirErrorKind::ErrStateBoundary);
        }

        Ok(())
    }

    /// Leitet deterministische Public Inputs aus dem Zeugen ab.
    pub fn derive_public_inputs(witness: &StateWitness) -> StatePublicInputs {
        StatePublicInputs {
            pre_state_root: hash_state("STATE:pre", &witness.pre_state),
            post_state_root: hash_state("STATE:post", &witness.post_state),
            diff_digest: hash_operations(&witness.operations),
        }
    }
}
