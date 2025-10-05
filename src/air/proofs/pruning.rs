//! Pruning-AIR-Profil.
//!
//! Modelliert deterministisches Entfernen oder Verdichten von Daten. Die
//! Wiederherstellbarkeit wird ueber einen extern gebundenen Anchor garantiert;
//! Merkle-Pfade verbleiben ausserhalb der AIR (Transcript-Bindung).

use super::ProofAirKind;
use crate::air::errors::AirErrorKind;
use crate::air::inputs::PruningPublicInputs;
use crate::hash::Hasher;

const KEY_MAX: u64 = (1u64 << 48) - 1;
const VALUE_MAX: u64 = (1u64 << 48) - 1;

/// Ein einzelner Key/Value-Eintrag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct PruningEntry {
    /// Feldkodierter Key.
    pub key: u64,
    /// Feldkodierter Wert.
    pub value: u64,
}

/// Operation in der Pruning-Spur.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PruningOperation {
    /// Der betrachtete Eintrag.
    pub entry: PruningEntry,
    /// Flag, ob der Eintrag behalten wird.
    pub keep: bool,
    /// Flag, ob der Eintrag entfernt wird.
    pub drop: bool,
}

/// Selektorfenster fuer das Pruning-Profil.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PruningSelectorWindows {
    /// Zeilen in der Filter-Phase.
    pub filter_rows: usize,
    /// Zeilen in der Finalize-Phase (>=1).
    pub finalize_rows: usize,
}

impl PruningSelectorWindows {
    fn total_rows(self) -> usize {
        self.filter_rows + self.finalize_rows
    }
}

impl Default for PruningSelectorWindows {
    fn default() -> Self {
        Self {
            filter_rows: 0,
            finalize_rows: 1,
        }
    }
}

/// Zeuge fuer das Pruning-Profil.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PruningWitness {
    /// Urspruengliche Menge an Eintraegen.
    pub old_entries: Vec<PruningEntry>,
    /// Resultierende Menge nach dem Pruning.
    pub new_entries: Vec<PruningEntry>,
    /// Partition in Keep/Drop.
    pub operations: Vec<PruningOperation>,
    /// Selektorfenster fuer Filter/Finalize.
    pub selectors: PruningSelectorWindows,
}

fn hash_entries(tag: &str, entries: &[PruningEntry]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(tag.as_bytes());
    hasher.update(&(entries.len() as u32).to_le_bytes());
    for entry in entries {
        hasher.update(&entry.key.to_le_bytes());
        hasher.update(&entry.value.to_le_bytes());
    }
    hasher.finalize().into_bytes()
}

fn validate_entry(entry: PruningEntry) -> Result<(), AirErrorKind> {
    if entry.key > KEY_MAX || entry.value > VALUE_MAX {
        Err(AirErrorKind::ErrPruneFormat)
    } else {
        Ok(())
    }
}

fn sorted(entries: &[PruningEntry]) -> Vec<PruningEntry> {
    let mut out = entries.to_vec();
    out.sort_unstable();
    out
}

/// AIR-Skelett fuer Pruning-Beweise.
pub struct PruningAirProfile;
impl PruningAirProfile {
    /// Zugehoerige Beweisart.
    pub const KIND: ProofAirKind = ProofAirKind::Pruning;
    /// Maximale Spurbreite (<=48).
    pub const TRACE_WIDTH_MAX: usize = 48;
    /// Maximale Schrittanzahl (`2^21`).
    pub const TRACE_STEPS_MAX: usize = 1 << 21;
    /// Core-Register.
    pub const CORE_REGISTERS: &'static [&'static str] = &[
        "A_old",
        "A_new",
        "A_anchor",
        "E_key",
        "E_val",
        "keep_flag",
        "drop_flag",
    ];
    /// Aux-Register fuer Zerlegungen und Grand-Product.
    pub const AUX_REGISTERS: &'static [&'static str] = &[
        "key_limb_lo",
        "key_limb_hi",
        "value_limb_lo",
        "value_limb_hi",
        "policy_helper",
        "grand_product_z",
    ];
    /// Selektoren.
    pub const SELECTOR_REGISTERS: &'static [&'static str] = &[
        "sigma_first",
        "sigma_last",
        "sigma_filter",
        "sigma_finalize",
    ];
    /// Public Inputs (LE).
    pub const PUBLIC_INPUTS: &'static [&'static str] = &[
        "OldPruneDigest[32]",
        "NewPruneDigest[32]",
        "RecoveryAnchor[32]",
    ];
    /// Boundary-Regeln.
    pub const BOUNDARY_CONSTRAINTS: &'static [&'static str] = &[
        "sigma_first * (A_old - OldPruneDigest) = 0",
        "sigma_first * (grand_product_z - 1) = 0",
        "sigma_last * (A_old - OldPruneDigest) = 0",
        "sigma_last * (A_new - NewPruneDigest) = 0",
        "sigma_last * (A_anchor - RecoveryAnchor) = 0",
        "sigma_last * (grand_product_z - 1) = 0",
    ];
    /// Transition-Phasen.
    pub const TRANSITION_PHASES: &'static [&'static str] = &[
        "sigma_filter: Partition (keep/drop) und Akkumulator-Updates",
        "grand_product: Multiset-Bindung old ↔ keep ∪ drop",
        "sigma_finalize: Konstanz der Akkumulatoren und des Grand-Products",
    ];
    /// Lookup-/Permutation-Argumente.
    pub const LOOKUPS: &'static [&'static str] = &[
        "range_key_format",
        "range_value_format",
        "policy_to_flags_deterministic",
        "permutation_old_equals_keep_union_drop",
    ];
    /// OOD-Oeffnungen.
    pub const OOD_OPENINGS: &'static [&'static str] = &[
        "A_old",
        "A_new",
        "A_anchor",
        "grand_product_z",
        "composition_polynomial",
    ];
    /// Grad-Hinweis.
    pub const DEGREE_HINT: &'static str =
        "Lineare Filter-Regeln Grad <=2; Permutation Grad < LDE-Bound";
    /// Fehlermodi.
    pub const FAILURE_MODES: &'static [&'static str] = &[
        "ErrPruneBoundary",
        "ErrPrunePartition",
        "ErrPruneFormat",
        "ErrPrunePolicy",
        "ErrPrunePermutation",
        "ErrPruneSelector",
    ];
    /// Selektorformeln.
    pub const SELECTOR_FORMULAS: &'static [&'static str] = &[
        "sigma_first(i) = 1 ⇔ i = 0",
        "sigma_last(i) = 1 ⇔ i = T-1",
        "sigma_filter(i) + sigma_finalize(i) = 1",
        "sigma_filter(i) * sigma_finalize(i) = 0",
    ];

    /// Prueft die dokumentierten Pruning-Constraints fuer einen Zeugen.
    pub fn evaluate_trace(
        witness: &PruningWitness,
        public_inputs: &PruningPublicInputs,
    ) -> Result<(), AirErrorKind> {
        if witness.selectors.finalize_rows == 0 {
            return Err(AirErrorKind::ErrPruneSelector);
        }
        if witness.selectors.filter_rows != witness.operations.len() {
            return Err(AirErrorKind::ErrPruneSelector);
        }
        if witness.selectors.total_rows() != witness.operations.len() + 1 {
            return Err(AirErrorKind::ErrPruneSelector);
        }

        if witness.operations.len() != witness.old_entries.len() {
            return Err(AirErrorKind::ErrPrunePartition);
        }

        for entry in &witness.old_entries {
            validate_entry(*entry)?;
        }
        for entry in &witness.new_entries {
            validate_entry(*entry)?;
        }

        let mut keep_entries = Vec::new();
        let mut drop_entries = Vec::new();

        for (op, original) in witness.operations.iter().zip(&witness.old_entries) {
            if op.entry != *original {
                return Err(AirErrorKind::ErrPrunePartition);
            }
            if op.keep == op.drop {
                return Err(AirErrorKind::ErrPrunePolicy);
            }
            if op.keep {
                keep_entries.push(op.entry);
            } else {
                drop_entries.push(op.entry);
            }
        }

        if sorted(&keep_entries) != sorted(&witness.new_entries) {
            return Err(AirErrorKind::ErrPrunePermutation);
        }

        if hash_entries("PRUNE:old", &witness.old_entries) != public_inputs.old_prune_digest {
            return Err(AirErrorKind::ErrPruneBoundary);
        }
        if hash_entries("PRUNE:new", &witness.new_entries) != public_inputs.new_prune_digest {
            return Err(AirErrorKind::ErrPruneBoundary);
        }
        if hash_entries("PRUNE:drop", &drop_entries) != public_inputs.recovery_anchor {
            return Err(AirErrorKind::ErrPruneBoundary);
        }

        Ok(())
    }

    /// Leitet deterministische Public Inputs aus dem Zeugen ab.
    pub fn derive_public_inputs(witness: &PruningWitness) -> PruningPublicInputs {
        let drop_entries: Vec<PruningEntry> = witness
            .operations
            .iter()
            .filter(|op| op.drop)
            .map(|op| op.entry)
            .collect();
        PruningPublicInputs {
            old_prune_digest: hash_entries("PRUNE:old", &witness.old_entries),
            new_prune_digest: hash_entries("PRUNE:new", &witness.new_entries),
            recovery_anchor: hash_entries("PRUNE:drop", &drop_entries),
        }
    }
}
