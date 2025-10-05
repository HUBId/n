//! Fehlertypen der AIR-Spezifikation.
//!
//! Die Fehler sind deterministisch und dienen der klaren Signalisation von
//! Konsistenzverletzungen. Es gibt keine implizite Wiederherstellung.

/// Auflistung aller validierungsrelevanten Fehler.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AirErrorKind {
    /// Die `TraceInfo`-Breite stimmt nicht mit dem erwarteten Layout überein.
    TraceWidthMismatch,
    /// Die Spurlaenge (`steps`) weicht von der spezifizierten Anzahl ab.
    TraceLengthMismatch,
    /// Ein Boundary-Constraint referenziert einen ungueltigen Schrittindex.
    BoundaryIndexOutOfRange,
    /// Selektoren liefern Werte ausserhalb der dokumentierten Bereiche.
    SelectorValueOutOfRange,
    /// Lookup-Tabellen besitzen inkonsistente Kardinalitaet.
    LookupCardinalityMismatch,
    /// Permutationsargumente referenzieren nicht-existente Spalten.
    PermutationColumnMismatch,
    /// Der Grad einer Randbedingung ueberschreitet den spezifizierten Grenzwert.
    BoundaryDegreeExceeded,
    /// Der Grad einer Uebergangsbedingung ueberschreitet den Grenzwert.
    TransitionDegreeExceeded,
    /// Das Kompositionspolynom verletzt die vorgegebene Gradgrenze.
    CompositionDegreeExceeded,
    /// Der LDE-Faktor verletzt die Vorgaben des Kontextes.
    InvalidLdeFactor,
    /// Die Anzahl der OOD-Punkte unterschreitet den Mindestwert.
    OodPointCountInsufficient,
    /// Die deterministischen Parallelisierungsregeln wurden verletzt.
    ParallelPlanMismatch,
    /// Commitments oder Openings wurden in einer falschen Reihenfolge angegeben.
    CommitmentOrderingMismatch,
    /// Bilanz- oder Fee-Konsistenz der Transaktion verletzt (`sum_in - sum_out - fee != 0`).
    ErrTxBalance,
    /// Range-Bedingungen fuer Betraege, Fees oder Nonce wurden verletzt.
    ErrTxRange,
    /// Multiset/Premutationsargument fuer Inputs/Outputs inkonsistent.
    ErrTxPermMismatch,
    /// Selektoren verletzen die dokumentierten Phasenregeln.
    ErrTxSelector,
    /// Poseidon-/Commitment-Bindung der Transaktion inkonsistent.
    ErrTxHashBind,
    /// Boundary-Bedingungen (Fee/Nonce/Commit-Roots) verletzt.
    ErrTxBoundary,
    /// Nonce-Fortschreibung inkonsistent mit Public Inputs oder Selektoren.
    ErrTxNonce,
    /// Poseidon-Accumulator stimmt nicht mit gebundenem Digest ueberein.
    ErrTxAccumulator,
    /// Zustandsdelta passt nicht zum Diff-Commitment.
    ErrStateBoundary,
    ErrStateDeltaMismatch,
    /// Operationstag ausserhalb der erlaubten Menge.
    ErrStateOpTag,
    /// Key- oder Value-Format verletzt dokumentierte Range-Regeln.
    ErrStateFormat,
    /// Update-Operation fuehrt keinen Wertwechsel durch.
    ErrStateUpdateTrivial,
    /// Permutationsargument fuer State-Scan nicht erfuellt.
    ErrStatePermutation,
    /// Selektoren fuer Scan/Finalize verletzen Disjunktheit.
    ErrStateSelector,
    /// Recovery-Anker oder Keep/Drop-Konsistenz verletzt.
    ErrPruneBoundary,
    /// Partition der alten Menge in Keep/Drop verletzt.
    ErrPrunePartition,
    /// Key- oder Value-Formate im Pruning-Trace verletzt.
    ErrPruneFormat,
    /// Policy-Flags (keep/drop) inkonsistent.
    ErrPrunePolicy,
    /// Multiset-Argument fuer Keep/Drop verletzt.
    ErrPrunePermutation,
    /// Selektorverletzung im Pruning-Trace.
    ErrPruneSelector,
    /// Slot- oder Epoch-Kohärenz im Uptime-Trace verletzt.
    ErrUptimeSlot,
    /// Quorum- oder Committee-Bindung fehlerhaft.
    ErrConsensusQuorum,
    /// Policy-Bindung oder Attest-Slot-Verknuepfung inkonsistent.
    ErrIdentityPolicy,
    /// Phasenreihenfolge des VRF-Profils gebrochen (NTT/Mul/Commit).
    ErrVrfPhaseMismatch,
}
