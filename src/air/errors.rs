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
}
