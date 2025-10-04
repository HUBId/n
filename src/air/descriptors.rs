//! Deskriptoren fuer Rand-, Uebergangs- und Lookup-Argumente.
//!
//! Alle Strukturen dienen ausschliesslich der Beschreibung der Constraint- und
//! Tabellenlandschaft einer AIR-Instanz. Es findet keinerlei algebraische
//! Auswertung statt; Implementierungen muessen die vorgegebenen Felder
//! deterministisch nutzen.

use super::traits::TransitionConstraintOrder;

/// Fest definierte Bindung eines Registers an einen Public Input oder eine
/// affine Kombination im Start-/Endschritt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundaryConstraintDescriptor {
    /// Schrittindex innerhalb der dichten Spur (0-basiert).
    pub step: usize,
    /// Betroffene Registerspalte im Trace.
    pub column: usize,
    /// Beschreibung der Bindung (Public-Input-Index, affine Kombination oder
    /// konstante Vorgabe im LE-Format).
    pub binding: BoundaryBinding,
}

/// Erlaubte Formen einer Boundary-Bindung.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BoundaryBinding {
    /// Bindung an einen Public-Input-Eintrag (Index in der Phase-2-Serialisierung).
    PublicInput { index: usize },
    /// Fest vorgegebene Konstante in Little-Endian Darstellung.
    ConstantLe { value: Vec<u8> },
    /// Affine Kombination mehrerer Spalten derselben Zeile.
    AffineCombination {
        /// Spaltenindices der beteiligten Register.
        columns: Vec<usize>,
        /// Koeffizienten im LE-Format.
        coefficients_le: Vec<Vec<u8>>,
        /// Konstanter Offset im LE-Format.
        offset_le: Vec<u8>,
    },
}

/// Beschreibt die kanonische Ordnung der Constraint-Gruppen bei der
/// Kompositionsbildung.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompositionPolynomialDescriptor {
    /// Reihenfolge, in der Boundary-Constraint-Indizes mit den Alpha-Werten
    /// verknüpft werden.
    pub boundary_order: Vec<usize>,
    /// Reihenfolge, in der Uebergangsklassen in das Kompositionspolynom
    /// einfliessen.
    pub transition_order: Vec<TransitionConstraintOrder>,
}

/// Lookup-Argument-Beschreibung fuer Multiset-Gleichheiten.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LookupArgumentDescriptor {
    /// Kanonischer Name des Arguments (Teil der AirSpecID).
    pub name: &'static str,
    /// Spaltenindices der Anfrage-Multimenge A in fester Reihenfolge.
    pub requested_columns: Vec<usize>,
    /// Spaltenindices der Tabellenspalten T in fester Reihenfolge.
    pub table_columns: Vec<usize>,
    /// Erwartete Kardinalitaet der Multimengen.
    pub multiset_cardinality: usize,
}

/// Permutations-Argument zur Absicherung von Summen- und Konsistenzpruefungen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermutationArgumentDescriptor {
    /// Kanonischer Name des Arguments.
    pub name: &'static str,
    /// Reihenfolge der Quellspalten.
    pub source_columns: Vec<usize>,
    /// Reihenfolge der Zielspalten.
    pub target_columns: Vec<usize>,
}
