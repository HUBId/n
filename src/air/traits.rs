//! Traits und Vertragsstrukturen der AIR-Schicht.
//!
//! Die hier definierten Traits beschreiben die Schnittstelle zwischen der
//! Spezifikation und den spaeteren Implementierungen. Es werden keine
//! Evaluierungen vorgenommen; alle Rueckgaben sind deskriptiv.

use super::context::AirContext;
use super::descriptors::{
    BoundaryConstraintDescriptor, CompositionPolynomialDescriptor, LookupArgumentDescriptor,
    PermutationArgumentDescriptor,
};
use super::ids::AirSpecId;
use super::inputs::PublicInputs;
use super::selectors::SelectorSet;

/// Gruppentyp eines Registers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceGroup {
    /// Kernregister mit arithmetischen Zuständen.
    Core,
    /// Hilfsregister fuer Carry-Bits, Range-Beweise etc.
    Auxiliary,
}

/// Reihenfolgeeintrag fuer eine Uebergangsbedingung.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitionConstraintOrder {
    /// Name der Constraint-Klasse.
    pub name: &'static str,
    /// Gruppenzugehörigkeit des Constraint-Vektors.
    pub group: TraceGroup,
    /// Index innerhalb der kanonischen Liste.
    pub index: usize,
    /// Optionaler Selektor, der die Bedingung aktiviert.
    pub selector_column: Option<usize>,
}

/// Beschreibung, welche Constraints bei der Auswertung einer Zeile relevant sind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitionEvaluationDescriptor {
    /// Zeilenindex innerhalb der dichten Spur.
    pub row_index: usize,
    /// Reihenfolge der aktiven Constraints.
    pub active_constraints: Vec<TransitionConstraintOrder>,
}

/// Beschreibung der Randbedingungen fuer erste und letzte Zeile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundaryEvaluationDescriptor {
    /// Constraints, die auf der ersten Zeile gelten.
    pub first_row: Vec<BoundaryConstraintDescriptor>,
    /// Constraints, die auf der letzten Zeile gelten.
    pub last_row: Vec<BoundaryConstraintDescriptor>,
}

/// Beschreibung einer Lookup-Tabelle innerhalb der AIR.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LookupTableAccess {
    /// Name der Tabelle.
    pub name: &'static str,
    /// Digest der Tabellenparameter.
    pub table_digest: super::ids::ParameterDigest,
    /// Lookup-Argument, das gegen diese Tabelle geprüft wird.
    pub argument: LookupArgumentDescriptor,
}

/// Beschreibung der Zuordnung von Transcript-Challenges zu Constraint-Gruppen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompositionChallengeSet {
    /// Indizes der Boundary-Alphas entsprechend `boundary_order`.
    pub boundary_alphas: Vec<usize>,
    /// Indizes der Transition-Alphas entsprechend `transition_order`.
    pub transition_alphas: Vec<usize>,
    /// Zufallswerte fuer Randomizer-Polynome nach Registergruppe.
    pub randomizer_alphas: Vec<usize>,
}

/// Trait, das jede konkrete AIR-Instanz implementieren muss.
pub trait AirSpec {
    /// Zugehoeriger Public-Input-Typ.
    type PublicInputs: PublicInputs;

    /// Eindeutige Kennung der Spezifikation.
    fn id(&self) -> AirSpecId;
    /// Kontextinformationen fuer Gradgrenzen, Spur und Domains.
    fn context(&self) -> &AirContext;
    /// Typisierte Sicht auf die Public Inputs.
    fn public_inputs(&self) -> &Self::PublicInputs;
    /// Beschreibung der Uebergangsevaluierung fuer eine Zeile.
    fn evaluate_transition(&self, row: usize) -> TransitionEvaluationDescriptor;
    /// Beschreibung der Boundary-Constraints fuer erste/letzte Zeile.
    fn evaluate_boundary(&self) -> BoundaryEvaluationDescriptor;
    /// Optionale Lookup-Tabellen (Range/Opcode/etc.).
    fn lookup_tables(&self) -> &[LookupTableAccess];
    /// Selektorwerte in kanonischer Reihenfolge.
    fn selectors(&self) -> &SelectorSet;
    /// Ordnung fuer das Kompositionspolynom.
    fn composition_descriptor(&self) -> &CompositionPolynomialDescriptor;
    /// Zuordnung der Transcript-Challenges.
    fn composition_challenges(&self) -> CompositionChallengeSet;
    /// Beschreibung der verwendeten Permutationsargumente.
    fn permutation_arguments(&self) -> &[PermutationArgumentDescriptor];
}
