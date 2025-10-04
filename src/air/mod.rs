//! # Algebraic Intermediate Representation (AIR)
//!
//! Dieses Modul beschreibt die vollstaendige Spezifikation fuer die
//! ausfuehrungsspuren (`Execution Traces`) und die zugehoerigen
//! algebraischen Nebenbedingungen innerhalb von `rpp-stark`.
//!
//! Die Definitionen in diesem Modul enthalten **ausschliesslich**
//! Schnittstellen, Typcontainer, feste IDs und umfangreiche Dokumentation.
//! Implementierungslogik gehoert in die Ebenen oberhalb der Spezifikation und
//! ist bewusst ausgeschlossen, damit die AIR stabil, auditierbar und
//! deterministisch bleibt. Alle Beschreibungen folgen dem LE-Endian Layout,
//! nutzen ausschliesslich stable Rust und verzichten auf externe Crates.
//!
//! ## Uebersicht
//!
//! * [`context`] stellt Trace- und Kontextinformationen bereit.
//! * [`descriptors`] fasst Metadaten zu Rand-, Uebergangs- und Lookup-Regeln
//!   zusammen.
//! * [`errors`] benennt alle deterministischen Fehlertypen.
//! * [`ids`] deklariert stabile Kennungen fuer AIR-Spezifikationen und Plansaetze.
//! * [`inputs`] enthaelt die Public-Input-Container fuer jede Beweisart.
//! * [`parallel`] dokumentiert die deterministische Parallelisierungsstrategie.
//! * [`proofs`] beschreibt die einzelnen AIR-Profile (Registerrollen,
//!   Constraints, Selektoren) fuer alle Beweisarten.
//! * [`selectors`] listet alle erlaubten Selektoren und deren Formeln.
//! * [`traits`] definiert die zentralen Traits (`AirSpec`, `AirContext`,
//!   `PublicInputs`-Vertraege) und damit die Schnittstelle zur STARK-Maschine.
//!
//! ## Determinismus
//!
//! Alle Datenstrukturen fixieren eine kanonische Ordnung fuer Register,
//! Constraints, Lookup-Argumente und OOD-Evaluierungen. Die Dokumentation
//! beschreibt explizit, wie diese Ordnungen zu interpretieren sind. Jede
//! Implementierung **muss** diese Ordnung exakt einhalten, damit identische
//! Eingaben zu bit-identischen Beweisergebnissen fuehren.
//!
//! ## Dichte Spuren
//!
//! Die Trace-Layouts setzen auf ein dichtes Modell (Schrittweite = 1). Alle
//! Phasenwechsel erfolgen ueber Selektoren; auszulassende Zeilen sind nicht
//! gestattet. Dieses Vorgehen vereinfacht LDE, DEEP und FRI und ist fuer die
//! Sicherheitsgarantien zwingend erforderlich.

pub mod context;
pub mod descriptors;
pub mod errors;
pub mod ids;
pub mod inputs;
pub mod parallel;
pub mod proofs;
pub mod selectors;
pub mod traits;

pub use context::{AirContext, FriPlanDigest, TraceDomainOffset, TraceInfo, TraceRegister};
pub use descriptors::{
    BoundaryConstraintDescriptor, CompositionPolynomialDescriptor, LookupArgumentDescriptor,
    PermutationArgumentDescriptor,
};
pub use errors::AirErrorKind;
pub use ids::{AirSpecId, ParameterDigest};
pub use inputs::{
    AggregationPublicInputs, ConsensusPublicInputs, IdentityPublicInputs, PruningPublicInputs,
    PublicInputs, StatePublicInputs, TransactionPublicInputs, UptimePublicInputs,
};
pub use parallel::{DeterministicParallelization, ParallelChunkingRule};
pub use proofs::{
    AggregationAirProfile, ConsensusAirProfile, IdentityAirProfile, ProofAirKind,
    PruningAirProfile, StateAirProfile, TransactionAirProfile, UptimeAirProfile,
};
pub use selectors::{SelectorColumnDescriptor, SelectorForm, SelectorSet};
pub use traits::{
    AirSpec, CompositionChallengeSet, LookupTableAccess, TraceGroup, TransitionConstraintOrder,
};
