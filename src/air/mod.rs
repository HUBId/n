//! # Algebraic Intermediate Representation (AIR)
//!
//! The AIR layer binds together the formal description of the STARK proving
//! pipeline. The documentation assembled here is intentionally high level and
//! focuses on sequencing, naming and interoperability requirements. Concrete
//! algorithms will be introduced incrementally in the dedicated modules.
//!
//! ## Pipeline overview
//!
//! 1. [`types`] establishes the canonical data containers shared between the
//!    prover and verifier. They document layout expectations without committing
//!    to storage backends.
//! 2. [`trace`] records how witness data is organised across execution steps and
//!    columns. The trace API is responsible for exposing the read interfaces
//!    consumed by constraint evaluation.
//! 3. [`composition`] captures how transition and boundary constraints are
//!    assembled into the polynomial commitments that feed the low-degree
//!    extension and FRI layers.
//! 4. [`traits`] defines the behavioural contracts that concrete AIRs must
//!    implement. These traits will later be implemented by each proof flavour to
//!    guarantee deterministic ordering and naming.
//! 5. [`example`] contains small, focused reference AIRs that double as tutorial
//!    material for integrators experimenting with the crate.
//!
//! Each section is currently a placeholder awaiting the detailed specification.
//! The module structure is kept in place so downstream crates can start wiring
//! their APIs without depending on unstable documentation artifacts.

pub mod composition;
pub mod example;
pub mod trace;
pub mod traits;
pub mod types;
