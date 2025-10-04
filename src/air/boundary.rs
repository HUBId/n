//! Boundary constraint helpers for AIR definitions.
//! Provides deterministic enforcement of initial and final state conditions.

use crate::field::FieldElement;

/// Boundary constraint defined by fixed values at specific steps.
#[derive(Debug, Clone)]
pub struct BoundaryConstraint {
    /// Step index in the trace.
    pub step: usize,
    /// Expected register values at the step.
    pub values: Vec<FieldElement>,
}

impl BoundaryConstraint {
    /// Creates a new boundary constraint descriptor.
    pub fn new(step: usize, values: Vec<FieldElement>) -> Self {
        Self { step, values }
    }
}
