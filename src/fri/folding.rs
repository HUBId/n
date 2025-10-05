//! FRI folding schedule descriptors and binary folding helpers.
//!
//! The folding utilities operate over the Goldilocks field and leverage the
//! deterministic pseudo-hashing primitives defined in [`crate::fri`].

use crate::field::FieldElement;
use crate::fri::config::FriProfile;
use crate::fri::{fe_add, fe_mul};
use crate::params::{FriFolding, StarkParams};

/// Constant folding arity used by the binary FRI variant supported in this crate.
pub const BINARY_FOLD_ARITY: usize = 2;

/// Canonical digest for commitments produced at a given layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LayerCommitment {
    /// Optional transcript digest emitted after committing to the layer.
    pub digest: Option<[u8; 32]>,
    /// Optional textual label describing how the layer contributes to the transcript.
    pub label: &'static str,
}

/// Describes how a layer is produced while folding the evaluation domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoldingLayer {
    /// Sequential index of the layer with respect to the original codeword.
    pub layer_index: usize,
    /// Logarithmic size of the evaluation domain at this layer.
    pub log_size: usize,
    /// Commitment emitted for the layer.
    pub commitment: LayerCommitment,
    /// Optional coset shift applied when deriving the folding challenge.
    pub coset_shift: Option<FieldElement>,
}

/// Full schedule tying a FRI profile to an ordered sequence of layers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoldingLayout {
    /// Reference to the canonical profile driving the schedule.
    pub profile: &'static FriProfile,
    /// Layers enumerated from root (codeword) to the residual polynomial.
    pub layers: Vec<FoldingLayer>,
}

impl FoldingLayout {
    /// Constructs the layout from layer roots and the initial domain size.
    ///
    /// The optional `coset_shifts` slice provides per-layer offsets applied to
    /// the folding challenge when operating in coset-switching mode.
    pub fn new(
        profile: &'static FriProfile,
        initial_size: usize,
        roots: &[[u8; 32]],
        coset_shifts: Option<&[FieldElement]>,
    ) -> Self {
        let mut layers = Vec::with_capacity(roots.len());
        let mut size = initial_size;
        for (layer_index, root) in roots.iter().copied().enumerate() {
            let log_size = log2(size);
            layers.push(FoldingLayer {
                layer_index,
                log_size,
                commitment: LayerCommitment {
                    digest: Some(root),
                    label: "fri-layer",
                },
                coset_shift: coset_shifts.and_then(|shifts| shifts.get(layer_index).copied()),
            });
            size = next_layer_size(size);
        }
        Self { profile, layers }
    }
}

/// Computes the next layer size by applying the binary folding arity.
fn next_layer_size(size: usize) -> usize {
    (size + BINARY_FOLD_ARITY - 1) / BINARY_FOLD_ARITY
}

/// Logarithm base two rounded down. `size` must be non-zero.
fn log2(size: usize) -> usize {
    assert!(size > 0, "domain size must be positive");
    usize::BITS as usize - 1 - size.leading_zeros() as usize
}

/// Applies the binary fold to `values` using the challenge `beta`.
///
/// The function groups evaluations into pairs `(a, b)` and produces the linear
/// combination described in the specification:
///
/// `g_i = a + beta * (coset_shift * b)`.
///
/// Coset shifts are derived from the [`StarkParams`] FRI configuration.  When
/// the last pair is incomplete the missing value is treated as zero which keeps
/// the combination well-defined.
pub fn binary_fold(
    values: &[FieldElement],
    beta: FieldElement,
    params: &StarkParams,
) -> Vec<FieldElement> {
    let coset_shift = derive_coset_shift(params);
    let mut result = Vec::with_capacity((values.len() + BINARY_FOLD_ARITY - 1) / BINARY_FOLD_ARITY);
    let mut chunks = values.chunks_exact(BINARY_FOLD_ARITY);

    for pair in chunks.by_ref() {
        let a = pair[0];
        let b = pair[1];
        let shifted_b = fe_mul(b, coset_shift);
        result.push(fe_add(a, fe_mul(beta, shifted_b)));
    }

    if let Some(&last) = chunks.remainder().first() {
        result.push(last);
    }

    result
}

fn derive_coset_shift(params: &StarkParams) -> FieldElement {
    match params.fri().folding {
        FriFolding::Natural => FieldElement::ONE,
        FriFolding::Coset => FieldElement::GENERATOR,
    }
}

/// Builds a per-layer coset shift schedule based on the FRI folding mode.
pub fn coset_shift_schedule(params: &StarkParams, layers: usize) -> Vec<FieldElement> {
    let shift = derive_coset_shift(params);
    vec![shift; layers]
}
