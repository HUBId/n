//! FRI folding schedule descriptors and quartic folding helpers.
//!
//! The folding utilities operate over the Goldilocks field and leverage the
//! deterministic pseudo-hashing primitives defined in [`crate::fri`].

use crate::field::FieldElement;
use crate::fri::config::FriProfile;
use crate::fri::{fe_add, fe_mul};

/// Constant folding factor used by the quartic FRI variant supported in this crate.
pub const QUARTIC_FOLD: usize = 4;

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
    pub fn new(profile: &'static FriProfile, initial_size: usize, roots: &[[u8; 32]]) -> Self {
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
            });
            size = (size + QUARTIC_FOLD - 1) / QUARTIC_FOLD;
        }
        Self { profile, layers }
    }
}

/// Logarithm base two rounded down. `size` must be non-zero.
fn log2(size: usize) -> usize {
    assert!(size > 0, "domain size must be positive");
    usize::BITS as usize - 1 - size.leading_zeros() as usize
}

/// Applies the quartic fold to `values` using the challenge `eta`.
///
/// The function groups evaluations into cosets of size four and computes the
/// linear combination described in the specification:
///
/// `g_i = v_{4i} + eta * v_{4i+1} + eta^2 * v_{4i+2} + eta^3 * v_{4i+3}`.
///
/// When the last coset has fewer than four evaluations the missing values are
/// treated as zero which keeps the combination well-defined.
pub fn quartic_fold(values: &[FieldElement], eta: FieldElement) -> Vec<FieldElement> {
    let mut result = Vec::with_capacity((values.len() + QUARTIC_FOLD - 1) / QUARTIC_FOLD);
    let mut powers = [FieldElement::ONE; QUARTIC_FOLD];
    for i in 1..QUARTIC_FOLD {
        powers[i] = fe_mul(powers[i - 1], eta);
    }

    for chunk in values.chunks(QUARTIC_FOLD) {
        let mut acc = FieldElement::ZERO;
        for (value, power) in chunk.iter().zip(powers.iter()) {
            acc = fe_add(acc, fe_mul(*value, *power));
        }
        result.push(acc);
    }

    result
}
