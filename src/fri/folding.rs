//! FRI folding schedule descriptors.
//! Encodes how quartic folding is applied across the layered commitment tree.

use crate::fri::config::FriProfile;

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

/// Trait describing access to quartic FRI folding metadata.
pub trait QuarticFriFolding {
    /// Returns the folding layout containing ordered layer commitments.
    fn layout(&self) -> &FoldingLayout;

    /// Returns the folding factor. Defaults to the quartic constant.
    fn folding_factor(&self) -> usize {
        QUARTIC_FOLD
    }
}
