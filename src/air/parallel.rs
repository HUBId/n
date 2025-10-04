//! Deterministische Parallelisierungsregeln.
//!
//! Dieses Modul dokumentiert die festen Aufteilungsregeln fuer Thread-Pools,
//! Spalten-Chunking und Query-Batches. Die Strukturen sind rein beschreibend.

/// Beschreibt einen Thread-Pool mit fester Groesse und Reihenfolge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeterministicParallelization {
    /// Anzahl der Worker-Threads.
    pub worker_count: usize,
    /// Reihenfolge, in der die Worker ihre Chunks bearbeiten.
    pub worker_order: Vec<usize>,
    /// Regeln zur Chunk-Bildung.
    pub chunking: Vec<ParallelChunkingRule>,
}

/// Regeln zur Aufteilung einzelner Arbeitspakete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParallelChunkingRule {
    /// Name des Arbeitsschritts (z. B. "core-columns", "aux-columns").
    pub name: &'static str,
    /// Anzahl der Spalten oder Zeilen pro Chunk.
    pub chunk_size: usize,
    /// Reihenfolge, in der die Chunks verarbeitet werden.
    pub chunk_order: Vec<usize>,
}
