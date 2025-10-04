//! Kennungen und Digests fuer AIR-Spezifikationen.
//!
//! Die IDs dienen der eindeutigen Verknuepfung zwischen Phase-2-Layouts,
//! Constraint-Definitionen und den in Phase 3 generierten Transcript-Digests.

/// 32-Byte-Digest einer AIR-Spezifikation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AirSpecId {
    /// Kanonische Digest-Repräsentation (Little-Endian).
    pub le_bytes: [u8; 32],
}

/// Digest ueber Parameter- oder Profilinformationen, die in das Transcript
/// einfließen (z. B. Gruppendefinitionen, Lookup-Tabellen-Layouts).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ParameterDigest {
    /// Little-Endian Byte-Repräsentation.
    pub le_bytes: [u8; 32],
}
