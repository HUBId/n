//! Selektor-Beschreibungen fuer deterministische Phasensteuerung.
//!
//! Selektoren werden ausschliesslich aus den Zeilenindizes und statischen
//! Parametern abgeleitet. Dieses Modul dokumentiert die zugelassenen Formen und
//! deren Little-Endian-Serialisierung.

/// Beschreibt die Formel, mit der ein Selektorwert berechnet wird.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelectorForm {
    /// Selektor ist exakt `1` in der ersten Zeile, sonst `0`.
    IsFirst,
    /// Selektor ist exakt `1` in der letzten Zeile, sonst `0`.
    IsLast,
    /// Selektor markiert alle Zeilen in der Absorb-Phase einer Sponge.
    /// Die Parameter definieren `start` (inklusive) und `length` in Schritten.
    AbsorbWindow { start: usize, length: usize },
    /// Selektor markiert alle Zeilen in der Squeeze-Phase einer Sponge.
    SqueezeWindow { start: usize, length: usize },
    /// Selektor ist `1`, wenn `row_index mod k == r`, sonst `0`.
    RoundClass { modulus: usize, residue: usize },
    /// Selektor mit konstantem Skalarwert fuer alle Zeilen.
    ConstantScalar { value_le: Vec<u8> },
}

/// Beschreibung einer Selektorspalte innerhalb des Traces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectorColumnDescriptor {
    /// Spaltenindex im Trace.
    pub column: usize,
    /// Formel, die die Selektorwerte definiert.
    pub form: SelectorForm,
}

/// Sammlung aller Selektoren einer AIR-Instanz in kanonischer Reihenfolge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectorSet {
    /// Reihenfolge der Selektoren entspricht der Spaltenordnung.
    pub selectors: Vec<SelectorColumnDescriptor>,
}
