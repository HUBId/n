# rpp-stark

## AIR pipeline overview

The AIR layer stitches together the execution trace, polynomial commitments, and
FRI sampling strategy described in Kap. 2–4 and 7. The high-level data flow is:

```text
Trace (Kap. 2) --> Low-Degree Extension (Kap. 3)
                    |
                    v
          Constraint Composition (Kap. 3–4)
                    |
                    v
            Merkle Commitments (Kap. 4)
                    |
                    v
        Transcript / Fiat–Shamir (Kap. 4)
                    |
                    v
                FRI Queries (Kap. 7)
```

Each arrow corresponds to a module under `src/air`:

| Stage | Module | Kap. | Deterministic contract |
|-------|--------|------|------------------------|
| Trace ingestion | [`src/air/trace.rs`](src/air/trace.rs) | 2–3 | Fixed row iterator and column ordering feeding the LDE. |
| LDE profiles | [`src/fft/lde.rs`](src/fft/lde.rs) | 3 | Blowup, ordering, and coset labelling shared by prover and verifier. |
| Composition | [`src/air/composition.rs`](src/air/composition.rs) | 3–4 | Transition/boundary combination bound to transcript challenges. |
| Merkle commitments | [`src/params/mod.rs`](src/params/mod.rs) & [`src/air/types.rs`](src/air/types.rs) | 4 | Canonical leaf encodings and arity selection. |
| Transcript | [`src/transcript/mod.rs`](src/transcript/mod.rs) | 4 | Label ordering for Fiat–Shamir challenges. |
| FRI | [`src/fri`](src/fri) | 7 | Query schedule derived from transcript seeds. |

### Trace and public-input schema

```
┌──────────────┐    ┌───────────────────────┐
│ Trace main   │    │ context_tag : [u8;32] │
│ Trace aux    │    │ trace_length : u32    │
│ Trace perm   │    │ public_values : Vec<F>│
│ Trace lookup │    │ challenge_bound : u32 │
└──────────────┘    └───────────────────────┘
```

| Segment | Column symbol | Description |
|---------|----------------|-------------|
| `main` | `columns::MAIN_WIDTH` | Execution registers evaluated at every step. |
| `aux` | `columns::AUX_WIDTH` | Auxiliary witness columns for helper relations. |
| `permutation` | `columns::PERM_WIDTH` | State for permutation arguments (Kap. 3). |
| `lookup` | `columns::LOOKUP_WIDTH` | Witnesses backing lookup constraints. |

Public inputs mirror the schema from [`types::PublicInputs`](src/air/types.rs):

| Field | Encoding | Purpose |
|-------|----------|---------|
| `context_tag` | 32-byte array | Names the execution instance and binds Kap. 2 metadata. |
| `trace_length` | `u32` little-endian | Selects the LDE domain length. |
| `public_values` | `Vec<FieldElement>` | Exposed registers absorbed into the transcript. |
| `challenge_bound` | `u32` little-endian | Caps Fiat–Shamir sampling range as mandated in Kap. 4. |

All serialisation is byte-for-byte reproducible; replaying the same trace and
public inputs therefore yields identical transcript openings and FRI queries.

### Transcript challenge ordering

The Fiat–Shamir transcript emits challenges in the order shown below. The phase
labels match [`AirTranscript`](src/air/traits.rs) and Kap. 4, ensuring that both
sides derive the same folding seeds and query indices.

```
Init → Public → TraceCommit → CompCommit → FRI(layer i) → Queries → Final
          │            │             │            │
          │            │             │            └─ FriFoldChallenge(i)
          │            │             └─ CompChallengeA
          │            └─ TraceChallengeA
          └─ PublicInputsDigest
```

The resulting challenge stream (`TraceChallengeA`, `CompChallengeA`, successive
`FriFoldChallenge(i)`, then `QueryIndexStream`) is highlighted in Kap. 7’s
worked example.

## Low-degree extension profiles

Low-degree extension (LDE) configuration lives in [`src/fft/lde.rs`](src/fft/lde.rs).
Instead of providing executable extension routines the module now describes
profiles in terms of their blowup factor, evaluation ordering, coefficient
endianness and deterministic chunking strategy.  Two profiles are currently
documented:

* `PROFILE_X8`: the prover-default ×8 configuration optimised for radix-2 FFTs.
* `PROFILE_HISEC_X16`: a ×16 high-security profile used during audits.

### Audit feature flags

Two opt-in Cargo features expose additional metadata for audit tooling without
changing runtime behaviour:

* `audit-lde` enables static tables that enumerate the standard audit profiles.
* `audit-lde-hisec` extends the above with the high-security ×16 profile and is
  declared as a dependent feature.

## Continuous integration

[![CI status](https://img.shields.io/badge/CI-pending-lightgrey.svg)](#)

## Projekt-Blueprint

Die folgende Spezifikation beschreibt die Zielarchitektur der Bibliothek
„rpp-stark – vollständige Library (v1.0, Rust stable only)“. Sie dient als
verbindliche Grundlage für Implementierung, Tests, Serialisierung und
Fehlermodell der gesamten Codebasis.

### Ziel & Scope

- **Zweck:** Eigenständige, deterministische STARK-Bibliothek mit klaren ABIs,
  Proof-Envelope, Verifier-API, Merkle/FRI/AIR/Composition, Serialisierung und
  Tests, kompatibel zur RPP-Chain (STWO-Default).
- **Rollen:** Wallet = Prover, Node = Verifier.
- **Ergebnis:** Byte-stabile Proof-Artefakte, präzise Fehlercodes,
  reproduzierbare Tests/Benches, CI-fähig – ohne nightly.

### Querschnitts-Policies (verbindlich)

- **Sprache/Toolchain:** Rust stable (MSRV festlegen und dokumentieren), keine
  `#![feature]`.
- **Safety:** Kein `unsafe`, keine Panics in Bibliothekslogik, keine
  `unwrap`/`expect`.
- **Determinismus:** Gleiche Inputs ⇒ bitidentische Outputs (Bytes, Roots,
  Indizes, Challenges).
- **Endianness:** Little-Endian für alle Ganzzahlen; Feldelemente als feste
  LE-Byte-Breite; Digests roh (byte-order-agnostisch).
- **Randomness:** Ausschließlich via Transcript (Fiat–Shamir); kein OS-RNG,
  keine Uhrzeit, kein Nonce aus Umgebung.
- **Fehler:** Wohldefinierte Enums (keine „stringly typed“ Zustände).
- **Hash & Merkle:** Hashfamilie via Params; STWO-kompatible 32-Byte
  Blake2s-Digests als Default (Adapter für alternative Hashes zulässig).
- **Versionierung:** Jede ABI- oder Protokolländerung ⇒ Versionsfeld erhöhen;
  ältere Verifier müssen deterministisch ablehnen.

### Feature-Flags (opt-in)

- `stark-core` (Standardkern)
- `parallel` (Rayon optional; muss bitidentische Ergebnisse liefern mit/ohne
  Parallelisierung)
- `audit-lde`, `audit-lde-hisec` (zusätzliche Prüfpfade/Assertions)
- `backend-rpp-stark` (für spätere Integration in chain)

Das Default-Feature-Set ändert kein bestehendes Verhalten außerhalb der
Library.

### Modulbaum & Dateien (Top-Level)

- `src/params/...` – Parameter, Profile, Hash-Bindings, `params_hash()`.
- `src/ser/...` – zentrales Serialisierungsschema (LE, Längenfelder,
  Enum-Tags).
- `src/transcript/...` – Domain-Separation, Absorb/Challenge, Labels,
  deterministische Streams.
- `src/merkle/...` – Tree, Proof, Open/Verify, Arity 2/4,
  Rightmost-Duplication.
- `src/fri/...` – Folding, Layer, Proof, Verify, Query-Orchestrierung.
- `src/air/...` – AIR-Traits, Trace-Schema, Beispiel-AIR, Composition-Builder.
- `src/proof/...` – Proof-Envelope, Ser/De, Verifier-API, Size-Gates.
- `tests/...` – Unit, Property, Negativ, Snapshot, E2E.
- `benches/...` – Criterion-Benches (nur stable-kompatible Messungen; keine
  nightly-Gates).

### Zentrales Serialisierungsschema (`ser/`)

- Ganzzahlen: `u16`/`u32`/`u64`/`u128` Little-Endian; `bool` als `u8` (0/1).
- Feldelemente: feste Byte-Länge, LE; keine Varints; keine Längenpräfixe
  innerhalb eines Felts.
- Digests: Rohbytes (keine Endianness-Interpretation).
- `Vec<T>`: `u32`-Elementanzahl als Präfix (Zählung in Elementen, nicht in
  Bytes).
- Optionale Felder: `u8`-Flag (0/1) vor dem Feld.
- Enums: fester Tag-Typ (`u8` oder `u16`), unbekannte Tags ⇒ Fehler.
- Zusammengesetzte Typen: Reihenfolge „Header → Fixed Fields → Längen →
  Arrays“; kein Padding.
- Fehlerbehandlung: `SerError`/`SerKind` → Modul-übergreifend auf
  `VerifyError::Serialization(SerKind)` mappen.
- Tests (Pflicht): Roundtrip aller Primitiven, Property-Tests für `Vec<Felt>`
  (begrenzte Länge), Negativfälle (falsche Längen/Tags), Snapshots für
  repräsentative Strukturen (MerkleProof, FriProof, Proof).

### Parameter (`params/`)

- Strukturfelder (verbindlich):
  - `proof`: `version (u16)`, `max_size_kb (u32)`.
  - `fri`: `domain_log2 (u16)`, `queries (u16)`, optionale zielgerichtete
    Layer-/Grad-Limits.
  - `merkle`: `arity (2/4)`, `leaf_width (u8)`, `leaf_encoding (Little; fixed)`,
    `domain-sep-Tag`.
  - `transcript`: `protocol_tag (u64)`, `seed ([u8;32])`.
  - `lde`: `order (RowMajor/ColMajor)`, ggf. Coset-Angaben.
  - `security`: `target_bits (u16)`, `soundness_slack_bits (u8)`.
  - `hash`: Familie/Variante, `digest_len` (z. B. 32).
- Funktion: `params_hash() -> [u8;32]` über kanonisch serialisierte Params.
- Profile: z. B. `PROFILE_X8`, `PROFILE_HISEC_X16`, dokumentiert mit festen
  Werten.
- Tests: Roundtrip & Snapshots der Profile; `params_hash` stabil; Invarianten
  (z. B. `1 << domain_log2 ≥ Trace-Länge`).

### Transcript (`transcript/`)

- Phasen & Reihenfolge (fix):
  1. Init: absorb `ParamsHash`, `ProtocolTag` (`u64` LE), `Seed ([32])`.
  2. Public: absorb `PublicInputsDigest`.
  3. TraceCommit: absorb `TraceRoot`; ggf. Komposition-Challenge(s).
  4. CompCommit (optional): absorb `CompRoot`; Challenges `CompChallengeA/B/...`
     (`α`-Vektor).
  5. FRI: pro Layer absorb `FriRoot(i)`, dann `FriFoldChallenge(i)`.
  6. Queries: absorb `QueryCount` (`u16` LE), dann Challenge-Strom
     `QueryIndexStream`.
  7. Final: optionale Abschlussbytes (reiner Bindungszweck).
- API (verbal): Konstruktor mit Params & Kontext; `absorb_*`
  (Bytes/Digest/Feld); `challenge_field`, `challenge_usize(range)`,
  `challenge_bytes(n)`; deterministisch, ohne OS-RNG.
- Tests: Reproduzierbarkeit der Challenge-Sequenzen bei identischen Inputs;
  Label-Reihenfolge fix.

### Merkle (`merkle/`)

- Leaf-Layout (fix):
  - `leaf_width` Feldelemente pro Leaf.
  - Jedes Felt als LE-Bytefolge; Leaves sind simple Konkatenation ohne Präfixe
    innerhalb des Leafs.
  - Reihenfolge: an `lde.order` gebunden (Row/ColMajor) – einmal definieren und
    überall referenzieren.
  - Domain-Separation: konsistente Tags (z. B. unterschiedlich für Leaves vs.
    innere Knoten).
- Baumregeln:
  - Arity 2 oder 4; Rightmost-Child-Duplication bei ungerader Blattzahl.
  - Proof: versionierte Struktur; Pfadknoten je Ebene arity-konform.
  - Batch-Openings: Indices aufsteigend & eindeutig.
- Fehlerfälle: `leere Leaves`, `LeafWidthMismatch`, `IndexOutOfRange`,
  `DuplicateIndex`, `ArityMismatch`, `InvalidPathLength`, `VerificationFailed`.
- Tests: Commit/Open/Verify; Multi-Openings; Negativ (manipulierte Pfade,
  falsche Root, Arity-Fehler); deterministische Snapshots.

### FRI (`fri/`)

- Spezifikation:
  - Domain: `N = 2^(domain_log2)`; Coset-Shift (falls verwendet) fix
    dokumentieren.
  - Folding (klassisch, arity-2): pro Layer `i` Challenge `βᵢ`; Paarbildungsregel,
    Abbildung der Indizes und Abbild `φ(x)` (z. B. `x→x²`) präzise festlegen.
  - Termination: definierte Anzahl Layer oder finaler Low-Degree-Check;
    Implementationsdetail dokumentieren (z. B. finaler Klein-Layer +
    Direktprüfung).
- Proof-Struktur (verbal): Version, `domain_log2`, `num_layers`, `roots[]`,
  `fold_challenges[]`, `query_proofs[]`, optional `oods`-Block.
- Verifier: Reproduziert Roots/Challenges via Transcript; generiert
  Query-Indizes lokal; prüft Merkle-Pfad & Faltungsrelation je Layer; finaler
  Check.
- Tests: E2E klein; Negativ (Challenge-Flip, Pfad-Fehler); deterministische
  Snapshots (Bytes, Roots, Challenges).

### AIR & Composition (`air/`)

- Traits & Rollen (verbal):
  - `Air`: `id` (stabil), `trace_schema`, `degree_bounds`, `public_spec`,
    `boundary(builder, first, last, public)`,
    `transition(evaluator, row, next, public)`.
  - `TraceBuilder`: deterministischer Witness-Generator aus PublicInputs.
  - `PublicInputsCodec`: kanonisches Encode/Decode (LE-Schema) + Digest
    (z. B. Blake2s-256).
  - `BoundaryBuilder`, `Evaluator`: deklarativ Constraints registrieren; intern
    polynomiale Ausdrücke.
  - `compose(...)`: Randomizer-α via Transcript; Gruppierung; Normierung gegen
    vanishing polynomials; Zielgrad einhalten; liefert Evaluationsvektor(e) +
    optional Commitment.
- Beispiel-AIR: LFSR oder MiMC-Round – komplett beschrieben (Rollen/Constraints
  /Public-Schema/Trace-Gen), um E2E-Tests zu ermöglichen.
- Tests: Determinismus, Degree-Grenzen, Boundary/Transition-Negativ,
  E2E-Mini.

### Proof-Envelope & Verifier (`proof/`)

- ABI (binärstabil):
  - Felder in dieser Reihenfolge:
    1. `proof_version (u16, =1)`
    2. `params_hash (32)`
    3. `public_digest (32)`
    4. `trace_commit (Digest)`
    5. Optional `comp_commit (Digest)` mit vorgeschaltetem `has_comp`-Flag (`u8`)
    6. `fri (FriProof; versioniert; über ser/ serialisiert)`
    7. `openings (Struktur für Trace/Composition/Aux)`
    8. Optional `telemetry` mit `has_tel`-Flag (`u8`) – nicht
       verifikationsrelevant
  - `openings.trace` muss existieren; `composition`/`aux` optional.
  - Jedes Merkle-Bundle: `root`, `indices (u32, aufsteigend & eindeutig &
    identisch zur lokalen Query-Liste)`, `leaves`, `paths`. Längenfelder
    konsistent.
- Verifier-Ablauf (fix):
  - Header-Checks: Version, `params_hash`, `public_digest`, Proof-Größe (echte
    Serialisierungslänge ≤ `max_size_kb × 1024`).
  - Transcript-Rebuild: absorb in fester Reihenfolge: `ParamsHash → ProtocolTag →
    Seed → PublicDigest → TraceRoot → optional CompRoot → alle FRI-Roots` in
    Proof-Reihenfolge; Challenges ziehen (`Composition-α` falls vorhanden; dann
    pro FRI-Layer `FriFoldChallenge`).
  - Query-Indizes lokal erzeugen: `q = params.fri.queries`,
    `N = 2^(domain_log2)`; via `challenge_usize` exakt `q` Werte; danach
    aufsteigend sortieren und Duplikate entfernen (deterministisch). Ergebnis
    muss exakt `openings.trace.indices` entsprechen – andernfalls
    `IndicesNotSorted`/`IndicesDuplicate`/`IndicesMismatch`.
  - Merkle-Openings prüfen: Root-Gleichheit (`RootMismatch`), Länge der Vektoren
    (`Indices`/`Leaves`/`Paths`), Pfad-Verifikation je Index (`MerkleVerifyFailed`).
  - FRI verifizieren: `fri_verify(...)`; Fehler 1:1 mappen.
  - Kompositions-Bindung (falls `comp_commit` existiert): Leaves, auf die
    FRI-Komposition referenziert, müssen bytegenau den `composition`-Leaves an
    denselben Indizes entsprechen (`CompositionInconsistent` bei Abweichung).
  - Report: Flags setzen (`params_ok`, `public_ok`, `merkle_ok`, `fri_ok`,
    `composition_ok`), `total_bytes` als echte Serialisierungslänge.
- Fehler-Taxonomie (final):
  - `VersionMismatch { expected, got }`
  - `ParamsHashMismatch`
  - `PublicDigestMismatch`
  - `ProofTooLarge { max_kb, got_kb }`
  - `EmptyOpenings` (trace fehlt/leer)
  - `IndicesNotSorted`
  - `IndicesDuplicate { index }`
  - `IndicesMismatch`
  - `RootMismatch { section }`
  - `MerkleVerifyFailed { section }`
  - `FriVerifyFailed(FriError)`
  - `CompositionInconsistent { reason }`
  - `Serialization(SerKind)`
  - `Unsupported(&'static str)`
- Größen-Gate: Proof nicht schätzen – serialisieren und Länge vergleichen.

### Query-Indizes (verbindlich)

- Niemals aus dem Proof übernehmen; immer lokal reproduzieren (Transcript).
- Nach Generierung: sortieren und deduplizieren (deterministisch).
- Identität zu `openings.trace.indices` ist Pflicht.

### Hashing & STWO-Adapter

- Default: Blake2s-256 (32 Byte) für maximale STWO-Kompatibilität (Merkle-Root
  & Public-Digest).
- Alternative Hashfamilien via Adapter-Hasher möglich (Poseidon/Rescue), sofern
  Root-Bytes identisch zum STWO-Pfad geliefert werden, falls Interop nötig.
- Domain-Separation konsistent (Leaf vs. Node; Trace vs. Composition vs. FRI).

### Testsuite (vollständig, stable-kompatibel)

- **Ser/Params:** Roundtrip aller `ser/`-Primitiven; Property-Tests für
  Felt-Vektoren (kleine Grenzen); Negativfälle (Längen/Tags);
  Profile-Snapshot-Bytes; `params_hash`-Stabilität.
- **Merkle:** Commit/Open/Verify (single & batch); Negativ: Pfad manipuliert,
  Root falsch, Arity-Fehler, unsortierte/duplizierte Indizes; Snapshots.
- **FRI:** E2E auf kleiner Domain; Negativ: Fold-Challenge flip, Pfad-Fehler;
  Snapshots von Roots/Challenges/Proof-Bytes.
- **AIR/Composition:** Beispiel-AIR (LFSR/MiMC): deterministischer Trace;
  Constraints-Checks; Degree-Grenzen; E2E klein.
- **Proof/Verifier:** Header-Checks (Positiv + vier Negativfälle
  Version/Params/Public/Size); Transcript/Queries (lokale Liste ==
  `openings.trace.indices`); Merkle-Openings (Positiv + unsortiert + Duplikat +
  Root-Mismatch + Pfad-Fehler); FRI-Glue (Positiv + Fold-Challenge flip ⇒
  Fehler); Composition-Konsistenz (Positiv + Leaf-Mutation ⇒ Fehler);
  Report-Flags plausibel; `total_bytes` korrekt.
- **Property-Tests (stable):** Random kleine Bäume/Indexmengen (engen Rahmen)
  ⇒ Verify OK. Random kleine Beispiel-AIR-Längen ⇒ Prove/Verify OK.
- **Snapshots (stabil):** Mini-Proof (z. B. `domain_log2=8`, `queries=2`,
  `leaf_width=1`, Arity-2, 1–2 FRI-Layer): Proof-Bytes, Roots,
  Fold-Challenges, Query-Liste, Pfadlängen.

### Performanceziele & Benches (stable-friendly)

- Merkle-Commit: Throughput für 1k/16k/64k Leaves; Verify-Latenz je Pfadlänge.
- FRI-Folding: Zeit für `N=2^14`, `2^16` (ohne nightly Tricks).
- Verifier E2E: `queries 8/16/32`, `domain_log2 12/16`.
- Keine Fail-Gates in CI; Berichte als Artefakte speichern.

### CI-Anforderungen (nur stable)

- Build/Test auf stable; MSRV separat prüfen, falls abweichend.
- `clippy -D warnings` (sauber).
- Snapshots deterministisch (keine Umgebungsabhängigkeiten).
- Artefakte: Bench-Reports, Snapshots.

### Integration in chain (später, optional)

- Adapter-Layer: Typalias für Felt, Digest-Wrapper, Hasher-Bindings zum
  STWO-Pfad.
- Feature-Gate `backend-rpp-stark`.
- Zwei kleine CLI-Binaries (separat) für prove/verify zum manuellen Testen.
- Proof-Size-Gate direkt an Node-Konfiguration abbilden.

### Milestones & Abnahme (empfohlene Reihenfolge, stable-only)

1. `ser/` (zentrales Schema) mit vollständigen Tests & Snapshots.
2. `params/` inkl. `params_hash()`, Profile, Snapshots.
3. `transcript/` mit deterministischen Labels/Challenges; Tests.
4. `merkle/` (Arity 2/4, RMD) inkl. Roundtrip/Negativ/Snapshots.
5. `fri/` (Proof & Verify) mit kleinen E2E-Fixtures; Snapshots.
6. `air/` + Beispiel-AIR + Composition (ohne Node-Anbindung) mit E2E-Mini.
7. `proof/` (Envelope/Ser + Header-Verifier) mit Header-Tests & Snapshots.
8. `proof/` (Transcript/Queries/Merkle/FRI/Composition) – komplette
   Verifier-Orchestrierung; volle Testsuite.
9. `parallel/` Flag (Rayon) – Beweis der Bit-Gleichheit on/off mit
   deterministischen Tests.

### Definition of Done

Alle Tests grün, Snapshots stabil, Clippy ohne Warnungen, Benches laufen,
Doku vollständig (Layouts, Reihenfolgen, Versionierung, Policies). Keine
nightly-Abhängigkeiten.

## Roadmap

### Phase 0 – Projektgerüst & Leitplanken

**Ziele:** saubere Basis, keine Nightly, deterministische Tests.

**Aufgaben**

- MSRV festlegen (README + CI).
- `clippy -D warnings`, `#![forbid(unsafe_code)]` in lib-root.
- CI: build+test+clippy auf stable; Artefakte: Test-Logs, Snapshots.

**Definition of Done (DoD):** Pipeline grün, keine Warnings, Policies dokumentiert.

### Phase 1 – Zentrales Ser-Schema (`ser/`)

**Ziele:** einheitliche LE-Serialisierung für Ints, Felt, Digest, Vec, Option, Enums.

**Aufgaben**

- Ser-Helfer: `u16`/`u32`/`u64`/`u128` (LE), `bool` (`u8`), Bytes (LP `u32`), Felt (fixe LE-Byte-Länge), Digest (roh), `Vec<T>` (`u32`-Anzahl), Option (`u8`-Flag), Enum-Tag (`u8`/`u16`).
- Fehler `SerError`/`SerKind` + Mapping.
- Tests: Roundtrip, Property (kleine `Vec<Felt>`), Negativ (InvalidLength/Tag), Snapshots für repräsentative Strukturen.

**DoD:** Snapshots stabil, alle Module müssen diese Helfer verwenden.

### Phase 2 – Params (+ Profile & Hash)

**Ziele:** `StarkParams` + `params_hash()` stabil; Profile X8/HISEC.

**Aufgaben**

- Strukturfelder (`proof`/`fri`/`merkle`/`transcript`/`lde`/`security`/`hash`) exakt wie Blueprint.
- Profile definieren (z. B. X8, HISEC X16); Blake2s-256 als Default-Digest.
- Tests: Roundtrip, `params_hash`-Stabilität, Snapshot pro Profil, Invarianten.

**DoD:** `params_hash` fix, Profiles dokumentiert.

### Phase 3 – Transcript

**Ziele:** deterministische Fiat–Shamir-Engine mit festen Labels/Phasen.

**Aufgaben**

- Phasenfolge: Init → Public → TraceCommit → CompCommit? → FRI (layered) → Queries → Final.
- API: `absorb_bytes`/`digest`/`felt`; `challenge_field`/`usize`/`bytes`.
- Tests: Wiederholbarkeit (gleiche Inputs ⇒ gleiche Challenges), Label-Order.

**DoD:** deterministisch, Dokumentation mit Label-Tabelle.

### Phase 4 – Merkle

**Ziele:** Arity-2/4 Baum, festes Leaf-Layout (LE), Verify-API.

**Aufgaben**

- Leaf-Layout: `leaf_width × Felt` (LE-konkat), Order via `lde.order`.
- Domain-Separation (Leaf/Node Tags) dokumentieren.
- Proof-Struktur + Batch-Openings (Indices strikt aufsteigend + unique).
- Tests: Commit/Open/Verify; Negativ (Pfadknoten/Root/Arity/Indices), Snapshots.

**DoD:** Verify stabil; Bytes & Regeln dokumentiert.

### Phase 5 – FRI

**Ziele:** Proof & Verify für kleines N; Folding formal fixiert.

**Aufgaben**

- Domain `N = 2^logN`; Folding mit βᵢ; Index-Mapping klar.
- Proof: version, `roots[]`, `fold_challenges[]`, `query_proofs[]`, optional OODS.
- Verifier: reproduziert Roots/Challenges via Transcript; nutzt lokale Query-Indizes.
- Tests: E2E klein; Negativ (Challenge flip, Pfad-Fehler), Snapshots.

**DoD:** Kleine FRI-Beweise laufen deterministisch.

### Phase 6 – AIR & Composition

**Ziele:** AIR-Traits + Beispiel-AIR + Composer.

**Aufgaben**

- Traits: `Air`, `TraceBuilder`, `PublicInputsCodec` (Encode + Digest), `Evaluator`/`Boundary`.
- Composer: α-Randomizer via Transcript; Degree-Limits; Evaluationsvektoren.
- Beispiel-AIR (LFSR/MiMC) für E2E.
- Tests: deterministischer Trace, Degree-Grenzen, E2E-Mini.

**DoD:** Beispiel-AIR generiert Prove/Verify-fähige Evaluations.

### Phase 7 – Proof-Envelope (ABI) & Header-Verifier

**Ziele:** binärstabiler Envelope + Header-Checks.

**Aufgaben**

- Proof-Layout exakt laut Blueprint (Version, Hashes, Commits, FRI, Openings, Telemetry).
- Ser/De via `ser/`.
- `verify()` (Teil A): Version, `params_hash`, `public_digest`, `size_gate` (echte Serialisierung).
- Tests: Roundtrip + Snapshot; 4 Negativfälle (Version/Params/Public/Size).

**DoD:** Proof-Bytes eingefroren (Snapshot), Header-Verifier grün.

### Phase 8 – Verifier-Orchestrierung komplett

**Ziele:** vollständige Verify-Pipeline.

**Aufgaben**

- Transcript-Rebuild (fixe Reihenfolge).
- Query-Indices lokal erzeugen, sortieren, deduplizieren; mit `openings.trace.indices` abgleichen (`NotSorted`/`Duplicate`/`Mismatch`).
- Merkle-Openings: Root-Match + Pfad-Verify.
- FRI-Verify einhängen, Fehler mappen.
- Composition-Konsistenz (falls `comp_commit`): Leaves bytegenau an gleichen Indizes.
- Report-Flags setzen; `total_bytes` füllen.
- Tests: Queries-Gleichheit, Merkle-Negativmatrix, FRI-Glue (flip), Composition-Mutation, Report.

**DoD:** Alle Verifier-Tests grün; Diagnose-Fehler präzise.

### Phase 9 – Parallelisierung (optional, stable)

**Ziele:** Rayon-Flag ohne Ergebnisabweichung.

**Aufgaben**

- Parallele Pfade (Commit/FRI) hinter `parallel`-Feature; deterministische Reduktionen.
- Tests: Bit-Gleichheit on/off für Mini-Proof.

**DoD:** Byte-identische Outputs mit/ohne Parallel.

### Phase 10 – Hardening, Docs, Release

**Ziele:** robuste Lib, klare Doku, Version 1.0.

**Aufgaben**

- Negative Property-Tests (gezielte Fail-Injection).
- README/Docs: Layout-Tabellen (Proof/Openings/Bundle), Label-Reihenfolge, Versionierungspolitik, Size-Gates, STWO-Adapterhinweise.
- Benchmarks (stable): Parse/Verify für kleine/mittlere Größen; Artefakte speichern.
- Version taggen; CHANGELOG.

**DoD:** Doku vollständig, CI grün, Bench-Artefakte vorhanden, Tag v1.0.0.

### PR-Plan (empfohlen, klein & linear)

1. Ser-Schema + Tests.
2. Params + Profiles + Snapshots.
3. Transcript + Determinismus-Tests.
4. Merkle + Tests/Snapshots.
5. FRI + Mini-E2E + Snapshots.
6. AIR + Beispiel-AIR + E2E.
7. Proof-Envelope + Header-Verifier + Snapshots.
8. Vollständiger Verifier (Queries/Merkle/FRI/Composition) + Tests.
9. Parallel-Flag + Gleichheits-Tests.
10. Docs/Benches/Release.

### Quality Gates (pro PR)

- `cargo test` (stable)
- `cargo clippy -D warnings`
- deterministische Snapshots (keine Umgebungsabhängigkeiten)
- Kein `unsafe`, keine `unwrap`/`expect` in Lib-Logik
- Review-Checklist: Endianness, Längenfelder, Fehlerpfade, deterministische Reihenfolge

### Risiken & Gegenmaßnahmen

- Drift beim Ser-Layout: Snapshots + `PROOF_VERSION++` bei Änderungen.
- Nichtdeterminismus: alle Zufallspfade über Transcript; keine OS-RNGs; Sort + Dedup für Indizes.
- Größen-Explosion: Size-Gate früh aktiv; Benchmarks zur Beobachtung.
- STWO-Interop: Digest 32B (Blake2s) + dokumentierte Domain-Separation; ggf. Adapter-Hasher.

### Spätere Chain-Integration (separat)

- Adapter-Layer (Felt/Digest/Hasher), Feature-Gate `backend-rpp-stark`.
- Zwei CLI-Binaries (`prove`, `verify`) für manuelle Tests.
- Proof-Size-Gate an Node-Config mappen.

## Canonical STARK parameters

The [`params`](src/params/mod.rs) module defines `StarkParams` as the single
source of truth for every security and performance relevant configuration item.
The structure is serialised into a deterministic byte layout which is used to
derive a stable `params_hash`.  The table below summarises the built-in
profiles:

| Profile | Field | Hash | Blowup | FRI queries | Merkle arity | Target bits |
|---------|-------|------|--------|-------------|--------------|-------------|
| `PROFILE_X8` | Goldilocks | Poseidon2 (set 0) | 8 | 30 | Binary | 96 |
| `PROFILE_HISEC_X16` | BN254 | Rescue (set 1) | 16 | 48 | Quaternary | 128 |

### Canonical byte layout

The binary format is free of padding and all integers are little-endian:

| Field | Bytes |
|-------|-------|
| `params_version` | 2 |
| `field` | 2 |
| `hash.family` | 1 |
| `hash.parameter_id` | 2 |
| `lde` (`blowup`, `order`, `coset_tag`) | 13 |
| `fri` (`r`, `queries`, `domain_log2`, `folding`, `num_layers`) | 7 |
| `merkle` (`leaf_encoding`, `leaf_width`, `arity`, `domain_sep`) | 11 |
| `transcript` (`protocol_tag`, `seed`, `challenge_bounds`) | 42 |
| `proof` (`version`, `max_size_kb`) | 6 |
| `security` (`target_bits`, `soundness_slack_bits`) | 3 |

Equal byte sequences imply identical parameter sets and therefore the same
`params_hash`.

## Transcript subsystem

The [`transcript`](src/transcript/mod.rs) module documents a deterministic
Fiat–Shamir transcript shared by prover and verifier.  The transcript operates
over labelled phases; each label is an enum variant to guarantee domain
separation at compile time.

| Phase | Label | Purpose |
|-------|-------|---------|
| Init | `ParamsHash`, `ProtocolTag`, `Seed`, `ContextTag` | Bind the transcript to the negotiated [`StarkParams`](src/params/stark_params.rs). |
| Public | `PublicInputsDigest` | Absorb canonical public inputs. |
| TraceCommit | `TraceRoot`, `TraceChallengeA` | Bind the execution trace commitment and emit the first challenge. |
| CompCommit | `CompRoot`, `CompChallengeA` | Bind composition commitments and emit the folding seed. |
| FRI | `FriRoot(i)`, `FriFoldChallenge(i)` | Iterate through each FRI layer. |
| Queries | `QueryCount`, `QueryIndexStream` | Fix the number of queries and derive deterministic indices. |
| Final | `ProofClose` | Produce the final 32-byte proof binding digest. |

Determinism is guaranteed by deriving every sponge update from the parameter
hash, transcript seed, protocol tag and context label.  Replaying the exact same
label/data sequence reproduces the state digest and challenge stream bit for
bit.  The query index stream uses a modulo reduction; the residual bias is
negligible for domain sizes above 2<sup>16</sup> and is documented in the
rustdoc comments.

## AIR benchmarking

Criterion benches covering the AIR layer live under [`benches`](benches).  The
`air_benches` target measures transition evaluation and constraint composition
throughput for the worked LFSR example across multiple trace lengths.  All
inputs are derived from a fixed seed and deterministic parameter set, ensuring
that repeated runs produce identical transcripts and commitments.

Run the suite with:

```
cargo bench --bench air_benches
```

The command completes without accessing randomness or the network, making the
results stable across invocations and hosts.
