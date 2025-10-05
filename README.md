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
