# rpp-stark

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
