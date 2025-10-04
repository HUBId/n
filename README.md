# laughing-winner
Fixed sized blockchain design with recursive compression

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
