# Prover/Verifier Determinism Specification

This repository currently ships interface-only modules. Implementations are
expected to satisfy the following behavioural contracts once wired in:

## Deterministic Proving
- `generate_proof` must be deterministic for a fixed combination of
  `ProofKind`, public inputs, witness blob and `ProverContext`.
- VRF commitments embedded inside the `ProofEnvelope` must be derived solely
  from prover-side state; no verifier challenge is allowed during the
  generation phase.

## Envelope and Size Checks
- Every produced `ProofEnvelope` must respect `MAX_PROOF_SIZE_BYTES` including
  metadata and body payload.
- Header lengths must match the serialized payload lengths documented in
  `public_inputs.rs` and the integrity digest must bind both segments.

## Verifier Requirements
- `Verifier::verify` must recompute transcript digests locally and compare
  them against the envelope without relying on prover responses.
- VRF challenges must be derived by the verifier independently using the
  commitments extracted via `Verifier::vrf_commitments`.

Test harnesses should capture these invariants through reproducible fixtures
that assert byte-for-byte equality of proof outputs and verify the maximum
size constraints.
