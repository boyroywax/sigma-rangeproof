# Audit and assurance

This page records the current assurance status of `sigma-rangeproof` and provides
a scope + sign-off template for an external cryptographic audit. It is meant to be
useful to an auditor on day one: what to review, what's already been done, and a
form to record the result.

## Current status

**Self-reviewed; not externally audited.** No third party has reviewed the
construction or the code. The following has been done in-house and is reproducible
from the repository:

| Area | State |
|---|---|
| Specification | Normative [encoding & transcript spec](spec.md); construction and security argument in [Sigma protocols](sigma-protocols.md) / [range proof](range-proof.md) |
| Construction | Textbook Sigma-protocol bit-decomposition range proof; no novel cryptography |
| Input validation | Subgroup membership + canonical-scalar checks on all untrusted proof elements |
| Malleability | Non-canonical scalars rejected (a `z + q` mutation no longer verifies) |
| Fiat-Shamir | Full statement bound into the transcript before any challenge (Frozen-Heart-resistant); modulus `p` bound as of 0.1.1 |
| Tests | Correctness, adversarial/soundness, Hypothesis property fuzzing, and published [KAT vectors](#known-answer-vectors) |
| Side channels | **Not** constant-time (Python `pow`); stated plainly in [Security](security.md#nonces-randomness-and-side-channels) |

What in-house review **cannot** substitute for, and an external audit should add:
an independent reimplementation / interop check, a second expert attacking the
soundness argument, and a side-channel assessment.

## Scope for an external audit

Suggested scope, for a fixed commit:

- **In scope:** `src/sigma_rangeproof/` (group, Pedersen commitments, transcript,
  the OR-proof and range-proof), the [spec](spec.md), and the serialization
  format.
- **Security goals to confirm:** soundness, honest-verifier zero-knowledge,
  commitment hiding/binding, encoding non-malleability — under discrete-log
  hardness and the random-oracle model, at the stated ~112-bit level.
- **Explicitly out of scope (documented limitations):** constant-time behavior,
  prover authentication/freshness, and caller-supplied custom groups. See
  [SECURITY.md](https://github.com/boyroywax/sigma-rangeproof/blob/main/SECURITY.md).

## Methodology checklist

An auditor can work down this list (see the
[audit-steps overview](https://boyroywax.github.io/sigma-rangeproof/) for context):

- [ ] Spec matches code; parameters and encodings fully pinned
- [ ] Group is prime-order; `g`, `h` valid; `h` has no known dlog rel. to `g`
- [ ] Pedersen hiding (perfect) and binding (computational) hold as claimed
- [ ] Schnorr special soundness + HVZK; OR-composition correct
- [ ] Fiat-Shamir binds the full statement; hash-to-scalar unbiased; `2ⁿ < q`
- [ ] All untrusted inputs validated (subgroup, canonical scalars, lengths)
- [ ] No nonce reuse; CSPRNG used; no secret-dependent control flow assumed safe
- [ ] Serialization is canonical and round-trips; no parser ambiguity
- [ ] Negative tests reject every malformed/adversarial input
- [ ] Independent reimplementation agrees on the KAT vectors

### Known-answer vectors

`tests/vectors/kat.json` (checked by `tests/test_kat.py`) lets an auditor or an
independent implementation confirm byte-for-byte agreement on the group
parameters, `h` derivation, Pedersen commitments, the transcript challenge, and
the verifier's accept/reject decisions on a frozen valid proof plus invalid
mutations.

## Sign-off template

Completed audit reports should be added under `audits/` in the repository. Copy
the block below into a dated report (e.g. `audits/2026-07-acme.md`).

```text
sigma-rangeproof — external audit sign-off

Auditor / firm:        ____________________________
Contact:               ____________________________
Audit dates:           ______________  to  ______________
Commit reviewed:       ____________________________ (full SHA)
Version:               ____________________________
Scope:                 src/sigma_rangeproof/, spec, serialization
Out of scope:          constant-time, prover auth/freshness, custom groups

Methodology:           [ ] design  [ ] implementation  [ ] side-channel
                       [ ] differential/interop  [ ] fuzzing  [ ] formal

Findings:
  ID    Severity   Title                                  Status
  ----  ---------  -------------------------------------  ----------
  ...   crit/high/med/low/info                            open/fixed

Summary of result:     ____________________________________________

Statement:
  Within the scope and limitations above, as of commit <SHA>, the reviewed
  code [does / does not] correctly implement the specified construction and
  [is / is not] free of the issues sought during this review. This review does
  not constitute a guarantee of security.

Auditor signature:     ____________________________   Date: __________
```

A sign-off is bound to a specific commit. Any change after the reviewed commit is
outside its scope and should be re-reviewed.
