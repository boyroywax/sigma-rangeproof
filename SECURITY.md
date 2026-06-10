# Security Policy

## Supported versions

This is a `0.x`, **pre-1.0, unaudited** library. Only the latest released version
receives security fixes. Pin an exact version and review the
[CHANGELOG](CHANGELOG.md) before upgrading — wire-format changes (e.g. 0.1.0 →
0.1.1) mean proofs are not cross-version compatible.

## Reporting a vulnerability

**Please do not open a public issue for a security vulnerability.**

Report it privately through GitHub's
[private vulnerability reporting](https://github.com/boyroywax/sigma-rangeproof/security/advisories/new)
(Security → Report a vulnerability). Include a description, affected version /
commit, and a reproduction if you have one.

What to expect:

- An acknowledgement within **5 business days**.
- An assessment and, for confirmed issues, a fix and a coordinated release.
- Credit in the advisory and CHANGELOG if you'd like it.

Please give us reasonable time to release a fix before any public disclosure.

## What this library is designed to protect

The package implements a zero-knowledge range proof: prove a Pedersen-committed
integer satisfies `value >= threshold` without revealing the value. The intended
guarantees, and their assumptions, are:

| Property | Holds against | Rests on |
|---|---|---|
| **Soundness** — a false `value >= T` cannot be proved | a computationally bounded prover | discrete-log hardness in the group + Fiat-Shamir (random-oracle model) |
| **Zero-knowledge** — a proof reveals only the boolean | any verifier | simulatability of the Sigma protocols |
| **Hiding** — a commitment reveals nothing about the value | an unbounded adversary | uniform blinding (perfect hiding) |
| **Binding** — a commitment cannot be opened two ways | a computationally bounded adversary | discrete-log hardness |
| **Non-malleability of encoding** — proofs are unique and canonical | a tampering relay | subgroup + canonical-scalar checks in `verify_ge` |

Security level is ~112 bits (the 2048-bit group). The construction, encoding, and
verifier obligations are specified in the
[docs](https://boyroywax.github.io/sigma-rangeproof/spec/).

## Out of scope / known limitations

These are **not** provided, by design or by current state, and callers must
account for them:

- **No external audit.** The construction is standard and the test suite is
  adversarial (subgroup attacks, malleability, fuzzing, published KAT vectors),
  but no third party has reviewed it. An in-house automated static self-review
  is recorded under [`audits/`](audits/), and commissioning an external
  cryptographic audit is tracked in
  [issue #2](https://github.com/boyroywax/sigma-rangeproof/issues/2). Treat
  accordingly.
- **Not constant-time.** The arithmetic uses Python's `pow`, whose timing depends
  on secret exponents (the value and the blinding). Do not use this where an
  attacker can precisely measure prove-time against a secret you must protect.
- **No prover authentication or freshness.** A proof says "the committed value
  clears the bar," not who made it or when. Binding a proof to an identity,
  session, or nonce is the caller's responsibility; a proof can otherwise be
  replayed verbatim.
- **Caller-supplied groups are trusted.** The default group is a fixed,
  nothing-up-my-sleeve safe prime. If you pass custom `Params`, you are
  responsible for `h` having no known discrete log relative to `g`.
- **The upper bound is real.** A proof of `value >= T` also proves
  `value < T + 2^bits`. Account for it if your threat model cares about the top.

## Verifying a build

Known-answer vectors live in [`tests/vectors/kat.json`](tests/vectors/kat.json)
and are checked by `tests/test_kat.py`. An independent implementation can use the
same file to confirm byte-for-byte agreement on the group, the commitment, the
transcript challenge, and verification accept/reject decisions.
