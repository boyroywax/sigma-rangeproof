# Changelog

## 0.1.2

Hardening release. No wire-format change — proofs produced by 0.1.1 verify
unchanged on 0.1.2 and vice versa.

- **Bounded verifier work (F-01).** `verify_ge` now rejects proofs claiming
  `bits > MAX_BITS` (= 64) or `threshold ≥ q` before any modular arithmetic
  runs, and `RangeProof.from_dict` rejects hex fields wider than the canonical
  group-element / scalar byte width. A hostile proof can no longer push the
  verifier into arbitrary work.
- **Integer-domain invariants enforced (F-02).** `commit` now raises on
  `value` or `blinding` outside `[0, q)` instead of silently reducing them mod
  `q`. `prove_ge` raises on `value ≥ q`, `threshold ≥ q`, `bits > MAX_BITS`,
  or `2^bits ≥ q`. With the default 2048-bit group these are formalities; with
  a custom small-group `Params` they prevent silent integer/modular confusion.
- New public symbol: `MAX_BITS`.
- New `Params.scalar_bytes` property (canonical big-endian width of a scalar).

## 0.1.1

**Wire-format change** (proofs are not cross-compatible with 0.1.0).

- Transcript now binds the modulus `p` as its raw 256-byte value. Previously it
  was absorbed via the integer path, which reduced `p mod p` to zero and left the
  modulus unbound; the group was pinned only through `g` and `h`. Motivated by a
  protocol review.
- Docs: added an explicit assumptions callout, a precise hash-to-scalar
  definition, OR-proof soundness caveat, the `2^n < q` / generator-independence
  range conditions, nonce/side-channel/API-invariant notes, and a normative
  [encoding & transcript specification](https://boyroywax.github.io/sigma-rangeproof/spec/)
  for interoperable implementations.

## 0.1.0

Initial release: dependency-free zero-knowledge range proofs (prove
`value >= threshold` over a Pedersen commitment via a Sigma-protocol bit
decomposition). Hardened verifier (subgroup + canonical-scalar checks),
adversarial + Hypothesis fuzz suites, docs site.
