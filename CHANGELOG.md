# Changelog

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
