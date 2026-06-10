# sigma-rangeproof — static security review (self-review)

> **Note:** This is an in-house review performed with an automated static-analysis
> tool, **not** an independent third-party audit. It is recorded here for
> transparency. An external cryptographic audit is still outstanding (tracked in
> [issue #2](https://github.com/boyroywax/sigma-rangeproof/issues/2); see
> [SECURITY.md](../SECURITY.md)).

```text
sigma-rangeproof — static security review (self-review)

Auditor / firm:        GitHub Copilot Coding Agent (automated static review)
Contact:               https://github.com/boyroywax/sigma-rangeproof
Audit dates:           2026-06-10  to  2026-06-10
Commit reviewed:       HEAD of main at time of review (v0.1.1)
Version:               0.1.1
Scope:                 src/sigma_rangeproof/, spec, serialization, CI/supply-chain, docs
Out of scope:          constant-time behavior, prover authentication/freshness,
                       caller-supplied custom groups

Methodology:           [x] design  [x] implementation  [ ] side-channel
                       [ ] differential/interop  [x] fuzzing (review of fuzz suite)
                       [ ] formal

Findings:
  ID    Severity   Title                                              Status
  ----  ---------  -----------------------------------------------    ----------
  F-01  Medium     Unbounded proof size enables verifier DoS          fixed (0.1.2)
  F-02  Medium     Integer-domain invariants not enforced by API      fixed (0.1.2)
  F-03  Low        Docs site loads third-party CDN JavaScript         fixed (0.1.2)
  F-04  Low        CI/release Actions pinned by tag, not commit SHA   fixed (0.1.2)
  F-05  Info       No automated dependency-scanning config present    fixed (0.1.2)
  F-06  Info       No external cryptographic audit completed yet      open

Summary of result:
  Within the scope and limitations above, as of v0.1.1, the reviewed code
  correctly implements the specified construction and is free of issues that
  would allow a computationally bounded adversary to forge a valid proof for a
  false statement or to break commitment hiding/binding under the stated
  assumptions. Two medium-severity hardening gaps (F-01, F-02) and three
  low/info supply-chain items (F-03, F-04, F-05) were recorded. This review was
  conducted by automated static analysis and does not constitute a guarantee of
  security.

Auditor signature:     GitHub Copilot Coding Agent   Date: 2026-06-10
```

## Findings and resolutions

### F-01 — Medium: Unbounded proof size enables verifier denial of service

`verify_ge()` accepted `proof.bits` without an upper bound, and `from_dict()`
parsed arbitrary-length hex into integers, so a hostile proof could force the
verifier into very large amounts of modular arithmetic.

**Resolution (0.1.2):**

- `verify_ge` rejects `bits` outside `[1, MAX_BITS]` (`MAX_BITS = 64`) and a
  `threshold` outside `[0, q)` before any modular exponentiation.
- `RangeProof.from_dict` rejects group-element hex wider than `2·elem_bytes`
  characters and scalar hex wider than `2·scalar_bytes` characters, and
  enforces `len(commitments) == len(bit_proofs) == bits` and the exact set of
  per-bit-proof keys.

### F-02 — Medium: Integer-domain invariants not enforced in public API

`commit()` silently reduced `value % q`, and `prove_ge()` did not enforce
`value < q` / `threshold < q` / `2^bits < q`. Harmless with the default
2048-bit group but a silent integer/modular-confusion hazard under custom
small-group `Params`.

**Resolution (0.1.2):**

- `commit` raises `ValueError` on `value` or `blinding` outside `[0, q)`.
- `prove_ge` raises on `value ≥ q`, `threshold ≥ q`, `bits > MAX_BITS`, or
  `2^bits ≥ q`.

### F-03 — Low: Docs site loads third-party CDN JavaScript

`mkdocs.yml` fetched MathJax from `unpkg.com`.

**Resolution (0.1.2):** MathJax 3 (`tex-mml-chtml.js` + its woff-v2 fonts) is
vendored under `docs/js/mathjax/` and served from the docs origin; the CDN
reference was removed. Upstream license retained at `docs/js/mathjax/LICENSE`.

### F-04 — Low: CI/release Actions pinned by tag, not commit SHA

All third-party Actions used mutable tags (`@v4`, `@release/v1`, …).

**Resolution (0.1.2):** Every third-party Action in `ci.yml`, `release.yml`, and
`docs.yml` is pinned to a full commit SHA with a trailing version comment.

### F-05 — Info: No automated dependency-scanning config present

**Resolution (0.1.2):** Added `.github/dependabot.yml` (GitHub Actions + pip,
including `docs/`) and a `pip-audit` job in CI.

### F-06 — Info: No external cryptographic audit completed

**Status: open.** Tracked in
[issue #2](https://github.com/boyroywax/sigma-rangeproof/issues/2). The
construction is a textbook Sigma-protocol bit-decomposition range proof with no
novel cryptography, and the KAT vectors plus this scope document give an external
auditor a starting point.
