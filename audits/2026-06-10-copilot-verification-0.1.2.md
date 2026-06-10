# sigma-rangeproof — Full Cryptographic Security Audit (verification re-audit)

> Produced by running the 11-step procedure in
> [`audits/llm-audit-prompt.md`](llm-audit-prompt.md) against the working tree
> after the 0.1.2 hardening changes. This is an in-house review with an
> automated agent, **not** an independent third-party audit. An external
> cryptographic audit remains outstanding (issue
> [#2](https://github.com/boyroywax/sigma-rangeproof/issues/2)).

```text
sigma-rangeproof — external audit sign-off

Auditor / firm:        GitHub Copilot (Claude) — automated agent audit
Contact:               https://github.com/boyroywax/sigma-rangeproof
Audit dates:           2026-06-10  to  2026-06-10
Commit reviewed:       db21ceb (v0.1.1) + working-tree 0.1.2 hardening changes
Version:               0.1.2 (in preparation)
Scope:                 src/sigma_rangeproof/, spec, serialization, CI/supply-chain, docs
Out of scope:          constant-time behavior, prover authentication/freshness,
                       caller-supplied custom groups

Methodology:           [x] design  [x] implementation  [ ] side-channel
                       [ ] differential/interop  [x] fuzzing (ran the suite)
                       [ ] formal

Findings:
  ID    Severity   Title                                              Status
  ----  ---------  -----------------------------------------------    ----------
  F-01  Medium     Unbounded proof size enables verifier DoS          fixed (verified)
  F-02  Medium     Integer-domain invariants not enforced by API      fixed (verified)
  F-03  Low        Docs site loads third-party CDN JavaScript         fixed (verified)
  F-04  Low        CI/release Actions pinned by tag, not commit SHA   fixed (verified)
  F-05  Info       No automated dependency-scanning config present    fixed (verified)
  F-06  Info       No external cryptographic audit completed yet      open (tracked, #2)
  G-01  Info       ci.yml has no explicit least-privilege permissions fixed
  G-02  Info       GitLab CI base image pinned by tag, not digest     open

Summary of result:
  Within the scope and limitations above, the reviewed code (v0.1.1 plus the
  0.1.2 hardening changes) correctly implements the specified construction and
  is free of issues that would allow a computationally bounded adversary to
  forge a valid proof for a false statement or to break commitment
  hiding/binding under the stated assumptions. All six findings from the
  2026-06-10 static review (F-01..F-06) are resolved except F-06 (external
  audit), which is now tracked. Two new informational supply-chain
  observations (G-01, G-02) are recorded. This review was conducted by an
  automated agent and does not constitute a guarantee of security.

Auditor signature:     GitHub Copilot (Claude)   Date: 2026-06-10
```

---

## Methodology

The 11-step procedure in `audits/llm-audit-prompt.md` was executed in order:

- **STEP 0** — environment & gates. `ruff check .` clean; the full `pytest`
  suite passes (59 passed) and `HYPOTHESIS_PROFILE=ci pytest tests/test_fuzz.py`
  passes (7 passed). No pre-existing failures.
- **STEPS 1–7** — an empirical harness re-derived and checked every numeric and
  structural claim (group constant vs. RFC 3526, subgroup membership, `h`
  reproduction, transcript binding, OR-proof equations, the blinding identity,
  verifier checks, and serialization bounds). Every check returned PASS.
- **STEP 8** — test-suite completeness reviewed against the prompt's checklist.
- **STEPS 9–10** — packaging, both CI systems, and the documentation security
  claims reviewed by reading the manifests/workflows and the docs.

All computational results in this report are reproducible from
`tests/vectors/kat.json` and the test suite.

---

## Positive findings (confirmed correct)

### Group & parameters (group.py)
- `_P_HEX` equals the authoritative RFC 3526 MODP Group 14 prime byte-for-byte.
- `q = (p-1)/2`; `g = 4` is a QR (`g^q ≡ 1`) and `g ≠ 1`.
- `h = sha512("sigma-rangeproof:h:v1" ‖ ctr)² mod p` reproduces the value in
  `kat.json`; `h^q ≡ 1`, `h ≠ 1`; the nothing-up-my-sleeve label means no party
  knows `log_g(h)`.
- `Params.validate()` rejects a wrong `q` and `g = 1`; primality is gated behind
  `check_primality` and exercised in the suite.
- `rand_scalar` uses `secrets.randbelow(q)` — uniform on `[0, q)`, no modular
  bias.

### Pedersen commitments (pedersen.py)
- `Com(v, r) = g^v · h^r mod p` computed exactly.
- **0.1.2 change:** `commit` now raises on `value`/`blinding` outside `[0, q)`
  (negative, `≥ q`) and on non-int types; `blinding = 0` is still accepted.
  `open_commit` returns `False` for out-of-range openings rather than raising.

### Transcript & Fiat-Shamir (transcript.py)
- Strong-binding confirmed: the constructor absorbs `domain, p, g, h` and
  `_seed` absorbs `C, threshold, bits` and every `C_i` **before** any challenge.
- `p` is absorbed as raw fixed-width bytes (`p.to_bytes(elem_bytes)`), not via
  `append_int` (the v0.1.1 Frozen-Heart-class fix); confirmed still present.
- Length-delimited `_absorb` (4-byte label-len ‖ label ‖ 8-byte data-len ‖ data)
  is unambiguous.
- Challenge is 512 bits reduced mod `q`; `2^512 < q` (`q` is 2047-bit), so the
  reduction is injective — no challenge bias. KAT challenge reproduced exactly.
- `prove_ge` and `verify_ge` each build a fresh `Transcript(p)`; none is shared.

### OR-proof (_prove_bit / _verify_bit)
- Fake-branch simulation `a_fake = h^{z_fake} · Y_fake^{-e_fake}` and honest
  branch `a_real = h^k`, `z_real = k + e_real·r_i (mod q)` match the standard CDS
  disjunction; the `bit == 1` real branch uses `Y_1 = c_i · g^{-1}`.
- `_verify_bit` checks `a0, a1 ∈ subgroup`, all four scalars canonical, the
  challenge split `e0 + e1 ≡ e (mod q)`, and both verification equations.
- Empirically: honest bit-0 and bit-1 proofs verify; a forged proof for a
  commitment to `2` is rejected.

### Range proof (prove_ge / verify_ge)
- The top bit blinding is solved so `Σ 2^i·r_i ≡ blinding (mod q)`; empirically
  `Π C_i^{2^i} ≡ C·g^{-threshold}`.
- **0.1.2 change:** `prove_ge` enforces `bits ≤ MAX_BITS (=64)`, `value < q`,
  `threshold < q`, and `2^bits < q`, in addition to the existing
  non-negativity and in-range checks.
- `verify_ge` validates subgroup membership of `C` and all `C_i`, computes
  `C' = C·g^{-threshold}` (now without a redundant `threshold % q`), checks the
  product identity, then every per-bit proof.

---

## Findings

### F-01 — Medium → **fixed (verified)**: unbounded proof size / verifier DoS
**Location:** `rangeproof.py` `verify_ge`, `RangeProof.from_dict`.
Resolved in 0.1.2:
- `verify_ge` rejects `bits ∉ [1, MAX_BITS]` and `threshold ∉ [0, q)` before any
  modular exponentiation. Verified: a proof with `bits = 100000` is rejected
  immediately.
- `from_dict` rejects group-element hex wider than `2·elem_bytes` and scalar hex
  wider than `2·scalar_bytes` characters, and enforces
  `len(commitments) == len(bit_proofs) == bits` and the exact per-bit key set.
  Verified: a 20 KB hex element and a length mismatch both raise `ValueError`.

### F-02 — Medium → **fixed (verified)**: integer-domain invariants
**Location:** `pedersen.py` `commit`, `rangeproof.py` `prove_ge`.
Resolved in 0.1.2 (see Pedersen / range-proof notes above). Verified: `commit`
and `prove_ge` reject `value ≥ q`, `threshold ≥ q`, negatives, and
`2^bits ≥ q`. The silent `value % q` reduction is gone.

### F-03 — Low → **fixed (verified)**: third-party CDN JavaScript
**Location:** `mkdocs.yml`. MathJax (`tex-mml-chtml.js` + woff-v2 fonts) is
vendored under `docs/js/mathjax/` with its upstream `LICENSE`; the `unpkg.com`
reference is removed. A strict `mkdocs build` succeeds and the built site
references only same-origin `js/mathjax/tex-mml-chtml.js` (no `unpkg`/CDN URLs).

### F-04 — Low → **fixed (verified)**: Actions pinned by tag
**Location:** `.github/workflows/{ci,release,docs}.yml`. Every third-party Action
is now pinned to a full commit SHA with a trailing version comment
(`actions/checkout@34e1148…  # v4.3.1`, `setup-python@a26af69…  # v5.6.0`,
`upload-artifact@ea165f8…  # v4.6.2`, `upload-pages-artifact@56afc60…  # v3.0.1`,
`deploy-pages@d6db901…  # v4.0.5`, `pypa/gh-action-pypi-publish@cef2210…
# v1.14.0`, `softprops/action-gh-release@3bb1273…  # v2.6.2`).

### F-05 — Info → **fixed (verified)**: dependency scanning
`.github/dependabot.yml` added (github-actions + pip for `/` and `/docs`), and a
`pip-audit` job runs in CI over `docs/requirements.txt`. The library itself
declares zero runtime dependencies.

### F-06 — Info → **open (tracked)**: no external cryptographic audit
No third party has reviewed the construction. Tracked in issue
[#2](https://github.com/boyroywax/sigma-rangeproof/issues/2); `SECURITY.md` and
`docs/audit.md` link it. The textbook construction, normative spec, and KAT
vectors give an external auditor a strong starting point.

### G-01 — Info (new) → **fixed**: `ci.yml` lacks an explicit least-privilege `permissions`
**Location:** `.github/workflows/ci.yml`.
`docs.yml` and `release.yml` already declared minimal scopes; `ci.yml` relied on
the repository/organization default token scope. Resolved by adding
`permissions: { contents: read }` at the top of `ci.yml`.

### G-02 — Info (new): GitLab CI base image pinned by tag, not digest
**Location:** `.gitlab-ci.yml` (`image: python:3.12-slim`, etc.).
The mirror's pipeline pulls Docker images by mutable tag. This is the same class
of risk as F-04 for the GitLab side. **Recommendation:** pin the base images by
digest (`python:3.12-slim@sha256:…`) if the GitLab pipeline is part of the trust
boundary. Low priority — GitHub Actions is the primary release path (PyPI
Trusted Publishing).

---

## Test-suite completeness (STEP 8)

The adversarial suite covers `z + q`, challenge shift (`e0 += q`, `e1 -= q`),
negative scalar, out-of-subgroup commitment / bit-commitment / `a` value,
commitment to a non-bit, below-threshold, and negative inputs. The 0.1.2 work
added oversized-`bits`, oversized-hex (element and scalar), length-mismatch,
missing-key, `value ≥ q`, `threshold ≥ q`, and `commit` range-guard tests. The
fuzz suite covers in-range round-trip, below-threshold raises, negative value
raises, wrong threshold rejects, scalar/commitment tamper rejects, and wrong
outer commitment rejects. KAT vectors lock the group, `h`, Pedersen, the
transcript challenge, and accept/reject decisions. `bits = 1` is exercised via
the parametrised edge cases and fuzz lower bound; `threshold = 0` is covered.

**Minor suggestion (non-blocking):** add an explicit positive test at
`bits = MAX_BITS` to lock the upper boundary as accepted, complementing the
`bits = MAX_BITS + 1` rejection test.

---

## Documentation claims (STEP 10)

- `docs/spec.md` transcript order, challenge derivation, and verifier
  obligations match `transcript.py` / `rangeproof.py`; the new "Verifier limits"
  section documents `MAX_BITS` and the byte-width caps.
- `SECURITY.md` accurately lists the limitations (not constant-time, no prover
  auth/freshness, custom groups trusted, real upper bound) and now references the
  self-review and audit-tracking issue.
- The ~112-bit security claim for the 2048-bit safe-prime group is consistent
  with the best known GNFS estimates and is stated as a floor, not a guarantee.
- No documentation claim was found to be contradicted by the code.

---

## Known limitations (out of scope, treatment confirmed)

| Limitation | Confirmed treatment |
|---|---|
| Not constant-time | Documented in `SECURITY.md`/`docs/security.md`; Python `pow` timing depends on secret exponents — caller responsibility. |
| No prover authentication/freshness | Documented; proofs are replayable verbatim unless the caller binds session/nonce. |
| Caller-supplied custom groups trusted | Documented; custom `Params.h` must have no known dlog to `g`. The 0.1.2 integer guards additionally reduce small-group confusion. |
| Real upper bound | Documented; a `≥ T` proof is also a `< T + 2^bits` proof. |

---

## Verdict

The cryptographic core is correctly implemented and the v0.1.1 → 0.1.2 changes
close both medium findings and all three low/info supply-chain items from the
prior static review without altering the wire format (existing proofs and the
KAT vectors still verify). Remaining items are informational: commission an
external audit (F-06, tracked), make `ci.yml` permissions explicit (G-01), and
optionally digest-pin the GitLab CI image (G-02). No soundness,
zero-knowledge, hiding, or binding issue was identified within scope.
