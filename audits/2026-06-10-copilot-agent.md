# sigma-rangeproof — Static Security Review

```
sigma-rangeproof — external audit sign-off

Auditor / firm:        GitHub Copilot Coding Agent (automated static review)
Contact:               https://github.com/boyroywax/sigma-rangeproof
Audit dates:           2026-06-10  to  2026-06-10
Commit reviewed:       HEAD of main at time of review (v0.1.1)
Version:               0.1.1
Scope:                 src/sigma_rangeproof/, spec, serialization, CI/supply-chain, docs
Out of scope:          constant-time behavior (documented limitation), prover
                       authentication/freshness, caller-supplied custom groups

Methodology:           [x] design  [x] implementation  [ ] side-channel
                       [ ] differential/interop  [x] fuzzing (review of fuzz suite)
                       [ ] formal

Findings:
  ID    Severity   Title                                              Status
  ----  ---------  -----------------------------------------------    ----------
  F-01  Medium     Unbounded proof size enables verifier DoS          open
  F-02  Medium     Integer-domain invariants not enforced by API      open
  F-03  Low        Docs site loads third-party CDN JavaScript         open
  F-04  Low        CI/release Actions pinned by tag, not commit SHA   open
  F-05  Info       No automated dependency-scanning config present    open
  F-06  Info       No external cryptographic audit completed yet      open

Summary of result:
  Within the scope and limitations above, as of v0.1.1, the reviewed code
  correctly implements the specified construction and is free of issues that
  would allow a computationally bounded adversary to forge a valid proof for a
  false statement or to break commitment hiding/binding under the stated
  assumptions. However, two medium-severity hardening gaps (F-01, F-02)
  should be addressed before the library is used in high-assurance settings.
  This review was conducted by automated static analysis and does not
  constitute a guarantee of security.

Auditor signature:     GitHub Copilot Coding Agent   Date: 2026-06-10
```

---

## 1  Scope and methodology

The review covered the full repository contents at v0.1.1:

| Area | Files examined |
|---|---|
| Library core | `src/sigma_rangeproof/{group,pedersen,transcript,rangeproof}.py` |
| Public API | `src/sigma_rangeproof/__init__.py` |
| Tests | `tests/test_rangeproof.py`, `test_adversarial.py`, `test_fuzz.py`, `test_kat.py`, `vectors/kat.json` |
| Specification | `docs/spec.md`, `docs/security.md`, `docs/range-proof.md`, `docs/sigma-protocols.md` |
| Packaging | `pyproject.toml`, `docs/requirements.txt` |
| CI/release | `.github/workflows/ci.yml`, `release.yml`, `docs.yml`, `.gitlab-ci.yml` |
| Security policy | `SECURITY.md` |

Methodology: full read of every source and test file, manual tracing of the prover/verifier data flow, review of the transcript binding (Fiat-Shamir strong-binding check), review of input validation and serialization, and review of the supply-chain/CI configuration. The fuzz and adversarial test suites were also inspected (not run end-to-end by this automated agent).

---

## 2  Positive findings

The following properties were **confirmed correct** by this review.

### 2.1  Group parameters

- The prime `p` matches RFC 3526 MODP Group 14 (`group.py` constant `_P_HEX`).
- `q = (p-1)/2` is derived correctly; `Params.validate()` asserts this structurally and optionally via Miller-Rabin.
- `g = 4 = 2²` is a quadratic residue and thus a generator of the prime-order subgroup.
- `h` is derived as `sha512("sigma-rangeproof:h:v1" ‖ ctr)² mod p`, the smallest `ctr ≥ 0` yielding `h > 1`. The label is fixed and public, so no one knows `log_g(h)`.
- `DEFAULT_PARAMS.validate()` runs at import time; the test suite additionally calls `validate(check_primality=True)`.

### 2.2  Commitment scheme

- Pedersen: `Com(v, r) = g^v · h^r mod p`. Perfectly hiding (uniform blinding from `secrets.randbelow(q)`), computationally binding under DL.
- Values and blindings are reduced mod `q` before exponentiation — no silently-wrong result from large inputs at the exponent level.

### 2.3  Fiat-Shamir transcript binding

- The transcript absorbs domain label, `p` as **raw bytes** (not reduced mod `p`), `g`, `h`, the public commitment, threshold, bit count, and all bit commitments **before** any challenge is derived.
- The raw-bytes fix for `p` landed in 0.1.1; the CHANGELOG records the prior bug (absorbing `p mod p = 0`) as a wire-format change. This is a "Frozen Heart"-category fix and the code now correctly implements strong Fiat-Shamir.
- Challenge derivation (two SHA-256 outputs concatenated, reduced mod `q`) produces 512 bits of entropy, far exceeding the 112-bit security level.

### 2.4  OR-proof correctness

- `_prove_bit`: the OR (CDS) proof structure is correct — one branch honest-simulated with a uniformly random nonce `k`, the other branch fake-simulated as `(e_fake, z_fake)` where `a_fake = h^z_fake · Y_fake^{-e_fake}`.
- `_verify_bit`: checks `(e0 + e1) ≡ e (mod q)` and both branch equations `h^z_b ≡ a_b · Y_b^{e_b}`.

### 2.5  Verifier input validation

- Every untrusted group element (commitment, bit commitments, `a0`/`a1` values) is validated with `in_subgroup()` — `pow(x, q, p) == 1`.
- Every scalar (`e0`, `e1`, `z0`, `z1`) is validated with `is_canonical_scalar()` — `0 <= x < q`. This closes the scalar-malleability channel.
- These checks happen before any expensive algebra.

### 2.6  Randomness source

- All secret randomness (`rand_scalar`, nonces, simulated challenges/responses) uses `secrets.randbelow(q)`. This is a cryptographically secure source on all supported Python versions (≥ 3.9).

### 2.7  Serialization

- `to_dict()` / `from_dict()` round-trip faithfully through hex strings.
- The verifier recomputes `bits`, lengths, and subgroup/scalar checks from the deserialized proof.
- KAT vectors in `tests/vectors/kat.json` freeze the exact encoding.

### 2.8  Test coverage

- Adversarial suite: scalar+`q` mutation, challenge shift, negative scalar, out-of-subgroup commitment, non-bit value, below-threshold value, negative inputs.
- Fuzz suite (Hypothesis): round-trip, below-threshold always raises, wrong threshold rejected, scalar tamper rejected, commitment tamper rejected, wrong commitment rejected.
- KAT suite: group params, `h` derivation, Pedersen, transcript challenge, verify accept/reject on frozen vectors.

---

## 3  Findings

### F-01 — Medium: Unbounded proof size enables verifier denial of service

**Location:** `src/sigma_rangeproof/rangeproof.py:173–203` and `from_dict()` at lines 120-126.

**Description:** `verify_ge()` accepts `proof.bits` from the untrusted proof object without an upper bound. Verification cost includes:
- `bits` subgroup membership checks (`pow(x, q, p)`)
- element recombination `pow(C_i, 1 << i, p)` — the exponent doubles each step, so the exponent reaches `2^(bits-1)`, which is a valid scalar in `[0, q)` for small `bits` but means the work is proportional to `i` modular squarings per step
- `bits` OR-proof checks, each 4 modexps

A malicious proof with `bits = 10000` (or any large integer) would cause the verifier to perform an enormous amount of work before returning `False`. Additionally, `from_dict()` converts arbitrary-length hex strings for group elements and scalars without checking their byte width, so adversarial inputs can pass in integers hundreds of kibibytes long.

**Impact:** CPU exhaustion / memory pressure on a service that verifies untrusted proofs.

**Recommendation:**
1. Reject `bits > MAX_BITS` (a sensible cap is 64; the default is 32).
2. In `from_dict()`, reject group elements wider than `params.elem_bytes` bytes and scalars wider than `ceil(q.bit_length()/8)` bytes.
3. Optionally limit the total number of commitments/bit_proofs parsed.

---

### F-02 — Medium: Integer-domain invariants not enforced in public API

**Location:** `src/sigma_rangeproof/pedersen.py:11-22`, `rangeproof.py:138-151`.

**Description:** `commit(value, ...)` silently reduces `value % q`, and `prove_ge()` does not enforce `value < q` or `threshold < q`. With default params this is astronomically unlikely to be relevant (`q ≈ 2^{2047}`), but:
- custom `Params` with a smaller group (e.g. for testing) could cause actual integer vs. modular confusion
- the proof window `[threshold, threshold + 2^bits)` is described in integer terms but the underlying algebra is modular; if `threshold >= q` the proof silently covers a different window than the user expects

The documented invariant in `docs/range-proof.md` ("the committed value must be `< q`") is correct but is not enforced.

**Recommendation:** Add explicit guards at the top of `prove_ge`:
```python
if value >= params.q or threshold >= params.q:
    raise ValueError("value and threshold must be < q")
if 1 << bits >= params.q:
    raise ValueError("2^bits must be < q")
```

---

### F-03 — Low: Docs site loads third-party CDN JavaScript

**Location:** `mkdocs.yml:52`.

```yaml
extra_javascript:
  - https://unpkg.com/mathjax@3/es5/tex-mml-chtml.js
```

**Description:** The documentation site fetches MathJax from `unpkg.com`. This is a minor supply-chain risk for docs visitors.

**Recommendation:** Vendor MathJax into `docs/js/` and serve it from the same origin as the docs site, or add a Subresource Integrity hash.

---

### F-04 — Low: CI/release Actions pinned by major tag, not commit SHA

**Location:** `.github/workflows/ci.yml`, `release.yml`, `docs.yml`.

**Description:** All third-party GitHub Actions are pinned by mutable tags (`@v4`, `@v5`, `@v2`, `@release/v1`), not by immutable commit SHAs. If any upstream action's tag is force-pushed or the account is compromised, the release pipeline could be hijacked.

**Recommendation:** Pin each action to a full commit SHA, e.g.:
```yaml
uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2
```
Use a tool such as [pin-github-actions](https://github.com/mheap/pin-github-actions) to automate this.

---

### F-05 — Info: No automated dependency-scanning config present

**Description:** No Dependabot configuration (`.github/dependabot.yml`) and no automated `pip-audit`, `safety`, or OSV scan job are present in the GitHub Actions config.

**Recommendation:** Add at minimum a Dependabot config for GitHub Actions and pip, and a `pip-audit` or OSV scanner step in the CI pipeline.

---

### F-06 — Info: No external cryptographic audit completed

**Description:** As clearly stated in `SECURITY.md` and `docs/audit.md`, no third party has reviewed the construction or the code.

**Recommendation:** Commission a professional cryptographic audit before any high-assurance production deployment. The repo's audit scope doc and KAT vectors give an auditor an excellent starting point.

---

## 4  Known documented limitations (out of scope for this review)

These are acknowledged in `SECURITY.md` and are **not** findings:

| Limitation | Notes |
|---|---|
| Not constant-time | Python `pow` timing depends on secret exponents. Caller responsibility. |
| No prover authentication | Proofs are replayable unless caller binds to session/nonce. Documented. |
| Caller-supplied groups trusted | Custom `Params.h` must have no known DL to `g`. Documented. |
| Upper bound is real | A `≥ T` proof is also a `< T + 2^bits` proof. Documented. |

---

## 5  Summary

The core cryptographic construction is correctly implemented. The Fiat-Shamir transcript is properly bound (including the v0.1.1 fix for the unbound modulus), the OR proofs are structurally correct, the verifier performs all required subgroup and canonical-scalar checks, and randomness comes from `secrets`. The two medium findings (F-01, F-02) are hardening gaps in input validation that do not break the cryptographic soundness or zero-knowledge properties of the default-parameter construction but should be fixed before the library is exposed to untrusted prover inputs in a service context.
