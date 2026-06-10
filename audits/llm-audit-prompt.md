# LLM Agent Prompt — Full Cryptographic Security Audit of sigma-rangeproof

## How to use this file

Paste the **System context** and **Task** sections below verbatim into a
Claude Code (or equivalent) session that has been given read access to the
repository root. The agent should have the ability to run shell commands,
read files, and write a report file. Supply the target commit SHA where
indicated.

---

## System context (set as system prompt or prepend to the first message)

```
You are an expert cryptography engineer and security auditor with deep
knowledge of:
- Zero-knowledge proofs (Sigma protocols, Schnorr proofs, OR-proofs, range proofs)
- Pedersen commitments and the discrete-logarithm assumption
- Fiat-Shamir transform, random-oracle security, Frozen Heart attacks
- Safe-prime groups (subgroup structure, subgroup-membership checks)
- Non-malleability, canonical encodings, and proof replay
- Python cryptography implementation hazards
- Supply-chain security for Python packages and GitHub Actions workflows

You are thorough, precise, and adversarial in your thinking. When reviewing
code you simultaneously ask "how could this be broken?" and "is this
correctly proven?". You do not skip sections, you do not accept "documented
limitation" as an excuse without checking whether the limitation is
exploitable in the current surface area, and you trace every data flow from
the untrusted boundary to the final accept/reject decision.
```

---

## Task (send as the first user message)

```
You are performing a full external security audit of the `sigma-rangeproof`
Python library (version 0.1.1).  The repository is already checked out for
you.  Work through every step below, in order.  Do not skip any step.
After completing all steps, write your full audit report as
`audits/YYYY-MM-DD-<your-agent-slug>.md` following the sign-off template
in `docs/audit.md`.

─────────────────────────────────────────────────────────────────────────────
STEP 0 — Environment setup
─────────────────────────────────────────────────────────────────────────────

0a. Print the current HEAD commit SHA.
0b. Install the package and its dev dependencies:
      pip install -e ".[dev]"
0c. Run the full test suite and record the result:
      pytest -q
      HYPOTHESIS_PROFILE=ci pytest -q tests/test_fuzz.py
0d. Run the linter:
      ruff check .
Paste the full output of 0b-0d at the top of your working notes.  A
pre-existing test failure is a finding; note it and continue.

─────────────────────────────────────────────────────────────────────────────
STEP 1 — Group and parameters (group.py)
─────────────────────────────────────────────────────────────────────────────

1a. Cross-check the _P_HEX constant against the authoritative RFC 3526 Group 14
    value (you can find it at https://www.rfc-editor.org/rfc/rfc3526#section-3
    or reproduce it from first principles).  Do they match byte-for-byte?

1b. Verify the subgroup structure:
    - Is q = (p-1)/2 exactly?
    - Is g = 4 a quadratic residue mod p?  (check pow(4, q, p) == 1)
    - Is g != 1?

1c. Verify the h derivation:
    - Reproduce the derivation from the label "sigma-rangeproof:h:v1"
      using the algorithm in _hash_to_subgroup.
    - Confirm the result matches the h stored in kat.json.
    - Confirm pow(h, q, p) == 1 and h != 1.
    - Is there any credible way to know log_g(h)?

1d. Review Params.validate():
    - Does it catch every structural anomaly?
    - Is the subgroup check sufficient — or could a non-residue element
      of order q slip through on a group where q is not prime?
    - Is the Miller-Rabin witness pool adequate for a 2048-bit prime?

1e. Review rand_scalar():
    - Is secrets.randbelow(q) uniform over [0, q)?
    - Is there a modular-bias risk?

─────────────────────────────────────────────────────────────────────────────
STEP 2 — Pedersen commitments (pedersen.py)
─────────────────────────────────────────────────────────────────────────────

2a. Confirm Com(v, r) = g^v * h^r mod p is computed exactly as stated.
2b. Is the blinding uniformly distributed from [0, q)?
2c. What happens if blinding is passed as 0?  As a negative integer?
    As a value >= q?  Trace through commit() for each case.
2d. Is perfect hiding preserved in each case above?
2e. Does open_commit provide any security guarantee?  Under what conditions
    could it return True for the wrong (value, blinding) pair?
2f. Does the commit API prevent value < 0 or value >= q?  What does a caller
    see if they commit to a negative value, then call prove_ge?

─────────────────────────────────────────────────────────────────────────────
STEP 3 — Transcript and Fiat-Shamir binding (transcript.py)
─────────────────────────────────────────────────────────────────────────────

3a. Reproduce the transcript challenge from the KAT vector in kat.json.
    Do you get the same integer?

3b. Frozen Heart check — does the transcript absorb ALL of the following
    before the first challenge is derived?
    - domain label
    - p (the modulus)
    - g and h
    - the public commitment C
    - threshold
    - bits
    - every bit commitment C_i
    If any of these is missing, it is a critical soundness issue.

3c. How is p absorbed?  Is it as its raw byte value, or is it reduced mod p
    (which would produce zero)?  The CHANGELOG records a bug here; confirm
    the fix is present and correct.

3d. Is the length-delimited encoding in _absorb() free of concatenation
    ambiguity?  (Two distinct field sequences must not produce the same
    byte stream.)

3e. Hash-to-scalar bias: the challenge is a 512-bit integer reduced mod q.
    Is 2^512 < q?  If not, there is modular bias; if yes, the reduction is
    injective.  Verify by comparing bit lengths.

3f. Could a Transcript be reused across two calls to prove_ge / verify_ge?
    Trace the construction sites in rangeproof.py; each call must create a
    fresh Transcript and must never share one.

─────────────────────────────────────────────────────────────────────────────
STEP 4 — OR-proof correctness (_prove_bit, _verify_bit)
─────────────────────────────────────────────────────────────────────────────

4a. Simulate the fake branch on paper:
    a_fake = h^z_fake * Y_fake^{-e_fake}
    Check this equals what _prove_bit produces.

4b. Honest branch:
    a_real = h^k
    z_real = k + e_real * r_i  (all mod q)
    Verify the verification equation holds:
    h^{z_real} == a_real * Y_real^{e_real}

4c. Special soundness: if a cheating prover answers the same commitment a_real
    with two different challenges e and e', can you extract the witness?
    Confirm the extractor is r_i = (z - z') / (e - e') mod q.

4d. HVZK simulatability: describe how to simulate a bit proof without
    knowing r_i (pick e0, z0 at random, back out a0; similarly for the other
    branch).  Does the current code exactly match this simulation?

4e. In _prove_bit, what is the "real" branch for bit == 1?  Confirm
    Y_1 = c_i / g, not Y_0.

4f. In _verify_bit, does the verifier check that a0 and a1 are in the subgroup?
    What happens if an adversary supplies out-of-subgroup a values?

─────────────────────────────────────────────────────────────────────────────
STEP 5 — Range proof prover (prove_ge)
─────────────────────────────────────────────────────────────────────────────

5a. Verify the blinding-factor identity:
    sum(2^i * r_i for i in range(bits)) ≡ blinding (mod q)
    Confirm the code constructs r[bits-1] to satisfy this.

5b. Is the modular inverse pow(2^{bits-1}, -1, q) always defined?
    What if q is not prime, or 2^{bits-1} = 0 mod q?
    (For q from a safe prime and small bits this is trivially fine, but check
    the general case for custom Params.)

5c. Bit decomposition: confirm w = value - threshold is decomposed correctly
    as bits from LSB to MSB, and that commit(bit_vals[i], r[i]) uses the
    right blinding for each bit.

5d. Does the prover verify that the commitment it computed matches the one
    it intends to prove about?  (i.e., does it call commit(value, blinding)
    and check the result against an externally supplied commitment?)
    What are the consequences if a caller passes a commitment that does not
    match (value, blinding)?

5e. Input range checks:
    - Is value < q enforced?  If not, what happens for value = q+1?
    - Is threshold < q enforced?
    - Is 2^bits < q enforced?
    Attempt to construct a scenario where missing checks lead to a verifiable
    proof for a statement the prover should not be able to make.

─────────────────────────────────────────────────────────────────────────────
STEP 6 — Range proof verifier (verify_ge)
─────────────────────────────────────────────────────────────────────────────

6a. Subgroup checks:
    - Is the outer commitment validated?
    - Are all bit commitments validated?
    - Are all a0/a1 values validated?
    Are any of these checks missing or reachable only if a prior check passes?

6b. Scalar canonicality:
    - Are all e0, e1, z0, z1 values checked to lie in [0, q)?
    - Can a malleated proof (z += q) still verify?

6c. Product identity:
    prod(C_i^{2^i}) == C' = C * g^{-threshold}
    Confirm the code computes this correctly.
    What if threshold = 0?  What if threshold is very large (close to q)?

6d. Transcript replay:
    Confirm the verifier seeds the transcript with the same values as the
    prover, in the same order, before reading challenges.

6e. Is there a length / size check on the proof before expensive computation?
    Can an attacker send bits = 100000 to cause a DoS?
    Suggest a maximum.

6f. Denial-of-service surface:
    In from_dict(), are oversized hex strings accepted without validation?
    How many bytes of work does a maximally adversarial proof cause?

─────────────────────────────────────────────────────────────────────────────
STEP 7 — Serialization (to_dict / from_dict)
─────────────────────────────────────────────────────────────────────────────

7a. Is the encoding canonical?  (Does every valid proof have exactly one
    serialized form?)
7b. Is from_dict injective?  Could two different dicts decode to the same
    proof?
7c. What happens if from_dict receives extra keys?  Missing keys?  A bits
    value that disagrees with the length of the commitment list?  Test these
    edge cases.
7d. Are the hex strings validated to be non-negative before int(s, 16) is
    called?  (Python's int(..., 16) accepts negative values with a leading
    minus; what does the verifier do with them?)
7e. Replay protection: could a valid proof be replayed byte-for-byte against
    a different commitment or threshold?  (This is by-design, but confirm
    what the spec says and that the code matches.)

─────────────────────────────────────────────────────────────────────────────
STEP 8 — Test suite completeness
─────────────────────────────────────────────────────────────────────────────

8a. Run every test file and confirm all pass on the commit under review.
8b. Do the adversarial tests in test_adversarial.py cover:
    - z + q scalar mutation?
    - challenge shift (e0 += q, e1 -= q)?
    - negative scalar?
    - out-of-subgroup commitment?
    - out-of-subgroup bit commitment?
    - out-of-subgroup a value?
    - commitment to a non-bit value?
    - value below threshold?
    - negative inputs?
    Are any of these missing?

8c. Do the fuzz tests exercise:
    - any value in range always verifies?
    - any value below threshold always raises?
    - negative value always raises?
    - any other threshold always rejects?
    - scalar tamper always rejects?
    - commitment tamper always rejects?
    - wrong outer commitment always rejects?

8d. Is there a test for bits = 1 (single-bit proof)?
    Is there a test for the maximum bits value you plan to allow?
    Is there a test with threshold = 0?

8e. Does the test suite cover from_dict with malformed / adversarial input?

─────────────────────────────────────────────────────────────────────────────
STEP 9 — Packaging and supply-chain
─────────────────────────────────────────────────────────────────────────────

9a. Review pyproject.toml:
    - Are runtime dependencies declared?  (Expected: none.)
    - Are dev/test dependencies range-pinned or fully pinned?
    - Is the package metadata accurate?

9b. Review docs/requirements.txt:
    - Are docs dependencies pinned to exact versions?
    - Are there any dependencies with known CVEs at those versions?
      (Check https://osv.dev or https://pypi.org/project/<name>/<version>/#history)

9c. Review .github/workflows/ci.yml, release.yml, docs.yml:
    - Are all third-party Actions pinned by full commit SHA?
    - Are pip install commands version-constrained?
    - Is the release workflow protected by a test gate?
    - Does the PyPI publish step use Trusted Publishing (OIDC) or a stored token?
    - Are workflow permissions minimally scoped (least-privilege)?

9d. Is there a Dependabot or Renovate configuration?

9e. Is there automated dependency vulnerability scanning (pip-audit, safety,
    osv-scanner) in CI?

─────────────────────────────────────────────────────────────────────────────
STEP 10 — Documentation security claims
─────────────────────────────────────────────────────────────────────────────

10a. Does docs/spec.md accurately reflect the implementation?
     Check: field order in the transcript, challenge derivation formula,
     verifier obligations.

10b. Does SECURITY.md accurately list all known limitations?

10c. Is the 112-bit security level claim accurate for a 2048-bit safe-prime
     group given the best known GNFS attacks?

10d. Are there any security claims in the documentation that are
     contradicted by the code?

─────────────────────────────────────────────────────────────────────────────
STEP 11 — Write your audit report
─────────────────────────────────────────────────────────────────────────────

Using the sign-off template from docs/audit.md, write a complete audit report
as a markdown file.  Save it to:

  audits/YYYY-MM-DD-<your-agent-slug>.md

The report must include:

- The filled-in sign-off block at the top.
- A methodology section summarising what you did.
- A positive-findings section for everything that is correctly implemented.
- A findings section for every issue found, with:
    ID, severity (critical/high/medium/low/info), title, location (file:line),
    description, impact, and a concrete recommendation.
- A "known limitations" section repeating what is out of scope and confirming
  the code's treatment matches the documented claims.
- A summary verdict.

Do not omit sections.  Do not mark findings as "out of scope" unless they
are explicitly listed in the scope exclusions in the sign-off block.

After writing the file, print its path and a one-paragraph executive summary.
```

---

## Notes for the operator

- The prompt above assumes the agent has shell (`bash`) access to run tests.
  If the environment is read-only, remove STEP 0 items 0b-0d and rely on
  the checked-in test results / KAT vectors instead.
- For a deeper side-channel review (not covered above), supplement with:
  > "Trace every code path in prove_ge and verify_ge that branches on or
  > iterates over a secret value.  For each, describe the observable
  > timing or memory side-channel and its exploitability."
- To extend to a differential / interop review, add:
  > "Write a second independent Python implementation of the verifier from
  > the spec in docs/spec.md only (do not read the library code).  Run it
  > against every KAT vector and all proofs your re-implementation generates."
- For a formal methods extension, add:
  > "Encode the transcript binding, OR-proof correctness, and product
  > identity in a tool of your choice (e.g. tamarin-prover pseudocode or
  > a manual reduction to the DL assumption) and identify any step that
  > is not tightly reducible."
