# Related work and alternatives

This page situates `sigma-rangeproof` among the other zero-knowledge options
reachable from Python, so the design choice is visible rather than assumed. The
honest summary: the pure-Python ZK ecosystem is **thin**. Most of what exists
falls into one of three buckets — primitive libraries you build on, research code,
or Python bindings over a Rust/C proving system. A small, dependency-free library
that does exactly one proof is an unusual niche, which is the gap this package
fills.

!!! note
    The ZK ecosystem moves quickly and packages come and go. Treat the specifics
    below as a starting map, not a current inventory — check maintenance status
    and security posture yourself before depending on anything.

## Direct alternatives for range proofs

- **[zkbp](https://pypi.org/project/zkbp/)** (JPMorgan Chase). Python bindings
  over a Rust implementation on the **BN254** pairing curve; offers Sigma
  protocols and Bulletproof-style range proofs, and pairs with their PADL ledger
  kit. Faster and more compact than a pure-Python O(n) proof, and EVM-adjacent.
  Caveats: it ships a compiled dependency, is labelled "research code … not for
  production," and BN254's security was revised down to roughly 100 bits after
  improved tower-number-field-sieve attacks (2016), which is why newer work
  prefers BLS12-381. Reach for it (or arkworks directly) if you need aggregated,
  log-size proofs at volume or on-chain verification.

- **[zksk](https://github.com/spring-epfl/zksk)** + **[petlib](https://github.com/gdanezis/petlib)**.
  An academic "Zero-Knowledge Swiss Knife" for *composing* Sigma protocols
  (discrete-log representations, AND/OR), built on petlib's OpenSSL-backed
  elliptic-curve arithmetic. Closest in spirit to this library's building blocks,
  but it is a toolkit for assembling proofs rather than a packaged range proof,
  depends on OpenSSL bindings, and is lightly maintained.

- **Bulletproofs ports.** Several pure-Python Bulletproofs implementations exist
  on GitHub as references; as of writing none is a maintained, packaged PyPI
  dependency. The reference implementations everyone actually uses are in Rust —
  `dalek-cryptography/bulletproofs` (over ristretto255) and the arkworks stack —
  reached from Python only through custom bindings or WASM.

## Building blocks (not proof systems)

These give you the group arithmetic to build Sigma protocols on, but no proof on
their own:

- **[py_ecc](https://github.com/ethereum/py_ecc)** (Ethereum Foundation) — pure
  Python BN254/BLS12-381 with pairings; correct but slow, used as a reference.
- **petlib**, **[fastecdsa](https://pypi.org/project/fastecdsa/)**,
  **[coincurve](https://pypi.org/project/coincurve/)** — elliptic-curve / secp256k1
  primitives (the latter two are native-backed and fast).
- **[noknow](https://pypi.org/project/noknow/)** — a Schnorr-style NIZK for
  *authentication* (prove you know a secret), not range proofs; mentioned because
  it is often the first hit when searching "python zero knowledge."

## Heavier proof systems with Python bindings

When the statement is an arbitrary computation rather than "a number is in a
range," you move to general-purpose SNARK/STARK systems. These are powerful and
production-grade, but they bring a circuit compiler and a native toolchain:

- **[pysnark](https://github.com/meilof/pysnark)** — write Python, get a zk-SNARK
  over an arithmetic circuit (libsnark / snarkjs backends). Research-grade.
- **[ezkl](https://pypi.org/project/ezkl/)** — halo2-based proving of computations
  and ML inference (zkML), Rust under Python bindings.
- **[Cairo](https://www.cairo-lang.org/) / starknet.py** — the STARK ecosystem;
  prove a Cairo program, verify on StarkNet.

Most of the serious options above are ultimately a Python skin over the same few
Rust crates — **arkworks**, **dalek** (curve25519/ristretto, Bulletproofs), and
**Merlin** transcripts. This library deliberately uses none of them: its
[transcript](spec.md) is a simpler SHA-256 analog of Merlin, and its group is a
prime field so that Python's C-accelerated `pow` does the heavy lifting and no
native build is needed.

## Where this library sits

`sigma-rangeproof` trades the things the native systems are good at — small
proofs, aggregation, raw speed, general circuits — for a narrow set of
properties they mostly cannot offer together:

- **Zero dependencies, pure Python, no build step** — installs and vendors
  anywhere, no wheels per platform, trivial to read end to end.
- **One job, done plainly** — prove `value ≥ threshold` over a Pedersen
  commitment, with a [normative spec](spec.md) and [published test
  vectors](audit.md#known-answer-vectors).
- **Auditable by a single person in a sitting**, which is the whole point for a
  threshold-gate use case where a bug should degrade gracefully rather than be
  catastrophic.

If your constraints are "server-side, occasional, small ranges, no native
dependency, easy to audit," this is the right tool. If they are "huge volume,
tiny proofs, or on-chain," one of the Rust-backed options above is, and this page
is your pointer to them.
