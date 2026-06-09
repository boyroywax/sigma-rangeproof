# sigma-rangeproof

A small, **dependency-free** zero-knowledge range proof for Python: prove that a
Pedersen-committed value satisfies `value ≥ threshold` **without revealing the
value**. Built from a Sigma-protocol bit decomposition with Fiat-Shamir, so it's
non-interactive, needs **no trusted setup**, and has **no native dependencies**
(pure Python + the standard library).

```python
from sigma_rangeproof import commit, prove_ge, verify_ge

# Prover commits to a secret value and publishes the commitment.
commitment, blinding = commit(740)          # keep `blinding` secret

# Prover makes a proof that the committed value is at least 700.
proof = prove_ge(740, blinding, 700, bits=10)

# Anyone with the public commitment can verify — learning only the boolean.
assert verify_ge(commitment, 700, proof)    # True
assert not verify_ge(commitment, 720, proof)  # a proof for ≥700 is not one for ≥720
```

## How it works

A Pedersen commitment `C = g^v · h^r` (over the prime-order subgroup of a
2048-bit safe prime) perfectly hides `v` and is computationally binding. To prove
`v ≥ T`:

1. The verifier can compute `C' = C · g^(−T) = g^(v−T)·h^r` itself.
2. The prover bit-decomposes `w = v − T = Σ bᵢ·2ⁱ`, commits to each bit
   `Cᵢ = g^(bᵢ)·h^(rᵢ)` (with the `rᵢ` chosen so `Π Cᵢ^(2ⁱ) = C'`), and attaches
   a Fiat-Shamir **OR-proof** that each `Cᵢ` opens to 0 or 1.
3. The verifier checks the product identity and every bit proof.

Proving each bit is in `{0,1}` over `bits` bits proves `w ∈ [0, 2^bits)`, i.e.
`T ≤ v < T + 2^bits`. Soundness rests on the discrete-log assumption plus
Fiat-Shamir (random-oracle model).

## API

| Function | Purpose |
|---|---|
| `commit(value, blinding=None) -> (commitment, blinding)` | Pedersen commitment; random blinding if omitted. |
| `prove_ge(value, blinding, threshold, *, bits=32) -> RangeProof` | Prove `value ≥ threshold`. Raises `ValueError` if `value − threshold ∉ [0, 2^bits)`. |
| `verify_ge(commitment, threshold, proof, *) -> bool` | Verify against the public commitment. |
| `RangeProof.to_dict()` / `from_dict()` | JSON-friendly (de)serialization (hex strings). |

Pick `bits` to bound the largest value you'll prove: `bits=10` covers `[0, 1024)`.
Proof size and prove/verify cost are **O(bits)**.

## Performance

Cost is `O(bits)` modular exponentiations over a 2048-bit modulus. On a native
CPython build a `bits=10` prove/verify is on the order of tens of milliseconds.
(An x86 interpreter under Rosetta is ~100× slower at big-int modexp — build/run
natively for realistic numbers.)

## Trade-offs vs Bulletproofs

Both prove the same statement over a Pedersen commitment with no trusted setup.
This proof is **O(n)** in proof size (n = bits) where Bulletproofs are
**O(log n)** and aggregatable — but it is far simpler to implement and audit, and
for small ranges (e.g. a 10-bit score) the size difference is negligible.

## Status

Alpha. The cryptography is standard and tested (correctness + soundness +
serialization, plus a Miller-Rabin check that the bundled prime is a safe prime),
but it has **not had an independent audit**. Review before relying on it for
high-value secrets.

## License

MIT.
