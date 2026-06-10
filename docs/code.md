# Reading the code

Four modules, each matching a layer of the math. Read them in this order and the
earlier pages should snap into code.

```
src/sigma_rangeproof/
  group.py       the group, the two generators, parameter checks
  pedersen.py    the commitment
  transcript.py  Fiat-Shamir hashing
  rangeproof.py  the OR proof and the range proof on top of it
```

## group.py

This holds the arithmetic world everything lives in. The prime `_P_HEX` is the
2048-bit safe prime from RFC 3526, group 14, a constant that has been published
and reused for decades. From it the module derives `q = (p - 1) // 2`, the order
of the subgroup we work in, and picks the two generators.

The first generator is `g = 4`. Four is \(2^2\), so it is a square, which puts it
in the quadratic-residue subgroup; in a safe-prime group that subgroup has prime
order, so any non-identity square generates all of it. The second generator comes
from `_hash_to_subgroup`, which hashes a fixed label and squares the result into
the subgroup. Squaring guarantees membership; hashing guarantees nobody knows its
discrete log relative to `g`. That is the nothing-up-my-sleeve construction the
binding property depends on.

`Params.validate` is a guard against a mistyped constant. The cheap half always
runs: it confirms `q = (p-1)/2` and that both generators actually sit in the
order-`q` subgroup, which is two exponentiations. The expensive half, a
Miller-Rabin primality test on both `p` and `q`, is behind a flag because it is
many exponentiations and only worth paying once. The test suite calls it with the
flag on; import does not. An earlier version ran it on every import and turned a
sub-second import into a 30-second one, which is a small lesson in not doing
heavy work at module load.

`rand_scalar` draws a blinding factor or a nonce uniformly from \([0, q)\) using
the `secrets` module, the standard library's cryptographic random source. Plain
`random` would be a real bug here; nonces and blindings have to be unpredictable.

## pedersen.py

Two functions, both one line of math. `commit(value, blinding)` returns

```python
(pow(g, value, p) * pow(h, blinding, p)) % p
```

which is \(g^v h^r \bmod p\), and the blinding it used, drawing one at random if
you did not supply it. `open_commit` recomputes the commitment from a claimed
value and blinding and checks it matches. Both `value` and `blinding` must lie in
\([0, q)\); rather than silently reducing them mod `q`, `commit` raises, so a
caller that confuses the integer threshold window with the modular exponent gets
an error instead of a commitment to a different number than it meant.

## transcript.py

This is Fiat-Shamir in mechanical form. A `Transcript` wraps a SHA-256 state and
exposes `append_int`, `append_bytes`, and `challenge`. Every value gets absorbed
with its length and a label, so two different sequences of values can never hash
to the same state by accident. Integers are written as fixed-width big-endian
bytes for the same reason: no ambiguity at the boundaries.

The transcript is seeded at construction with a domain string and the group
parameters, so a proof made under one group cannot be replayed under another.
`challenge` reads a scalar in \([0, q)\) out of the current state. Because both
the prover and the verifier append the same values in the same order, they pull
identical challenges without exchanging a message. This object is the difference
between the interactive protocols on the [Sigma page](sigma-protocols.md) and the
single-shot proofs the library actually produces.

## rangeproof.py

The top module, where the OR proof and the range proof live.

`_prove_bit` is the [OR proof](sigma-protocols.md#or-proofs-one-of-two-without-saying-which)
for "this commitment holds a 0 or a 1." It computes the two targets \(Y_0 = C_i\)
and \(Y_1 = C_i / g\), simulates the branch that does not match the real bit by
choosing that branch's challenge and response first and backing out its
commitment, runs an honest Schnorr commitment on the real branch, pulls the
overall challenge from the transcript, and splits it so the two branch challenges
sum to it. The output is the six numbers `a0, a1, e0, e1, z0, z1`.

`_verify_bit` is the mirror. It recomputes the targets, pulls the same challenge,
checks that `e0 + e1` equals it, and checks the Schnorr equation
\(h^{z_b} = a_b Y_b^{e_b}\) on both branches.

`prove_ge(value, blinding, threshold, bits)` assembles the whole thing. It
computes \(w = \text{value} - \text{threshold}\) and refuses, with a `ValueError`,
if \(w\) is negative or does not fit in `bits` bits; there is no valid proof
outside the range and the function will not fabricate one. It chooses the bit
blindings so they recombine to the original blinding, using the
`inv_top = pow(pow(2, bits-1, q), -1, q)` line to solve for the last one. It
commits to each bit, seeds the transcript with the statement and all the bit
commitments, and runs `_prove_bit` for each bit in order.

`verify_ge(commitment, threshold, proof)` does the two checks from the
[range-proof page](range-proof.md): it forms \(C' = C \cdot g^{-T}\), confirms
that \(\prod_i C_i^{2^i}\) reconstructs \(C'\), then verifies every bit proof
against a transcript seeded exactly as the prover seeded it. Both checks have to
pass.

`RangeProof` is a small dataclass with `to_dict` and `from_dict` that turn the
integers into hex strings and back, so a proof serialises straight to JSON for
sending over a wire or storing in a database.

## Where to start poking

If you want to convince yourself it works rather than take the math on faith, the
quickest probe is in `verify_ge`: change the threshold you pass to verification
and watch the product identity fail, because \(C'\) moved. The
[notebook](https://github.com/boyroywax/sigma-rangeproof/blob/main/examples/demo.ipynb)
does this and a few other deliberate failures, which is usually a faster way to
trust a proof system than reading the soundness argument twice.
