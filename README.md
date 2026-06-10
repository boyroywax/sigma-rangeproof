<p align="center">
  <img src="https://raw.githubusercontent.com/boyroywax/sigma-rangeproof/main/docs/assets/sigma-rangeproof-128.png" alt="sigma-rangeproof" width="128" height="128">
</p>

# sigma-rangeproof

Prove that a number you committed to is at least some threshold, without saying
what the number is. The whole thing is pure Python with nothing outside the
standard library.

A typical use: you hold a score and you publish a commitment to it. Later you
want to convince someone the score clears a bar (say 700 out of 1000) but you
don't want to hand over the score itself, or anything that would let them work
it out. This library produces a proof of exactly that statement and nothing
more.

```python
from sigma_rangeproof import commit, prove_ge, verify_ge

commitment, blinding = commit(740)            # publish commitment, keep blinding
proof = prove_ge(740, blinding, 700, bits=10) # "the committed value is >= 700"

verify_ge(commitment, 700, proof)   # True
verify_ge(commitment, 720, proof)   # False: a proof for >=700 is not one for >=720
```

The verifier learns one bit of information: whether the claim holds. The score,
and how far above or below the bar it sits, stay hidden.

## Install

Not on PyPI yet. For now, install from a checkout:

```bash
pip install -e .
```

Python 3.9 or newer. No compiled extensions, no C library to find at build time.

## The three calls

`commit(value, blinding=None)` returns `(commitment, blinding)`. If you don't
pass a blinding factor one is drawn at random. Keep it next to the value; you
need both to produce a proof later. The commitment is safe to publish.

`prove_ge(value, blinding, threshold, *, bits=32)` returns a `RangeProof`. It
proves `value >= threshold`. The catch worth knowing up front: the proof only
covers the window `[threshold, threshold + 2**bits)`. If `value - threshold`
falls outside `[0, 2**bits)` the call raises `ValueError`, because a value below
the threshold has no valid proof and the library will not pretend otherwise.

`verify_ge(commitment, threshold, proof)` returns a bool. It recomputes
everything it needs from the public commitment and the threshold you pass, so a
proof made for one threshold will not check out against a different one.

A `RangeProof` serialises with `to_dict()` and rebuilds with
`RangeProof.from_dict(...)`. The dictionary holds hex strings, so it drops
straight into JSON.

## Choosing `bits`

`bits` sets the width of the range you can prove and, with it, the size and cost
of the proof. Both grow linearly in `bits`. Pick the smallest width that covers
your values:

- a percentage or a 0-1000 score fits in `bits=10` (covers 0 through 1023)
- a 16-bit counter fits in `bits=16`
- leave the default `bits=32` if you have no reason to narrow it

The prover and verifier have to agree on `bits`; it travels inside the proof, so
the verifier reads it from there.

## Speed, honestly

The work is `bits` modular exponentiations on each side, over a 2048-bit modulus.
On a normally built CPython that lands in the low tens of milliseconds for
`bits=10`. One trap to flag: an x86 Python running under Rosetta on Apple
silicon does big-integer math something like a hundred times slower, so the same
call can take seconds there. Build and run natively before you judge the
numbers.

## How it works, in one paragraph

The commitment is a Pedersen commitment, `C = g^v * h^r`, over the prime-order
subgroup of a 2048-bit safe prime. To show `v >= T`, note the verifier can form
`C / g^T = g^(v-T) * h^r` by itself. Write `w = v - T` in binary, commit to each
bit, and arrange the bit blindings so the bit commitments multiply back to
`C / g^T`. Then attach, for every bit, a short proof that it is a commitment to
0 or to 1 (a Schnorr OR-proof made non-interactive with Fiat-Shamir). If each of
the `bits` bits is genuinely 0 or 1, then `w` lies in `[0, 2**bits)`, which is
the range claim. Security rests on the discrete logarithm assumption and the
random-oracle heuristic; there is no trusted setup.

The longer version, with the math worked out and the code walked through line by
line, is in [`docs/`](docs/). There is also a runnable notebook at
[`examples/demo.ipynb`](examples/demo.ipynb).

## Why not Bulletproofs

Bulletproofs prove the same kind of statement with a proof that grows like
`log(bits)` instead of `bits`, and several proofs can be folded into one. That
matters when you are proving 64-bit amounts or batching thousands of proofs.
None of the maintained Bulletproofs code targets Python, and the inner-product
argument behind it is genuinely fiddly to get right. For a ten-bit score the
size gap is a few dozen group elements, so the simpler construction here is the
better trade. If your ranges or volumes grow, reach for a Bulletproofs library
in Rust — the [related-work page](https://boyroywax.github.io/sigma-rangeproof/related-work/)
surveys the Python ZK options (zkbp, zksk, py_ecc, pysnark, ezkl, …) and when to
pick each.

## A word on trust

The construction is textbook and the test suite is adversarial: alongside the
happy path it checks that out-of-range values cannot be proved, that proofs do
not transfer across thresholds or commitments, that bit positions cannot be
reordered, that out-of-subgroup elements are rejected, and that proofs are
non-malleable (a scalar shifted by the group order no longer verifies). On top of
the fixed cases there is a property-based fuzz suite (Hypothesis) that asserts the
same invariants over thousands of randomized inputs; run it hard with
`HYPOTHESIS_PROFILE=ci pytest tests/test_fuzz.py`. What it has not had is an
external audit. Read it before you put real secrets behind it. It is short on
purpose, partly so you can.

## License

MIT.
