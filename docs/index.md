<p align="center">
  <img src="assets/sigma-rangeproof.svg" alt="sigma-rangeproof" width="128" height="128">
</p>

# sigma-rangeproof

This library does one thing. You commit to a number. Later you convince someone
that the number is at least some threshold, and they come away knowing only
that, not the number.

That sounds like a small trick until you try to build it. The obvious approaches
leak. If you sign the number, the reader sees it. If you hash it, you cannot
prove anything about its size. If you reveal a range like "between 700 and 800,"
you have given away most of what you were trying to hide. What you want is a
proof that is convincing and reveals nothing beyond the single fact you meant to
share. That is what a zero-knowledge proof is, and a range proof is the
particular kind that talks about the size of a hidden number.

## The shape of the thing

Three calls:

```python
from sigma_rangeproof import commit, prove_ge, verify_ge

commitment, blinding = commit(740)
proof = prove_ge(740, blinding, 700, bits=10)
verify_ge(commitment, 700, proof)   # True
```

`commit` hides the number behind a value you can publish. `prove_ge` builds the
proof that the hidden number is at least the threshold. `verify_ge` checks it.
Nobody who sees the commitment, the threshold, and the proof can recover the
number, or even tell how far over the line it sits.

## What these docs cover

The code is short, under three hundred lines, and most of it is one idea applied
in layers. These pages build that idea up so the code reads as obvious by the
time you get to it.

- [The math you need](background.md) sets up finite cyclic groups, the discrete
  logarithm problem, and Pedersen commitments. If you have seen a Diffie-Hellman
  key exchange you already have the instincts; this fills in the rest.
- [Sigma protocols](sigma-protocols.md) is the engine room: Schnorr's proof of
  knowledge, the Fiat-Shamir transform that makes it non-interactive, and the OR
  trick that lets you prove one of two things without saying which.
- [From bits to a range proof](range-proof.md) assembles those pieces. The idea
  is almost silly once you see it: a number is in range exactly when its binary
  digits are all genuinely digits, so prove each bit is a bit.
- [Reading the code](code.md) walks the four modules against the math, so you can
  see where each equation lives.
- [Security and parameters](security.md) is the part to read before trusting it
  with anything: what it assumes, what the 2048-bit prime buys you, and the ways
  to hold it wrong.
- [API reference](api.md) is the short version for when you just need the
  signatures.

There is also a runnable notebook, `examples/demo.ipynb`, that exercises the
whole surface including the cases that are supposed to fail.

## What it does not do

It is not a general proof system. It proves one statement, a lower bound on a
committed integer, and the closely related upper bound that falls out of the
same construction. It is not aggregated or succinct in the Bulletproofs or SNARK
sense; the proof grows linearly with the bit width. And it has not been audited.
The construction is standard and the tests are pointed, but those are not the
same as a third party trying to break it.
