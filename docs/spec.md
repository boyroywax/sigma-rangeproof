# Encoding and transcript specification

This page pins down the byte-level details an independent implementation needs to
produce **bit-identical** proofs: how group elements and scalars are encoded, the
exact order in which the transcript absorbs them, and how a challenge is derived
from the hash state. Two implementations that agree on this page interoperate;
two that disagree on any field will compute different challenges and reject each
other's proofs. (That sensitivity is a feature — it is also what makes a proof
non-malleable.)

Everything here is normative and matches `transcript.py` and `rangeproof.py`.

## Group parameters

The default group is the prime-order subgroup of quadratic residues of the
RFC 3526 2048-bit MODP safe prime \(p = 2q + 1\):

| Symbol | Value |
|---|---|
| \(p\) | RFC 3526 group 14 prime (2048 bits) |
| \(q\) | \((p-1)/2\) (prime; the subgroup order) |
| \(g\) | `4` (a quadratic residue, hence a generator of the order-\(q\) subgroup) |
| \(h\) | `sha512("sigma-rangeproof:h:v1" ‖ ctr)² mod p`, smallest `ctr ≥ 0` giving `h > 1` |
| `elem_bytes` | \(\lceil \mathrm{bitlen}(p)/8 \rceil = 256\) |

Group elements are integers in \([1, p)\); scalars are integers in \([0, q)\).

## Field encoding

The transcript is a single running SHA-256. Each value is absorbed as a
**labelled, length-delimited** field:

```text
absorb(label, data):
    sha256.update( len(label) as 4-byte big-endian )
    sha256.update( label )
    sha256.update( len(data)  as 8-byte big-endian )
    sha256.update( data )
```

The length prefixes make the encoding unambiguous: no two distinct sequences of
fields can produce the same byte stream, so there is no concatenation ambiguity.

Two kinds of `data` appear:

- **Group elements and small integers** (`g`, `h`, commitments, `a` values, the
  threshold, the bit count) are encoded as `(value mod p)` in **big-endian over
  exactly `elem_bytes` (256) bytes**. Group elements are already in range; the
  reduction is defensive.
- **The modulus `p`** is encoded as its raw 256-byte big-endian value — *not*
  reduced mod `p`, which would collapse it to zero and leave the modulus unbound.

## Challenge derivation (hash-to-scalar)

A challenge is read from the current transcript state \(S\) after absorbing a
per-challenge label:

```text
challenge(label):
    absorb("challenge", label)            # fold the label into the state S
    d = sha256( S.digest() ‖ 0x00 )       # 32 bytes
      ‖ sha256( S.digest() ‖ 0x01 )       # + 32 bytes  -> 512 bits
    return int_big_endian(d) mod q
```

The 512-bit output is interpreted big-endian and reduced mod \(q\). Because
\(2^{512} < q\), the reduction is injective (no modular bias), and 512 bits is far
more challenge entropy than the security level requires.

## Transcript order for a range proof

To prove `value ≥ threshold` over `bits` bits, the transcript absorbs the
following, **in this exact order**. `C` is the public commitment, \(C_i\) the
per-bit commitments, \((a0_i, a1_i)\) the OR-proof commitments for bit \(i\).

```text
1.  ("domain",    "sigma-rangeproof:v1")
2.  ("p",         p as 256-byte big-endian)
3.  ("g",         g)
4.  ("h",         h)
5.  ("C",         commitment)
6.  ("threshold", threshold)
7.  ("bits",      bits)
8.  ("Ci", C_0), ("Ci", C_1), ..., ("Ci", C_{bits-1})        # in index order
9.  for i in 0 .. bits-1:
        ("a0", a0_i)
        ("a1", a1_i)
        e_i = challenge("bit")            # derived here, after a0_i, a1_i
```

The prover and verifier run steps 1–9 identically; the only difference is that
the prover *chooses* the \(a\) values and the verifier *reads them from the
proof*. Because \(C\), the threshold, the bit count, and every \(C_i\) are folded
in before any challenge is drawn, each challenge \(e_i\) is bound to the whole
statement — the property the [Sigma page](sigma-protocols.md) calls strong
Fiat-Shamir.

## Proof serialization

`RangeProof.to_dict()` produces a JSON-friendly object; integers are Python
`hex()` strings (lower-case, `0x`-prefixed), and `from_dict` parses them back with
`int(s, 16)`.

```json
{
  "bits": 10,
  "commitments": ["0x…", "0x…", "…"],
  "bit_proofs": [
    { "a0": "0x…", "a1": "0x…",
      "e0": "0x…", "e1": "0x…",
      "z0": "0x…", "z1": "0x…" },
    "…"
  ]
}
```

`commitments` and `bit_proofs` each have exactly `bits` entries. The commitment
itself is not part of the proof object — it is the public value the verifier
already holds and passes to `verify_ge` alongside the threshold.

## Verifier obligations

A conforming verifier, given `(commitment, threshold, proof)`:

1. Rejects unless `len(commitments) == len(bit_proofs) == bits` and `bits ≥ 1`.
2. Rejects unless `commitment` and every \(C_i\) and every \(a\) value is in the
   order-\(q\) subgroup (\(x^q \equiv 1 \bmod p\), \(x \neq 0\)).
3. Rejects unless every scalar `e0,e1,z0,z1` is canonical (in \([0, q)\)).
4. Computes \(C' = C \cdot g^{-\text{threshold}} \bmod p\) and rejects unless
   \(\prod_i C_i^{2^i} = C'\).
5. Replays steps 1–9 above and rejects unless every per-bit check holds:
   \(e0_i + e1_i \equiv e_i \pmod q\) and \(h^{z b_i} = a b_i \cdot Y b_i^{\,e b_i}\)
   for both branches, where \(Y0_i = C_i\) and \(Y1_i = C_i \cdot g^{-1}\).

Steps 2 and 3 are what make the proof non-malleable and immune to
out-of-subgroup inputs; see [Security and parameters](security.md#what-verification-enforces-on-an-untrusted-proof).

## Verifier limits

A conforming verifier processing a proof from an untrusted source MUST also
enforce the following bounds before performing any modular exponentiation, so
that hostile input cannot inflate verifier cost:

- `1 ≤ bits ≤ 64`. The default range proof uses `bits = 32`; the cap of 64
  covers every realistic integer threshold and lets the verifier reject an
  oversized proof in constant time.
- `0 ≤ threshold < q`. A threshold outside the scalar range cannot describe
  a meaningful statement; reject without further work.
- Each serialized group element MUST fit in `2 · elem_bytes` hex characters
  (`= 512` for the default group, `+ 2` for the optional `0x` prefix). Each
  serialized scalar MUST fit in `2 · scalar_bytes` hex characters.
- `len(commitments) == len(bit_proofs) == bits`, and each bit-proof entry
  MUST contain exactly the keys `a0`, `a1`, `e0`, `e1`, `z0`, `z1`.

These limits are exposed in the reference implementation as
`sigma_rangeproof.MAX_BITS` and `Params.{elem_bytes, scalar_bytes}`.
