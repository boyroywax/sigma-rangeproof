# API reference

Everything you need is importable from the top level.

```python
from sigma_rangeproof import (
    commit, open_commit, prove_ge, verify_ge,
    RangeProof, Params, DEFAULT_PARAMS, MAX_BITS, rand_scalar,
)
```

## commit

```python
commit(value: int, blinding: int | None = None, *, params=DEFAULT_PARAMS) -> tuple[int, int]
```

Returns `(commitment, blinding)`. If `blinding` is omitted, a uniform one is
drawn from `secrets`. The commitment is a group element safe to publish; the
blinding is secret and is needed again to prove anything about the value. Both
`value` and `blinding` must be integers in \([0, q)\); a value that is negative,
`>= q`, or the wrong type raises rather than being silently reduced. For a range
proof, keep `value` a small non-negative integer.

## open_commit

```python
open_commit(commitment: int, value: int, blinding: int, *, params=DEFAULT_PARAMS) -> bool
```

Recomputes the commitment from a claimed opening and reports whether it matches.
Useful for tests and for the holder to check its own bookkeeping; it is not part
of the zero-knowledge flow, since it requires revealing the value.

## prove_ge

```python
prove_ge(value: int, blinding: int, threshold: int, *, bits: int = 32, params=DEFAULT_PARAMS) -> RangeProof
```

Proves the commitment to `(value, blinding)` satisfies `value >= threshold`.
Raises `ValueError` if `value - threshold` is negative or does not fit in `bits`
bits, because no valid proof exists there. It also raises if `bits` exceeds
`MAX_BITS` (64), if `value` or `threshold` falls outside \([0, q)\), or if the
window `2**bits` would reach the subgroup order. Cost and proof size are linear
in `bits`; pick the smallest width covering your values.

## verify_ge

```python
verify_ge(commitment: int, threshold: int, proof: RangeProof, *, params=DEFAULT_PARAMS) -> bool
```

Checks `proof` against the public `commitment` and `threshold`. Returns a plain
bool. A proof made for one threshold will not verify against another, and a proof
will not verify against a commitment it was not made for. Untrusted input is
bounded before any modular arithmetic: a proof declaring more than `MAX_BITS`
(64) bits, or a `threshold` outside \([0, q)\), returns `False` immediately
rather than triggering unbounded work.

## RangeProof

A dataclass holding `bits`, the per-bit `commitments`, and the per-bit
`bit_proofs`.

```python
proof.to_dict() -> dict                                  # hex strings, JSON-ready
RangeProof.from_dict(d: dict, *, params=DEFAULT_PARAMS) -> RangeProof
```

Use these to move a proof across a network or into storage. `from_dict` is a
strict parser built for hostile input: it requires `bits` in `[1, MAX_BITS]`, the
commitment and bit-proof lists to have exactly `bits` entries with the exact
expected keys, and every hex field to be no wider than the canonical
group-element or scalar encoding. Anything else raises `ValueError` before the
proof reaches `verify_ge`.

## Params, DEFAULT_PARAMS, MAX_BITS, rand_scalar

`DEFAULT_PARAMS` is the 2048-bit safe-prime group every call uses unless you pass
your own. `Params` is its frozen dataclass; `Params.validate(check_primality=...)`
runs the structural checks always and the primality test only when asked. Its
`elem_bytes` and `scalar_bytes` properties give the canonical big-endian width of
a group element and a scalar, which the strict deserializer uses to cap field
sizes.

`MAX_BITS` (64) is the largest bit width any proof may declare; `prove_ge`,
`verify_ge`, and `RangeProof.from_dict` all enforce it.

`rand_scalar(params=DEFAULT_PARAMS)` returns a uniform scalar in \([0, q)\), the
same source the library uses internally for blindings and nonces.

## A complete round trip

```python
from sigma_rangeproof import commit, prove_ge, verify_ge, RangeProof
import json

# holder side
score = 740
commitment, blinding = commit(score)        # publish commitment, keep blinding

# prove score >= 700 over a 10-bit range
proof = prove_ge(score, blinding, 700, bits=10)
wire = json.dumps({"commitment": hex(commitment), "proof": proof.to_dict()})

# verifier side
msg = json.loads(wire)
ok = verify_ge(int(msg["commitment"], 16), 700, RangeProof.from_dict(msg["proof"]))
assert ok
```
