# API reference

Everything you need is importable from the top level.

```python
from sigma_rangeproof import (
    commit, open_commit, prove_ge, verify_ge,
    RangeProof, Params, DEFAULT_PARAMS, rand_scalar,
)
```

## commit

```python
commit(value: int, blinding: int | None = None, *, params=DEFAULT_PARAMS) -> tuple[int, int]
```

Returns `(commitment, blinding)`. If `blinding` is omitted, a uniform one is
drawn from `secrets`. The commitment is a group element safe to publish; the
blinding is secret and is needed again to prove anything about the value. `value`
is reduced mod the subgroup order, so keep it a small non-negative integer when
you intend to prove a range over it.

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
bits, because no valid proof exists there. Cost and proof size are linear in
`bits`; pick the smallest width covering your values.

## verify_ge

```python
verify_ge(commitment: int, threshold: int, proof: RangeProof, *, params=DEFAULT_PARAMS) -> bool
```

Checks `proof` against the public `commitment` and `threshold`. Returns a plain
bool. A proof made for one threshold will not verify against another, and a proof
will not verify against a commitment it was not made for.

## RangeProof

A dataclass holding `bits`, the per-bit `commitments`, and the per-bit
`bit_proofs`.

```python
proof.to_dict() -> dict                 # hex strings, JSON-ready
RangeProof.from_dict(d: dict) -> RangeProof
```

Use these to move a proof across a network or into storage.

## Params, DEFAULT_PARAMS, rand_scalar

`DEFAULT_PARAMS` is the 2048-bit safe-prime group every call uses unless you pass
your own. `Params` is its frozen dataclass; `Params.validate(check_primality=...)`
runs the structural checks always and the primality test only when asked.
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
