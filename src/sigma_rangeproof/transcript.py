"""Fiat-Shamir transcript: turns the interactive Sigma protocol non-interactive.

A transcript accumulates labelled public values (group elements, integers,
bytes) and derives challenges by hashing the running state. Prover and verifier
append the *same* values in the *same* order, so they derive identical
challenges without interacting.
"""

from __future__ import annotations

import hashlib

from .group import Params


class Transcript:
    def __init__(self, params: Params, *, domain: bytes = b"sigma-rangeproof:v1") -> None:
        self._params = params
        self._h = hashlib.sha256()
        self._n = params.elem_bytes
        self.append_bytes(b"domain", domain)
        # Bind the group parameters so a proof can't be replayed under others.
        self.append_int(b"p", params.p)
        self.append_int(b"g", params.g)
        self.append_int(b"h", params.h)

    def _absorb(self, label: bytes, data: bytes) -> None:
        self._h.update(len(label).to_bytes(4, "big"))
        self._h.update(label)
        self._h.update(len(data).to_bytes(8, "big"))
        self._h.update(data)

    def append_bytes(self, label: bytes, data: bytes) -> Transcript:
        self._absorb(label, data)
        return self

    def append_int(self, label: bytes, value: int) -> Transcript:
        # Fixed-width big-endian so encodings are unambiguous.
        self._absorb(label, (value % self._params.p).to_bytes(self._n, "big"))
        return self

    def challenge(self, label: bytes) -> int:
        """Derive a challenge scalar in ``[0, q)`` bound to the state so far."""
        self._absorb(b"challenge", label)
        # Two SHA-256 blocks -> 512 bits, reduced mod q, ample for a < 2048-bit q.
        digest = hashlib.sha256(self._h.digest() + b"\x00").digest()
        digest += hashlib.sha256(self._h.digest() + b"\x01").digest()
        return int.from_bytes(digest, "big") % self._params.q
