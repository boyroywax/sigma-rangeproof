# Sigma protocols

A Sigma protocol is a three-message conversation that lets a prover convince a
verifier it knows a secret, without handing the secret over. The name comes from
the shape of the message flow, which people thought looked like the letter. The
three messages are a commitment, a challenge, and a response. Once you have seen
one you have basically seen them all, so start with the canonical example.

## Schnorr: proving you know a discrete log

The prover knows \(x\) and has published \(Y = h^{x}\). It wants to prove it knows
\(x\), revealing nothing about \(x\) itself.

1. **Commitment.** The prover picks a random \(k\) and sends \(a = h^{k}\).
2. **Challenge.** The verifier picks a random \(e\) and sends it back.
3. **Response.** The prover sends \(z = k + e x \bmod q\).

The verifier accepts if

\[
h^{z} \;=\; a \cdot Y^{e}.
\]

Check why that holds for an honest prover: \(h^{z} = h^{k + ex} = h^{k} (h^{x})^{e}
= a Y^{e}\). The equation balances.

Two properties make this a proof rather than a handshake.

**It reveals nothing (honest-verifier zero-knowledge).** Given any challenge
\(e\), you can produce a transcript that passes without knowing \(x\): pick \(z\)
at random, then set \(a = h^{z} Y^{-e}\). The verification equation holds by
construction, and the distribution of \((a, e, z)\) is identical to a real run.
Since a transcript can be conjured from nothing, seeing one teaches nothing.

**It cannot be faked (special soundness).** Suppose a prover can answer two
different challenges \(e\) and \(e'\) for the *same* commitment \(a\), giving
\(z\) and \(z'\). Then \(h^{z} = a Y^{e}\) and \(h^{z'} = a Y^{e'}\). Divide:
\(h^{z - z'} = Y^{e - e'}\), so

\[
x \;=\; (z - z')\,(e - e')^{-1} \bmod q .
\]

The two transcripts hand you the secret. Turned around: a prover who does not know
\(x\) can answer at most one challenge per commitment, so it passes a random
challenge only by luck, with probability \(1/q\). For a 2048-bit group that is
hopeless.

That gap between "can answer two challenges, so knows the secret" and "can answer
one challenge, so might be guessing" is the soundness of every Sigma protocol.
Everything later inherits it.

## Fiat-Shamir: cutting out the verifier

The challenge has to be unpredictable, or the prover would prepare for it and the
soundness argument collapses. In the interactive version the verifier supplies
that unpredictability. The Fiat-Shamir transform replaces the verifier with a
hash function: the prover computes the challenge itself as

\[
e = H(\text{statement}, a),
\]

hashing the public statement and its own commitment. Because \(a\) is fixed before
\(e\) is computed, and because a hash output is unpredictable until you have the
input, the prover cannot grind toward a convenient challenge any more than it
could against a live verifier. The price is that the argument now holds in the
*random-oracle model*, a setup where the hash is treated as an idealized random
function. That is a heuristic, but a load-bearing one used across deployed
cryptography.

The payoff is a proof that is a single message. No back-and-forth, so it can be
written down, stored, and checked later by anyone. In this library the hashing is
handled by a running transcript (see [the code](code.md)); every public value
gets absorbed in a fixed order, and challenges are read out of the accumulated
state, so prover and verifier derive identical challenges without ever talking.

A challenge is a scalar, so the hash output has to be mapped into
\(\mathbb{Z}_q\). Concretely the transcript produces a 512-bit value — two
SHA-256 evaluations over the current state, concatenated — interpreted as a
big-endian integer and reduced mod \(q\):

\[
e \;=\; \big(\text{SHA256}(S \,\|\, \texttt{0x00}) \,\|\,
                \text{SHA256}(S \,\|\, \texttt{0x01})\big) \bmod q .
\]

512 bits is far more challenge entropy than the ~112-bit security target needs
(and, since \(2^{512} < q\), the reduction is injective here, so there is no
modular bias). The exact byte layout of the state \(S\) — field ordering,
domain tag, and encodings — is pinned down in the
[encoding specification](spec.md); two implementations that follow it produce
bit-identical challenges, which is what makes proofs interoperable and
non-malleable.

## OR proofs: one of two, without saying which

Now the move that makes range proofs work. Suppose there are two statements,
\(S_0\) and \(S_1\), and you know a witness for exactly one of them. You want to
prove "\(S_0\) or \(S_1\)" without leaking which one you can actually back up.

The trick, due to Cramer, Damgård, and Schoenmakers, runs both branches at once
but fakes the one you cannot do. Recall from the Schnorr discussion that you can
simulate a transcript for *any* challenge you get to choose in advance. So:

- For the branch you cannot prove, choose its challenge \(e_\text{fake}\) and
  response \(z_\text{fake}\) up front, and back out its commitment
  \(a_\text{fake} = h^{z_\text{fake}} Y_\text{fake}^{-e_\text{fake}}\). This is the
  simulator, run deliberately.
- For the branch you can prove, send an honest commitment \(a_\text{real} = h^{k}\).
- Now obtain the overall challenge \(e = H(\text{statement}, a_0, a_1)\).
- Split it so the two branch challenges are forced to add up:
  \(e_\text{real} = e - e_\text{fake} \bmod q\). Answer the real branch honestly,
  \(z_\text{real} = k + e_\text{real}\,x\).

The proof is \((a_0, a_1, e_0, e_1, z_0, z_1)\). The verifier recomputes \(e\),
checks that \(e_0 + e_1 = e\), and checks the Schnorr equation on both branches.

Why it is sound: the prover fixed \(e_\text{fake}\) before learning \(e\), so it
controls only one of the two branch challenges freely. To cheat both branches it
would need both simulated, which means choosing \(e_0\) and \(e_1\) in advance and
still landing \(e_0 + e_1 = H(\dots)\). That is guessing the hash. So at least one
branch is a genuine Schnorr proof, which means at least one statement is true and
the prover knows its witness.

Why it hides the choice: each branch, real or simulated, is just a valid Schnorr
transcript, and those are identically distributed whether produced honestly or by
the simulator. The verifier sees two well-formed proofs and cannot tell which one
carried a real witness.

!!! warning "Soundness rests on a big challenge space"
    A cheating prover wins a single OR-proof only by guessing the hash output,
    with probability \(1/|\mathcal{E}|\) where \(\mathcal{E}\) is the challenge
    space. Here that is ~\(2^{512}\), so the per-proof cheating probability is
    negligible. A range proof chains \(n\) of these OR-proofs in **one**
    transcript (each bit's challenge is drawn after the previous bits are
    absorbed), so the soundness error grows only linearly in \(n\) — still
    negligible. The thing that must not shrink is the challenge: a truncated or
    biased hash-to-scalar would be the way to quietly break soundness, which is
    why the [encoding spec](spec.md) fixes a 512-bit derivation.

That last sentence about hiding the choice is the whole reason a range proof can
hide a bit. The next page commits to each binary digit of a number and uses this
OR proof to show the digit is 0 or 1, without revealing which.
