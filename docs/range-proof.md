# From bits to a range proof

Here is the idea the whole library turns on. A number sits in the range
\([0, 2^{n})\) if and only if it has an \(n\)-bit binary expansion whose digits are
all genuinely 0 or 1. So if you can commit to each digit and prove each one is a
real bit, and tie the digits back to the number, you have proved the number is in
range. No inequality reasoning, just bits.

## Reducing "greater or equal" to "in a range"

The public statement is \(v \ge T\): the value inside commitment \(C = g^{v} h^{r}\)
is at least the threshold \(T\). Turn it into a range statement using the
homomorphism from the [background](background.md). The verifier computes, on its
own, from public data:

\[
C' \;=\; C \cdot g^{-T} \;=\; g^{\,v - T}\, h^{r}.
\]

Write \(w = v - T\). Then \(C'\) is a commitment to \(w\) with the same blinding
\(r\). Proving \(w \in [0, 2^{n})\) proves \(0 \le v - T < 2^{n}\), that is,

\[
T \le v < T + 2^{n}.
\]

The lower bound is the claim you wanted. The upper bound comes along for free; it
is the price of working with a fixed bit width, and it is why you choose \(n\)
(the `bits` argument) to cover the largest value you will ever prove.

## Committing to the bits

Write \(w\) in binary, \(w = \sum_{i=0}^{n-1} b_i 2^{i}\), and commit to each bit
separately:

\[
C_i \;=\; g^{b_i}\, h^{r_i}.
\]

The blinding factors \(r_i\) are not arbitrary. Choose them so that they reproduce
the original blinding when weighted by place value:

\[
\sum_{i=0}^{n-1} 2^{i} r_i \;\equiv\; r \pmod q .
\]

You get this for free by picking \(r_0, \dots, r_{n-2}\) at random and solving the
last one:

\[
r_{n-1} \;=\; \Big(r - \sum_{i=0}^{n-2} 2^{i} r_i\Big)\,(2^{n-1})^{-1} \bmod q .
\]

Why that constraint? Multiply the bit commitments together with place-value
weights and watch the homomorphism work:

\[
\prod_{i=0}^{n-1} C_i^{\,2^{i}}
   \;=\; g^{\sum_i b_i 2^{i}}\; h^{\sum_i r_i 2^{i}}
   \;=\; g^{\,w}\, h^{\,r}
   \;=\; C'.
\]

The bit commitments, recombined, land exactly on \(C'\). That single equation is
the seam that stitches the bits to the committed value. The verifier can check it
using only public commitments, so it confirms the bits really are the bits of the
number inside \(C\), without learning the number.

## Proving each commitment holds a bit

The product check ties the \(C_i\) to \(w\), but on its own it does not stop a
cheating prover from using "bits" like 2 or \(-5\) that happen to sum to \(w\).
That is the job of a per-bit proof: each \(C_i\) must open to 0 or 1.

Look at what \(C_i\) is for each case. If \(b_i = 0\), then \(C_i = h^{r_i}\). If
\(b_i = 1\), then \(C_i = g \cdot h^{r_i}\), so \(C_i / g = h^{r_i}\). In both
cases there is some element that equals \(h^{r_i}\): either \(C_i\) itself or
\(C_i/g\). Set

\[
Y_0 = C_i, \qquad Y_1 = C_i / g .
\]

The statement "\(C_i\) commits to a bit" is exactly "\(Y_0 = h^{r_i}\) or
\(Y_1 = h^{r_i}\)", an OR of two discrete-log statements that share the base
\(h\) and the same witness \(r_i\). That is precisely the
[OR proof](sigma-protocols.md#or-proofs-one-of-two-without-saying-which) from the
previous page. The prover knows which case is real, proves that branch honestly,
simulates the other, and the verifier cannot tell which was which. So the bit is
shown to be 0 or 1 without revealing its value.

## Putting it together

The full proof is: the bit commitments \(C_0, \dots, C_{n-1}\), and one OR proof
per bit. Verification is two checks.

1. **The product identity** \(\prod_i C_i^{2^i} = C'\). This binds the bits to the
   committed value and to the threshold (since \(C'\) depends on \(T\)). It is why
   a proof built for one threshold fails against another: change \(T\) and the
   verifier forms a different \(C'\), which the same bit commitments no longer
   reproduce.
2. **Every bit proof.** Each \(C_i\) opens to 0 or 1.

If both pass, soundness chains together cleanly. Binding says each \(C_i\) opens
to a unique value. The bit proofs say that value is 0 or 1. The product identity,
combined with binding on \(C'\), says \(\sum_i b_i 2^i = w \bmod q\). Since each
\(b_i \in \{0,1\}\) the sum is a real integer in \([0, 2^{n})\), and because both
it and \(w\) sit well below \(q\) there is no wraparound, so the equality holds
over the integers. Therefore \(w \in [0, 2^{n})\), which is the range claim.

Zero-knowledge chains together just as cleanly. The bit commitments are perfectly
hiding, so they leak nothing about the bits. Each OR proof is simulatable, so it
leaks nothing about which branch was real. A simulator can assemble a transcript
indistinguishable from a real proof, which is the formal way of saying the
verifier learns only the one fact: the value clears the threshold.

## What it costs

A proof carries \(n\) bit commitments and \(n\) OR proofs, each a fixed handful of
group elements, so its size is linear in \(n\). Proving and verifying are each on
the order of \(n\) exponentiations. For a score in \([0, 1000]\) you set \(n = 10\)
and the whole thing is a few dozen group elements and a few dozen
exponentiations. That linear growth is the trade against Bulletproofs, which
compress the same statement to logarithmic size at the cost of much harder code.
For small ranges the trade is firmly in favor of the simple version.
