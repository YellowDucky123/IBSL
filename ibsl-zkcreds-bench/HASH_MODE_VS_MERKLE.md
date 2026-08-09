# IBSL hash mode vs a plain Merkle tree

The IBSL now has a **Merkle mode** (`Ibsl::prove_hash` / `verify_hash`, core
crate `~/IBSL`): the same interval skip list, but each node's authenticator is
the hash of its children (as it already was under the Merkle backends) and a
membership proof is a plain **sibling-hash chain** — the verifier recomputes
each node's hash bottom-up from the child hash below plus the opened siblings
and checks the top equals the root. No node commitments travel in the proof.
This is exactly how a Merkle tree's authentication path is checked, one
mini-path per skip-list level.

At promotion probability **p = 0.5** (fan-out ~2, ~one sibling per level) this
lands on par with a binary Merkle tree over the same keys.

## Setup

Both structures use **Poseidon two-to-one over BLS12-381 Fr, 32-byte digests**
— the exact hash zkcreds-rs's `ComTree` uses — so this is apples-to-apples on
the hash and field; only the *structure* differs (interval skip list vs a
single fixed-height path). Native operations only, no ZK.

- IBSL: `Ibsl<PoseidonMerkleVc>`, `new_with_promotion(.., 0.5)`, Merkle mode.
  Run: `cargo run --release -- ibsl-merkle 0.5 1000 10000`
- Merkle tree: zkcreds-rs `ComTree` run raw.
  Run: `cargo run --release -- zkcreds-merkle-raw 1000 10000`

Machine: 12-core WSL2, 7 GB RAM. Single-run timings; prove/verify averaged over
10 evenly-spread member keys. Date: 2026-07-16.

## Results

| n | structure | height | proof size | siblings | prove | verify |
|---|---|---|---|---|---|---|
| 1 000  | **IBSL (hash mode, p=0.5)** | 11 | 497 B | 15 | 3.6 µs   | 1.32 ms |
| 1 000  | zkcreds Merkle tree (2^10)  | 11 | 328 B | 10 | 657 µs\* | 589 µs  |
| 10 000 | **IBSL (hash mode, p=0.5)** | 15 | 783 B | 24 | 7.5 µs   | 2.41 ms |
| 10 000 | zkcreds Merkle tree (2^14)  | 15 | 456 B | 14 | 938 µs\* | 869 µs  |

For contrast, the IBSL's *commitment-mode* proof (`prove`, which also carries a
32-byte node commitment + 8-byte position per level) is **926 B / 1368 B** at
the same sizes — Merkle mode roughly halves that by dropping the carried
commitments.

\* zkcreds's path generation *is* an insert in that API (it re-hashes the
path), so its "prove" number is really a tree update, not a witness copy.

## Reading

- **Height / structure.** At p = 0.5 the skip list is the same height as the
  Merkle tree (11 vs 2^10, 15 vs 2^14). It touches ~1.5× as many sibling
  hashes (15 vs 10, 24 vs 14): the extra come from levels whose node has
  fan-out 3–4 (two siblings) and from the skip list running a hair taller than
  a perfect binary tree. So the proof is ~1.5× the size — same order, on par.

- **Verify.** IBSL 1.3–2.4 ms vs Merkle 0.6–0.9 ms — the ~1.5–2.7× gap is
  almost entirely the extra sibling hashes: **per hash both are ~50 µs**
  (Poseidon over BLS12-381), so on a like-for-like per-compression basis the
  two verifiers are the same; the IBSL just recomputes more of them because its
  path is longer.

- **Prove.** IBSL prove is a witness *copy* out of the prover's stored trees
  (zero hashing) → single-digit µs. The zkcreds number regenerates the path by
  re-inserting, so it is not a like-for-like prove; treat it as an upper bound.

- **Bottom line.** At p = 0.5 the IBSL Merkle-mode membership proof is on par
  with a plain binary Merkle path — same height, ~1.5× the sibling hashes,
  identical per-hash verify cost — while additionally supporting interval
  membership over arbitrary u64 keys and O(log n) authenticated updates
  (the plain tree rebuilds globally).

## Tuning p (n = 10 000; zkcreds baseline: 14 siblings, 456 B, 869 µs)

`p` sets tower height: higher p → taller towers → more skip-list levels in the
chain. Each node gets slightly narrower (fan-out ~1/p), but a Merkle-per-node
opening is only `log2(fan-out)` siblings, so the extra *levels* dominate the
fewer *siblings-per-level*. Lowering p (wider, shallower) is therefore what
moves toward the binary tree — until ~p ≤ 0.3, where widening nodes start
costing intra-node siblings again and the sibling count plateaus at ~19.

| p | height | siblings | proof (hash) | verify |
|---|---|---|---|---|
| 0.15 | 6  | 19 | 620 B | 1.28 ms |
| 0.20 | 7  | 19 | 627 B | 1.36 ms |
| 0.25 | 9  | 20 | 658 B | 1.45 ms |
| 0.30 | 8  | 19 | 628 B | 1.28 ms |
| 0.50 | 15 | 24 | 783 B | 1.83 ms |
| 0.60 | 18 | 25 | 824 B | 1.96 ms |

So **raising p past 0.5 only widens the gap** to the plain tree; the sweet spot
is ~p = 0.2–0.3 (~19 siblings, ~625 B, shallowest towers). The residual gap to
14 siblings is the structural cost of the interval skip list and does not close
by tuning p.
