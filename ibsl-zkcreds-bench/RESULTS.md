# IBSL vs zkcreds-rs — benchmark results

> **Newer numbers:** [`BENCHMARKS_2026-07-17.md`](BENCHMARKS_2026-07-17.md) is a
> full re-run of every benchmark at n=1000 and n=10000 in one sequential pass.
> Note the p=0.5 KZG rows there come out 1–2 levels taller than §3/§4 below, so
> the two sets are **not directly comparable at p=0.5** — see its
> "Reproducibility" section. The p=0.15 rows reproduce exactly.
> How to run any of this: [`HOW_TO_RUN.md`](HOW_TO_RUN.md).

Machine: 12-core WSL2, 7 GB RAM. Single-run timings (prove/verify averaged
over a few iterations where noted in the harness). Date: 2026-07-14.

Three proof systems appear below:

- **STARK** — IBSL's own compiler (`~/IBSL`, Winterfell, Rescue hash over
  f128, ~96-bit conjectured, transparent — no trusted setup).
- **Groth16 / BLS12-381** — zkcreds-rs's `TreeMembershipProver` circuit
  (Poseidon two-to-one hash), driven through linkg16, the Groth16
  implementation zkcreds-rs uses. ~128-bit. Per-circuit trusted setup.
- **Groth16 / MNT6-298** — the same linkg16 Groth16, over the outer curve
  of the MNT4-298/MNT6-298 cycle, verifying IBSL-KZG's pairing-based
  opening chain in-circuit. ~80-bit (cycle limitation). Per-shape trusted
  setup.

## 1. Merkle tree vs Merkle tree ("test the merkle tree with the merkle tree in this repo")

Plain Merkle membership, ZK-proved — IBSL repo's STARK path circuit vs
zkcreds-rs's Groth16 tree circuit, at matched capacities:

| capacity | zkcreds Groth16 (Poseidon): prove | verify | proof | CRS gen | IBSL-repo STARK (Rescue): prove | verify | proof |
|---|---|---|---|---|---|---|---|
| 2^10 (~n=1000) | 359 ms | 1.86 ms | 192 B | 388 ms | 5.2 ms | 320 µs | 19,129 B |
| 2^14 (~n=10000) | 484 ms | 1.91 ms | 192 B | 562 ms | 5.0 ms | 281 µs | 19,711 B |
| 2^17 (~n=100000) | 568 ms | 1.97 ms | 192 B | 649 ms | 8.3 ms | 242 µs | 22,238 B |
| 2^31 (zkcreds default) | 1.01 s | 1.92 ms | 192 B | 1.41 s | — | — | — |

zkcreds Groth16 constraint counts: 15,276 (h=11) / 21,128 (h=15) /
25,517 (h=18) / 45,999 (h=32).

Reading: the STARK prover is ~70-100x faster and needs no trusted setup;
Groth16's proof is ~100x smaller (192 B constant) and its verifier checks a
few pairings regardless of tree size. Hashes differ by necessity (each
system uses its circuit-friendly hash: Rescue in the AIR, Poseidon in
R1CS), so this is a systems comparison, not a hash comparison.

## 2. IBSL chain vs plain path, inside each proof system

IBSL membership (chain of per-level openings) vs a single Merkle path, at
n = 1000 / 10000 / 100000 (from `~/IBSL/bench_results.md`, fresh run):

**STARK (Rescue, f128):**

| n | IBSL chain: prove | proof | verify | plain path: prove | proof | verify |
|---|---|---|---|---|---|---|
| 1000 | 11.3 ms | 22,687 B | 317 µs | 5.2 ms | 19,129 B | 320 µs |
| 10000 | 23.8 ms | 28,800 B | 429 µs | 5.0 ms | 19,711 B | 281 µs |
| 100000 | 17.4 ms | 27,931 B | 324 µs | 8.3 ms | 22,238 B | 242 µs |

**Groth16:** IBSL-KZG in-circuit (MNT cycle, section 3) vs zkcreds' tree
circuit (BLS12-381, section 1) — see the per-system tables; the two Groth16
columns are not on the same curve, so compare shapes and orders of
magnitude, not exact ratios.

## 3. IBSL-KZG native, and inside zkcreds' Groth16

Native IBSL-KZG (BLS12-381, `ark-poly-commit` KZG10, IBSL's own backend):

| n | height | build | prove | verify | proof size | shape |
|---|---|---|---|---|---|---|
| 1000 | 10 | 24.6 s | 101 ms | 31.2 ms | 1,050 B | 10 (com, pi) pairs |
| 10000 | 13 | 217 s | 130 ms | 36.3 ms | 1,365 B | 13 (com, pi) pairs |

IBSL-KZG **inside Groth16** (linkg16): KZG re-instantiated on MNT4-298 so
each opening's pairing equation e(com − v·G + z·W, H) = e(W, βH) is native
arithmetic in the MNT6-298 circuit. Public input: sigma. Hidden: key,
positions, all intermediate commitments/openings. ~22k constraints per
IBSL level (nonnative z-domain check 8.4k, two G1 scalar muls 6.7k,
2-pairing product 9.3k, seam ≈ free).

| n | levels | constraints | CRS gen | prove | verify | proof size | native build | native prove | native verify |
|---|---|---|---|---|---|---|---|---|---|
| 100 | 8 | 173,013 | 6.8 s | 5.5 s | 3.4 ms | 190 B | 2.6 s | 50 ms | 21 ms |
| 1000 | 10 | 216,905 | 8.4 s | 11.5 s | 7.4 ms | 190 B | 29.2 s | 70 ms | 28 ms |
| 10000 | 13 | 282,743 | 10.5 s | 9.9 s | 3.7 ms | 190 B | 281 s | 94 ms | 35 ms |

Correctness checks performed each run: the circuit is satisfied on the
honest witness, the Groth16 proof verifies against sigma, and verification
fails against a wrong sigma.

## Takeaways

- **Proof size / verify time:** Groth16 wins outright (192 B / ~2-7 ms)
  in both the zkcreds Merkle setting and the IBSL-KZG setting; STARK
  proofs are 20-30 KB with sub-ms verification but no trusted setup.
- **Prover time:** the STARK compiler is in the tens of milliseconds; the
  Groth16 provers are hundreds of ms (small Merkle circuit) to ~10 s
  (IBSL-KZG chain: in-circuit pairings are cheap on the MNT cycle but the
  ~22k/level cost times 10 levels is two orders of magnitude more
  constraints than a Poseidon Merkle path).
- **IBSL vs plain tree, same system:** the chain costs ~2-4x the single
  path in the STARK; in Groth16 the IBSL-KZG chain (~217k constraints at
  n=1000) is ~14x the zkcreds tree circuit (~15k at the same capacity) —
  the price of verifying pairing-based openings instead of hashes
  in-circuit. IBSL's structural advantage (native updates touching only
  the affected path) is not exercised by these membership benchmarks.
- The security levels are not identical across columns (f128 STARK
  ~96-bit conjectured, BLS12-381 ~128-bit, MNT-298 cycle ~80-bit); treat
  cross-system ratios as indicative.

## What was changed / added where

- `~/zkcreds-rs`: one line — `linkg16` git dependency `ssh://` → `https://`
  (SSH auth unavailable). Everything else untouched; all 14 tests pass.
- `~/IBSL`: added `src/lib.rs` (crate is now bin + lib); `src/main.rs` now
  imports from the lib. No algorithm changes. `bench_results.md`
  regenerated on this machine.
- `~/ibsl-zkcreds-bench`: new harness crate (this repo) — see README.md.

## 4. IBSL-KZG vs Merkle trees — native, all operations (2026-07-15)

Re-run after making IBSL insert/delete **incremental** (recompute only the
O(log n) affected path instead of every commitment). Same workload across
three structures: `Ibsl<KzgVc>` (BLS12-381), the same IBSL structure over a
SHA-256 Merkle vector commitment, and a plain sorted-leaf SHA-256 Merkle
tree. Driver: `native-compare` subcommand (`src/native_compare.rs`). search
avg/200 probes; prove/verify/proof-size avg/10 members; insert/delete avg
over 20 fresh odd keys (inserted, then deleted).

**n = 1000 keys**

| structure | build | search | prove | verify | insert | delete | proof size | shape |
|---|---|---|---|---|---|---|---|---|
| IBSL-KZG (BLS12-381) | 20.90 s | 2.63 µs | 99.1 ms | 29.2 ms | 119 ms | 109 ms | 1,050 B | 10 (com, pi) pairs |
| IBSL over Merkle VC (SHA-256) | 5.16 ms | 1.28 µs | 1.86 µs | 17.9 µs | 38.5 µs | 51.9 µs | 937 B | 10 (com, path) pairs |
| plain Merkle tree (SHA-256) | 1.17 ms | 11 ns | 273 ns | 6.28 µs | 1.05 ms | 1.02 ms | 328 B | 1 path, 10 siblings |

IBSL-KZG aggregated (SHPLONK): prove 47.8 ms, verify 5.75 ms, proof **656 B**
(one two-point witness for the whole 10-level chain).

**n = 10000 keys**

| structure | build | search | prove | verify | insert | delete | proof size | shape |
|---|---|---|---|---|---|---|---|---|
| IBSL-KZG (BLS12-381) | 218.3 s | 2.02 µs | 133.7 ms | 35.5 ms | 169 ms | 154 ms | 1,365 B | 13 (com, pi) pairs |
| IBSL over Merkle VC (SHA-256) | 53.4 ms | 1.18 µs | 3.24 µs | 18.1 µs | 50.0 µs | 236 µs | 1,163 B | 13 (com, path) pairs |
| plain Merkle tree (SHA-256) | 16.6 ms | 32 ns | 428 ns | 7.79 µs | 14.4 ms | 14.0 ms | 456 B | 1 path, 14 siblings |

IBSL-KZG aggregated (SHPLONK): prove 48.4 ms, verify 8.09 ms, proof **824 B**
(one two-point witness for the whole 13-level chain).

Reading:

- **Incremental updates land.** IBSL-KZG insert/delete are now ~110-170 ms —
  roughly one `prove` — and barely grow from n=1000 to n=10000 (119→169 ms
  insert), versus the 21 s / 218 s full rebuild each op used to cost. The
  IBSL-Merkle backend updates in tens of µs. The plain Merkle tree, which
  still rebuilds globally, is the only structure whose update cost grows with
  n (1.05 ms → 14.4 ms). This is IBSL's structural update advantage, finally
  visible.
- **KZG's cost is the group ops, not the structure.** Swapping the KZG
  backend for a SHA-256 Merkle VC (same IBSL, same fan-out chain) drops
  prove from ~100 ms to ~2-3 µs and verify from ~30 ms to ~18 µs; KZG's build
  is dominated by per-node MSMs (218 s at n=10000). KZG buys a smaller,
  aggregatable proof (656-824 B for the whole chain via SHPLONK) and a
  pairing-checkable opening — the property the in-circuit Groth16 work relies
  on — not speed.
- **Proof size:** aggregated IBSL-KZG (656-824 B) beats the per-level Merkle
  chains (0.9-1.2 KB) but not a single plain Merkle path (0.3-0.5 KB); the
  chain pays for one commitment per level.
- Single runs on the 12-core / 7 GB WSL2 machine, not statistics.

## 5. Raw IBSL-KZG (aggregated) vs zkcreds Groth16 Merkle (2026-07-15)

Raw (native) IBSL-KZG membership using the **aggregated SHPLONK** proof
(`prove_agg`/`verify_agg`: the whole opening chain collapses to one two-point
witness) versus zkcreds-rs's Groth16 Merkle-membership circuit (Poseidon,
BLS12-381), at matched capacity (IBSL n members vs tree capacity 2^(h-1)).
Membership proof only.

| capacity | IBSL-KZG agg: prove | verify | proof | zkcreds Groth16: prove | verify | proof |
|---|---|---|---|---|---|---|
| 2^10 (n=1000) | 44.4 ms | 5.60 ms | 656 B | 498 ms | 2.71 ms | 192 B |
| 2^14 (n=10000) | 57.1 ms | 6.31 ms | 824 B | 744 ms | 2.88 ms | 192 B |

zkcreds circuit: 15,276 constraints (h=11) / 21,128 (h=15); per-circuit CRS
gen 554 ms / 766 ms. IBSL-KZG: 10 / 13 levels.

Raw IBSL-KZG (aggregated) full numbers:

| n | levels | build | agg prove | agg verify | agg proof |
|---|---|---|---|---|---|
| 1000 | 10 | 20.92 s | 44.4 ms | 5.60 ms | 656 B |
| 10000 | 13 | 222.50 s | 57.1 ms | 6.31 ms | 824 B |

Reading — the two are different kinds of object, which explains every gap:

- **Raw IBSL-KZG aggregated** is a native VC opening: one aggregated
  pairing-checkable witness plus the chain of per-level commitments. It is
  **not zero-knowledge** (reveals commitments and positions) and **not
  constant-size** (656->824 B, one commitment per level). Universal, reusable
  KZG SRS.
- **zkcreds Groth16** is a **zk-SNARK**: constant 192 B, hides
  key/path/root, verifies in ~2.8 ms independent of tree size — but pays a
  per-circuit trusted setup (regenerated per height) and a heavier prover.
- **Prover:** raw IBSL-KZG is ~10x faster (44-57 ms vs 498-744 ms) — no
  circuit to satisfy.
- **Verifier / proof size:** zkcreds wins — constant 192 B / ~2.8 ms vs
  IBSL's 656-824 B (grows with height) / ~6 ms.
- **Setup:** KZG's SRS is universal and size-independent; Groth16's CRS is
  circuit-specific.
- **Build is not compared:** the zkcreds bench inserts a single credential
  into an empty tree, while IBSL-KZG builds all n keys, committing every node
  by MSM (20.9 s / 222.5 s) — IBSL-KZG's real weak point here, separate from
  the proof numbers.

The "raw vs raw" framing is really: the 656 B aggregated IBSL-KZG proof is
the *input* one would feed into a SNARK to match zkcreds' 192 B — exactly
what the MNT-cycle Groth16 wrapper (section 3) does, landing at 190 B.

## 6. Raw IBSL-KZG (aggregated) vs raw zkcreds Merkle tree (2026-07-15)

Both **native, no Groth16** — the honest raw-vs-raw comparison. zkcreds'
`ComTree` (Poseidon two-to-one over BLS12-381 Fr) run through its own native
ops (build = n inserts, path-gen via `insert`, native `SparseMerkleTreePath::
verify`, `remove`), driver `zkcreds-merkle-raw` (`src/zkcreds_merkle_raw.rs`),
versus raw IBSL-KZG with the aggregated SHPLONK proof. Matched capacity.

| n (cap) | metric | IBSL-KZG agg | zkcreds Merkle (Poseidon) | Merkle advantage |
|---|---|---|---|---|
| 1000 (2^10) | build | 20.92 s | 644.7 ms | ~32x |
| | prove | 44.4 ms | 649 µs | ~68x |
| | verify | 5.60 ms | 555 µs | ~10x |
| | proof size | 656 B | 328 B | ~2x |
| 10000 (2^14) | build | 222.5 s | 8.83 s | ~25x |
| | prove | 57.1 ms | 840 µs | ~68x |
| | verify | 6.31 ms | 851 µs | ~7x |
| | proof size | 824 B | 456 B | ~1.8x |

zkcreds Merkle native insert/delete: ~0.6-0.8 ms/op at both sizes.

Reading: raw and native, both BLS12-381 with ~32-byte digests, the plain
Poseidon Merkle tree beats IBSL-KZG on every axis by 1-2 orders of magnitude
— a Merkle op is a few Poseidon hashes, every IBSL-KZG op is EC MSMs and
pairings. IBSL's build (222 s) commits every node by MSM.

IBSL-KZG's value is NOT native speed; it is what this benchmark strips away:
(1) the aggregated KZG opening is pairing-checkable and SNARK-friendly — the
656 B native proof compiles to a ~190 B Groth16 proof (section 3), whereas a
Poseidon path must be re-hashed in-circuit; (2) IBSL is a key-searchable
interval skip-list (membership AND non-membership over arbitrary u64 keys,
updates touching only the O(log n) path), while `ComTree` is addressed by
leaf index. For native membership in a fixed commitment set, the Merkle tree
is strictly better here.

## 7. Promotion probability p vs IBSL-KZG proof size (2026-07-15)

Testing whether widening the skip list shrinks the KZG proof: made p
configurable (`Ibsl::new_with_promotion`; fan-out ~1/p, height ~log_{1/p} n)
and swept it. Aggregated (SHPLONK) proof. Driver: scratch `psweep`.

n=1000 (binary Merkle native proof = 328 B):

| p | mean fan-out | height | build | agg prove | agg verify | agg proof |
|---|---|---|---|---|---|---|
| 0.50 | 2.14 | 11 | 20.4 s | 45.9 ms | 5.56 ms | 712 B |
| 0.25 | 4.17 | 6 | 14.5 s | 35.0 ms | 4.54 ms | 432 B |
| 0.15 | 6.35 | 5 | 13.2 s | 30.7 ms | 4.12 ms | 376 B |
| 0.10 | 9.07 | 5 | 12.7 s | 32.4 ms | 4.50 ms | 376 B |

n=10000 (binary Merkle native proof = 456 B):

| p | mean fan-out | height | build | agg prove | agg verify | agg proof |
|---|---|---|---|---|---|---|
| 0.50 | 2.14 | 15 | 218.1 s | 61.1 ms | 6.80 ms | 936 B |
| 0.15 | 7.17 | 6 | 131.8 s | 33.2 ms | 4.47 ms | 432 B |
| 0.10 | 10.60 | 6 | 125.2 s | 35.8 ms | 4.61 ms | 432 B |

Findings:

- **Lower p shrinks the proof and speeds everything up.** p=0.15 (fan-out
  ~7, ~3x binary Merkle's 2) cuts the proof ~47% at n=1000 (712->376 B) and
  ~54% at n=10000 (936->432 B), and build/prove/verify all drop (fewer, if
  wider, nodes).
- **Crossover with Merkle.** proof = height x (48 B commitment + 8 B pos) +
  96 B aggregate. IBSL height ~log_{1/p} n shrinks slower than Merkle's
  log_2 n as n grows, so at n=10000 the p=0.15 proof (432 B) is *smaller*
  than the binary Merkle path (456 B); at n=1000 it is 376 B vs 328 B (still
  just behind — the 96 B aggregate + 48>32 B per level dominate at small
  height).
- **Diminishing returns + a cost.** p=0.10 gives no smaller proof than 0.15
  (height plateaus) but max fan-out grows (72 at n=10000 vs 48). Wider nodes
  mean larger per-node MSMs and, with insert Case-2 head piling, push toward
  MAX_FANOUT (512) and the KZG SRS width. Sweet spot ~p=0.15.
- **In-circuit bonus:** fewer levels => fewer per-level pairing checks in the
  Groth16 circuit (~22k constraints/level, section 3). p=0.15 roughly halves
  the level count (15->6 at n=10000), so it roughly halves the SNARK circuit
  too — the bigger practical win.
- Default `new` stays at p=1/2; p is opt-in via `new_with_promotion`.

## 8. IBSL-MerkleVC (p = 0.15) vs raw zkcreds Merkle tree (2026-07-15)

Both **native, no Groth16, same hash family** — IBSL run over a *Poseidon*
Merkle vector commitment (`PoseidonMerkleVc`: Poseidon two-to-one over
BLS12-381 Fr, ark 0.6) at promotion probability **p = 0.15**, versus
zkcreds-rs's `ComTree` (Poseidon two-to-one over BLS12-381 Fr, ark 0.3) run
raw. Same hash, same field, same 32-byte digests, so this isolates the
*structure*: IBSL's per-level chain of node-commitment openings (interval
skip list) vs one fixed-height authentication path. Drivers: `ibsl-merkle
0.15 …` (`src/ibsl_merkle.rs`, added 2026-07-15) and `zkcreds-merkle-raw`.
Membership only; prove/verify averaged over 10 evenly spread members.

| n (cap) | metric | IBSL-MerkleVC (Poseidon, p=0.15) | zkcreds Merkle (Poseidon) |
|---|---|---|---|
| 1000 (2^10) | prove | 1.63 µs | 575.9 µs |
| | verify | 922.2 µs | 518.3 µs |
| | proof size | 654 B (5 levels) | 328 B (11 levels) |
| 10000 (2^14) | prove | 3.48 µs | 783.3 µs |
| | verify | 1.15 ms | 797.0 µs |
| | proof size | 854 B (6 levels) | 456 B (15 levels) |

Build (context, not the focus): IBSL-MerkleVC 305 ms / 2.92 s; zkcreds tree
603 ms / 8.53 s.

Reading:

- **Prove:** IBSL-MerkleVC is ~300x faster (1.6-3.5 µs vs 0.58-0.78 ms), but
  this compares different things. IBSL's `MerkleOpener` stores every node's
  tree layers, so `prove` just *copies* sibling digests out — zero hashing.
  zkcreds' path-gen API produces an auth path via `ComTree::insert`, which
  re-hashes the path. The honest read is "IBSL opening is a lookup"; it is
  not a 300x algorithmic win.
- **Verify:** the fair axis (both re-hash paths natively). At n=1000 IBSL is
  ~1.8x slower (922 µs vs 518 µs), at n=10000 ~1.4x (1.15 ms vs 797 µs).
  IBSL re-hashes 5-6 short per-node Merkle paths (one per skip-list level,
  each over a node's small child-vector tree); the plain tree re-hashes one
  11-15 deep path. Comparable order of magnitude; the chain costs a bit more.
- **Proof size:** the plain tree wins (~2x): 328/456 B vs IBSL's 654/854 B.
  IBSL pays one 32 B node commitment *per level* on top of the sibling
  digests, where the plain path carries only siblings + one index. p=0.15
  buys a low level count (5-6 vs 11-15) — without it (p=0.5) IBSL-Merkle
  would be ~11-15 levels and far larger — but the per-level commitment
  overhead still leaves it ~2x the single path.
- **Why p=0.15 matters here:** fan-out ~1/p ≈ 7 flattens the skip list to
  5-6 levels at these n, cutting both the number of per-level openings the
  verifier checks and the number of (commitment, path) pairs in the proof
  roughly in half versus the binary (p=0.5) default. It does not close the
  ~2x proof-size gap to a single Merkle path, because each level still adds a
  commitment the plain path never carries.
- Same caveat as sections 4-7: IBSL is a *key-searchable* interval skip list
  (membership + non-membership over arbitrary u64 keys, O(log n)-path
  updates), while `ComTree` is index-addressed. For native membership in a
  fixed set the plain tree is smaller/simpler; IBSL buys searchability and
  cheap structural updates. Single runs, 12-core / 7 GB WSL2.

## 9. IBSL-BDLOP (lattice commitments, p = 0.15) (2026-07-15)

Experimental backend: IBSL run over BDLOP (Baum et al.) lattice commitments
from the `lettuce` crate (v0.1.3), at promotion probability **p = 0.15**.
Driver: `ibsl-bdlop 0.15 …` (`src/ibsl_bdlop.rs`); backend `../src/vc/bdlop.rs`
(a `VectorCommitment` impl over `lettuce::BDLOP<N, MilliScalarMont>`, ring
R_q = Z_q[X]/(X^N+1), q ≈ 2^32, **N = 64**). Native, no SNARK. Prove/verify
averaged over 10 members; honest members verify (checked each run).

**HEAVY caveats — read before quoting:**

- **Not sound / demo parameters.** `lettuce` itself states its BDLOP "is not
  sound" (challenge invertibility unargued; sigma/dimension not analyzed).
  We picked N = 64 for benchmark speed, far below any secure lattice
  dimension. These are size/systems sketches, not a secure scheme.
- **Adapted to a positional interface.** BDLOP is a *compact commitment to a
  whole message vector* (c_1 = A_1·r, c_2 = A_2·r + m), not a positional VC.
  We satisfy IBSL's `VectorCommitment` by making an "opening of slot i" carry
  the randomness r; the verifier reconstructs the commitment, `try_open`s to
  recover the whole message m = c_2 − A_2·r (after checking A_1·r = c_1), and
  compares m[i]. So each level effectively **reveals the whole child vector +
  randomness** — the witness is O(fan-out) ring elements, not O(log fan-out).

Results:

| n | height | build | prove | verify | proof size | shape |
|---|---|---|---|---|---|---|
| 100 | 5 | 32.0 ms | 25.5 µs | 5.11 ms | 26,868 B | 5 (com, r) |
| 1000 | 5 | 260.2 ms | 13.5 µs | 5.74 ms | 35,777 B | 5 (com, r) |
| 10000 | 6 | 2.45 s | 16.4 µs | 9.75 ms | 61,180 B | 6 (com, r) |

Set against the other p = 0.15 backends and the raw zkcreds Merkle baseline
(sections 7, 8) — **proof size / prove / verify**:

| n | IBSL-BDLOP (lattice, N=64) | IBSL-MerkleVC (Poseidon) | IBSL-KZG (agg) | raw zkcreds Merkle |
|---|---|---|---|---|
| 1000 | 35,777 B / 13.5 µs / 5.74 ms | 654 B / 1.63 µs / 922 µs | 376 B / 30.7 ms / 4.12 ms | 328 B / 576 µs / 518 µs |
| 10000 | 61,180 B / 16.4 µs / 9.75 ms | 854 B / 3.48 µs / 1.15 ms | 432 B / 33.2 ms / 4.47 ms | 456 B / 783 µs / 797 µs |

Reading:

- **Proof size is the story: ~35–61 KB, ~100x the raw Merkle path and ~50x
  the Merkle-VC / KZG IBSL proofs.** A BDLOP level carries (c_1, c_2) ≈ 2·d
  ring elements plus randomness r ≈ 2·d ring elements (d = fan-out), each an
  N-coefficient polynomial. At fan-out ~7, N=64, 4 B/coeff that is ~7 KB per
  level × 5–6 levels. Lattice commitments are simply large objects, and the
  non-succinct opening (whole vector + r) compounds it. Larger, secure N
  (256–1024) would multiply these by 4–16x.
- **Prove is a lookup (13–26 µs)**, like the Merkle-VC backend: `open` just
  clones the stored short randomness r — no arithmetic. Not an algorithmic
  win over the tree, an API artifact (the tree's path-gen re-hashes).
- **Verify (5.7–9.8 ms)** is the real per-level cost: reconstruct the lattice
  and compute A_1·r and A_2·r (matrix × vector over R_q) per level. Same
  order as KZG's pairing verify (~4 ms), ~10x the raw Merkle re-hash
  (~0.5–0.8 ms), and it grows with fan-out and N.
- **What (a real, sound) BDLOP would buy** that this benchmark does not
  exercise: post-quantum security, and a NIZK opening (`try_open_zk`, page 15
  of eprint 2016/997) that hides the message instead of revealing it. The
  sizes above are the *transparent* (message-revealing) opening — the floor,
  not the ZK version.
- Single runs, 12-core / 7 GB WSL2. p = 0.15 keeps the level count to 5–6
  (vs ~11–15 at p = 0.5), which matters more here than for any other backend
  because each BDLOP level is so expensive in bytes.

### 9a. Lowering p hurts BDLOP — the opposite of KZG (2026-07-15)

Sweeping p at n = 1000 (single run each, so ±1 level of random-realization
noise):

| p | fan-out ~1/p | height | prove | verify | proof size |
|---|---|---|---|---|---|
| 0.50 | 2 | 11 | 12.6 µs | 4.26 ms | 27,326 B |
| 0.37 | ~e≈2.7 | 9 | 15.5 µs | 5.01 ms | 30,894 B |
| 0.25 | 4 | 6 | 32.7 µs | 7.37 ms | 43,977 B |
| 0.15 | ~7 | 5 | 18.4 µs | 5.36 ms | 35,777 B |
| 0.10 | ~10 | 5 | 19.7 µs | 6.83 ms | 47,041 B |
| 0.07 | ~14 | 4 | 75.3 µs | 11.14 ms | 56,556 B |

And at n = 10000: p=0.15 → 6 levels / 61,180 B / 9.75 ms; p=0.07 → 5 levels /
91,995 B / 19.61 ms. Fewer levels, but +50% bytes and ~2x verify.

**Why the sign flips vs section 7 (KZG).** For a *succinct/positional* VC a
level contributes O(1) (KZG) or O(log d) (Merkle) to the proof regardless of
fan-out d, so flattening the tree (lower p) strictly shrinks the proof. BDLOP
here is *non-succinct*: opening a level reveals the whole node's child vector,
~d = 1/p ring elements. So the membership proof is

    cost ∝ (per-level fan-out) × (height) ≈ (1/p) · log_{1/p}(n).

That function is **minimized near p = 1/e ≈ 0.37** (fan-out ~e) and *grows*
as p → 0: the wider nodes cost more than the extra depth saves. The measured
"element-level" totals (1/p)·log_{1/p}(1000) are ≈ 20 / 18.8 / 19.9 / 24 / 30
/ 37 for the rows above — a shallow minimum around p = 0.37–0.5, then a steep
climb toward p = 0.07, matching the proof-size column (the p=0.15<0.25
inversion is single-run noise).

**Takeaway:** for the KZG backend, low p (≈0.15) is the sweet spot (section 7);
for a non-succinct backend like this BDLOP adaptation, the sweet spot is the
*other* end — keep p high (≈0.37–0.5, i.e. a near-binary skip list).
Lowering p to 0.07 is the wrong direction: it makes the proof ~2x larger and
verification ~2x slower. The right lever for BDLOP is a succinct opening
(reveal one slot, not the whole vector), not a wider tree.

## 10. IBSL-Greyhound (lattice PCS via Rust→C FFI), p-sweep (2026-07-15)

IBSL over the **Greyhound** lattice polynomial-commitment scheme
(github.com/lattice-dogs/labrador) wired in through a C FFI shim
(`~/labrador/greyhound_shim.c` → `../src/vc/greyhound.rs`, feature `greyhound`,
which this crate forwards to `ibsl/greyhound`; the ibsl crate's `build.rs`
compiles the labrador C with `-march=icelake-server`). Driver:
`ibsl-greyhound [p] [n...]`.

**Ran under Intel SDE** (this CPU has no AVX512; labrador requires it — native
run = SIGILL). Under SDE: **proof sizes and verification are real; ALL TIMINGS
ARE VOID** (50-100x emulation, non-uniform). Small n only (each level is a full
Greyhound eval proof + Labrador reduction, emulated).

Adaptation (non-succinct, like the BDLOP backend): a node's child vector is the
polynomial's coefficients; an opening reveals the vector + a Greyhound eval
proof of `p(x)=y` at `x=FS(commitment)`; `check` accepts iff the proof's x ties
to the commitment, the eval proof verifies, `y == eval(revealed vec, x)`, and
`vec[i]==value`. Demo params: N=64, 32-bit modulus, field values kept to 16
bits (norm budget). Proof size counted = the Greyhound eval-proof
(`2·kappa1·N·LOGQ/8` ≈ 2 KB/level) + the revealed padded vector.

| n | p | height | proof size | verifies |
|---|---|---|---|---|
| 20 | 0.50 | 5 | 10,400 B | ✓ |
| 20 | 0.37 | 5 | 10,400 B | ✓ |
| 20 | 0.25 | 4 | 8,322 B | ✓ |
| 20 | 0.15 | 3 | 6,268 B | ✓ |
| 20 | 0.10 | 3 | 6,296 B | ✓ |
| 20 | 0.07 | 3 | 6,296 B | ✓ |
| 60 | 0.50 | 6 | 12,480 B | ✓ |
| 60 | 0.37 | 5 | 10,400 B | ✓ |
| 60 | 0.25 | 5 | 10,409 B | ✓ |
| 60 | 0.15 | 4 | 8,337 B | ✓ |
| 60 | 0.10 | 3 | 6,673 B | ✓ |
| 60 | 0.07 | 3 | 6,678 B | ✓ |

Findings:

- **Proof ≈ height × ~2.05 KB.** Each level's Greyhound eval proof is
  ~2,048 B and, crucially, **~constant in fan-out** (a succinct PCS: size =
  2·kappa1·N·LOGQ/8, and kappa1 barely moves with length). The revealed vector
  adds only ~32-56 B/level.
- **Lowering p SHRINKS the proof — like KZG, opposite of BDLOP.** Because the
  per-level cost is flat (succinct), fewer levels = smaller proof. p 0.5→0.07
  cuts height 5→3 (n=20) / 6→3 (n=60) and proof 10.4 KB→6.3 KB / 12.5 KB→6.7 KB.
  This is the mirror image of §9a, where BDLOP's non-succinct per-level opening
  (∝ fan-out) made low p *grow* the proof. Greyhound's succinctness is exactly
  what makes the promotion-probability lever point the KZG way.
- **Diminishing returns below ~p=0.15** (height plateaus at 3 for these n).
- **Honest size caveat.** This counts the eval-proof (u1,u2); the *simple*
  polcom flow used here also ships a Labrador witness for `principle_verify`
  (non-succinct, omitted from the count). The fully-succinct **composite/pack**
  proof — which replaces that witness with a recursive Labrador proof — measured
  ~19 KB *constant* at len=8 but failed to verify at such tiny lengths (its
  aggregation needs large dimension), so it isn't usable per-node. So ~2 KB/level
  is the eval-proof core, a lower bound on a fully-succinct per-node proof.
- Timings are omitted from the table on purpose: they were emulated and are
  meaningless. Verification passed on every honest proof.

Bottom line: the Rust→C bridge works and the sweep runs, but Greyhound is a
poor structural fit as a per-node IBSL VC (an evaluation-PCS forced into a
positional interface, ~2 KB of fixed lattice machinery per tiny node, and only
runnable under emulation here). Its one qualitative win over BDLOP: succinct
per-level proofs, so flattening the skip list (low p) helps rather than hurts.
See [[greyhound-sde-findings]].

### 10a. IBSL-Greyhound at n = 10000 (2026-07-15)

Same FFI backend, larger set, under SDE (proof sizes real, timings void). Peak
RSS 478-711 MB; wall 88-143 s/point (emulated). All verify.

| n | p | height | proof size | verifies |
|---|---|---|---|---|
| 10000 | 0.50 | 15 | 31,200 B | ✓ |
| 10000 | 0.25 |  9 | 18,742 B | ✓ |
| 10000 | 0.15 |  6 | 12,566 B | ✓ |
| 10000 | 0.07 |  5 | 11,104 B | ✓ |

The succinct-per-level effect is far more dramatic at n=10000, because height
ranges widely (15→5): lowering p from 0.5 to 0.07 cuts the proof **64%**
(31.2 KB → 11.1 KB), confirming proof ≈ height × ~2.08 KB with a fan-out-flat
per-level cost. (Compare §9a: BDLOP at n=10000 went the other way, 61 KB→92 KB
as p dropped 0.15→0.07.) For reference at n=10000 the other p=0.15 backends:
IBSL-KZG agg 432 B, IBSL-MerkleVC 854 B, IBSL-BDLOP 61 KB — Greyhound's 12.6 KB
sits between BDLOP and the succinct schemes, dominated by ~2 KB of fixed lattice
machinery per level.

### 10b. Can Greyhound/Labrador aggregate the IBSL chain? (2026-07-15)

Labrador IS a folding/aggregation system, so the question is whether the L
per-level Greyhound openings can collapse into ONE proof (an `AggregatableVc`
like KZG's SHPLONK). Investigated with a C probe (`~/labrador/test_agg.c`);
findings, honest:

- **Verification-side aggregation WORKS.** Merging L Greyhound eval statements
  block-diagonally into one principal statement — 4L witness vectors, 5L
  constraints, per-block index offsets, betasq = ΣnormSq (~1e8, far under
  JLMAXNORMSQ≈7.2e16) — and calling `principle_verify` **passes (OK) for L up
  to 6**. So the L per-level checks can be batched into a single Labrador
  statement.
- **Succinct composite aggregation did NOT round-trip.** Running the composite
  (recursive) prover on that merged statement via
  `composite_prove_principle` "succeeds" (~20 KB at L=1 → ~36 KB at L=6, nearly
  flat in L — the aggregation payoff would be real), but
  `composite_verify_principle` **FAILS** — and crucially it fails **even at
  L=1** (err 117), the exact single eval that verifies fine through the
  library's dedicated `composite_prove_polcom` wrapper (§10 measured 19-43 KB,
  verify OK). Larger nodes only change the error (29 "inner commitments not
  secure" → 115 "aggregated dot-product"), never pass.
- **Conclusion.** The blocker is not the block-merge; it is that the generic
  principle-composite API path does not round-trip in my harness the way the
  Greyhound-specific `composite_prove_polcom` does. A real aggregated
  IBSL-Greyhound would need the intended multi-statement construction (the
  Chihuahua frontend / one coherent statement with proper comkey allocation),
  not a shim-level statement merge — deeper library work than a backend wiring.
  So: aggregatable in principle and for the *check* (demonstrated), but a
  drop-in succinct `AggregatableVc` did not come together. The IBSL harness was
  left unchanged (still the working per-level §10 backend); this was all in the
  throwaway `test_agg.c`.
