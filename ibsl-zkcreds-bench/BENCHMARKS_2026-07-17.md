# Full benchmark sweep at n = 1000 and n = 10000 (2026-07-17)

Every benchmark in the project, re-run at **n = 1000** and **n = 10000** on one
machine in one sequential pass. To reproduce any row, see
[`HOW_TO_RUN.md`](HOW_TO_RUN.md).

**Machine:** i7-10750H (Comet Lake, 12 threads, **no AVX512**), 7 GB RAM, WSL2
(kernel 5.15). All runs release-mode, sequential — nothing ran in parallel, so
timings are not contaminated by each other. Single runs; prove/verify are
averaged over a few iterations inside each harness. Treat timings as
indicative, not statistics.

**This is the first sweep since the VC backends moved into the `ibsl` crate**
(`src/vc/bdlop.rs`, `src/vc/greyhound.rs`, `src/vc/mnt_kzg.rs`). The bench crate
now owns no backend — it only drives them. See "Reproducibility" at the bottom:
the move is verified behaviour-preserving.

---

## Summary — everything at a glance

Proof size is the number to compare; timings differ in what they include.

| System | n=1000 proof | n=10000 proof | prove | verify | Setup | Notes |
|---|---|---|---|---|---|---|
| zkcreds Groth16 Merkle | **192 B** | **192 B** | 368 / 483 ms | ~2 ms | trusted, per-circuit | Poseidon/BLS12-381, ~128-bit |
| IBSL-KZG in Groth16 | **190 B** | **190 B** | 8.1 / 11.1 s | ~3.7 ms | trusted, per-shape | MNT cycle, ~80-bit |
| IBSL-KZG native, aggregated | 712 B | 936 B | 46 / 60 ms | 6.0 / 7.0 ms | trusted (demo SRS) | p=0.5 |
| IBSL-KZG native, per-level | 1155 B | 1575 B | 120 / 159 ms | 32 / 42 ms | trusted (demo SRS) | p=0.5 |
| zkcreds Merkle raw (no SNARK) | 328 B | 456 B | 0.73 / 0.86 ms | 0.60 / 0.75 ms | none | auth path |
| IBSL-MerkleVC hash mode, p=0.15 | 459 B | 620 B | 1.4 / 4.0 µs | 0.89 / 1.25 ms | none | closest raw comparison |
| IBSL-MerkleVC hash mode, p=0.5 | 497 B | 783 B | 3.2 / 5.2 µs | 1.32 / 1.84 ms | none | |
| IBSL chain in STARK (Rescue) | 22,880 B | 27,896 B | 10.7 / 16.9 ms | 0.55 / 0.29 ms | **none** | transparent, ~96-bit conj. |
| Plain path in STARK (Rescue) | 19,129 B | 19,711 B | 4.9 / 3.9 ms | 0.24 / 0.20 ms | **none** | |
| IBSL-Greyhound, p=0.15 | 10,430 B | 12,566 B | — timings void — | | none (lattice) | SDE-emulated |
| IBSL-BDLOP, p=0.15 | 35,777 B | 61,180 B | 12 / 19 µs | 5.5 / 10.1 ms | none (lattice) | **not sound**, demo params |

Security levels are **not** matched across rows (STARK f128 ~96-bit conjectured,
BLS12-381 ~128-bit, MNT-298 cycle ~80-bit, lattice rows are demo parameters).
Cross-system ratios are indicative only.

### The shape of it

- **Groth16 wins size outright and is flat in n** — 190–192 B whether the set is
  1,000 or 10,000, in both the zkcreds Merkle setting and the IBSL-KZG setting.
  The cost is a trusted setup and a prover measured in seconds.
- **IBSL-KZG in-circuit costs ~16× the zkcreds tree circuit** (238,851 vs 15,276
  constraints at n=1000): verifying pairing-based openings in-circuit is far
  dearer than hashing a Merkle path, and it buys the same 190 B proof.
- **The STARK is the fastest prover by ~760×** (10.7 ms vs 8.14 s at n=1000)
  and needs no trusted setup, at ~120× the proof size.
- **Lattice backends are 10–60 KB and the two move oppositely in p.** Greyhound
  is succinct per level (~2 KB flat), so fewer levels = smaller proof; BDLOP
  reveals O(fan-out) per level, so flattening the list *grows* the proof. This
  reproduces §9a/§10 of `RESULTS.md`.
- **IBSL's native prove is microseconds** (1.4–19 µs) across every backend —
  it is a lookup over stored prover state. The verify column is where the
  backend's real cost shows.

---

## 1. zkcreds-rs Groth16 Merkle membership (baseline)

`zkcreds-merkle 11 15` — takes **heights, not n**; capacity is 2^(h-1), so
h=11 ≈ n=1000 and h=15 ≈ n=10000.

| height | capacity | constraints | CRS gen | prove | verify | proof size |
|---|---|---|---|---|---|---|
| 11 | 2^10 | 15,276 | 384.04 ms | 368.28 ms | 2.01 ms | 192 B |
| 15 | 2^14 | 21,128 | 564.35 ms | 483.22 ms | 1.93 ms | 192 B |

## 2. zkcreds-rs Merkle tree, raw (no SNARK)

`zkcreds-merkle-raw 1000 10000`

| n | height | capacity | build | prove/path-gen | verify | insert | delete | proof size |
|---|---|---|---|---|---|---|---|---|
| 1000 | 11 | 2^10 | 649.33 ms | 729.43 µs | 596.58 µs | 602.61 µs | 637.70 µs | 328 B |
| 10000 | 15 | 2^14 | 9.00 s | 859.67 µs | 754.82 µs | 875.43 µs | 761.37 µs | 456 B |

## 3. IBSL over Poseidon Merkle VC, native

`ibsl-merkle 0.5 1000 10000` and `ibsl-merkle 0.15 1000 10000`. Hash mode is the
sibling-hash chain (`prove_hash`/`verify_hash`) — the row to compare against §2.
Digest 32 B.

| n | p | height | build | prove (hash) | verify (hash) | proof (hash) | proof (commit) | siblings |
|---|---|---|---|---|---|---|---|---|
| 1000 | 0.50 | 11 | 351.94 ms | 3.20 µs | 1.32 ms | 497 B | 926 B | 15 |
| 10000 | 0.50 | 15 | 3.63 s | 5.24 µs | 1.84 ms | 783 B | 1368 B | 24 |
| 1000 | 0.15 | 5 | 299.17 ms | 1.39 µs | 891.48 µs | 459 B | 654 B | 14 |
| 10000 | 0.15 | 6 | 2.99 s | 3.95 µs | 1.25 ms | 620 B | 854 B | 19 |

IBSL's hash-mode proof at p=0.15 (620 B) is **larger** than the plain tree's auth
path (456 B) at n=10000, but its prove is ~200× faster (3.95 µs vs 859 µs) because
it reads stored state instead of recomputing hashes. The interesting IBSL
property — updates touching only the affected path — is not exercised here.

## 4. IBSL over KZG10 (BLS12-381), native

`ibsl-kzg 1000 10000` — no `p` argument, so this is the default **p = 0.5**.

| n | height | build | prove | verify | proof size | agg prove | agg verify | agg proof | shape |
|---|---|---|---|---|---|---|---|---|---|
| 1000 | 11 | 19.96 s | 119.83 ms | 32.04 ms | 1,155 B | 45.61 ms | 6.03 ms | **712 B** | 11 (com, π) pairs |
| 10000 | 15 | 218.29 s | 159.25 ms | 42.16 ms | 1,575 B | 59.61 ms | 7.02 ms | **936 B** | 15 (com, π) pairs |

SHPLONK-style aggregation collapses the per-level witnesses into one: proof
−38%/−41%, verify ~5–6× faster, prove ~2.6× faster. Build is the bottleneck
(218 s at n=10000) — every node runs a KZG commit.

## 5. IBSL-KZG membership inside Groth16

`kzg-groth16 1000 10000` — KZG on MNT4-298 so each opening's pairing equation
is native arithmetic in an MNT6-298 circuit. Public input: sigma. Hidden: key,
positions, all intermediate commitments and openings.

| n | levels | constraints | CRS gen | prove | verify | proof size | native build | native prove | native verify |
|---|---|---|---|---|---|---|---|---|---|
| 1000 | 11 | 238,851 | 9.32 s | 8.14 s | 3.65 ms | 190 B | 27.64 s | 74.68 ms | 29.21 ms |
| 10000 | 15 | 326,635 | 12.58 s | 11.07 s | 3.86 ms | 190 B | 279.99 s | 100.47 ms | 41.82 ms |

≈21.7k constraints per IBSL level. Each run checks that the circuit is satisfied
on the honest witness, that the proof verifies against sigma, and that it
**fails** against a wrong sigma. Peak RSS 2.32 GB — the heaviest run in the
sweep, and the reason the 7 GB budget matters.

## 6. In-circuit primitive costs (`probe`)

Size-independent — no `n`. Constraint counts for the MNT4-in-MNT6 primitives
that make up §5:

| primitive | constraints |
|---|---|
| alloc p,q | 13,867 |
| prepare_g1 | 8 |
| prepare_g2 | 6,112 |
| pairing (miller + final exp) | 5,349 |
| product_of_pairings (2 pairs) | 9,345 |
| g1 scalar_mul_le, 298-bit var base | 3,610 |
| nonnative alloc | 318 |
| 9 nonnative squarings | 7,002 |
| nonnative to_bits_le | 1,128 |
| **total probe circuit** | **46,744** (satisfied ✓) |

## 7. IBSL vs plain Merkle tree, in the STARK (Rescue / f128)

`cargo run --release -- bench 1000 10000` from `~/IBSL`. Transparent — no
trusted setup.

**Native:**

| n | structure | build | prove | verify | insert |
|---|---|---|---|---|---|
| 1000 | IBSL (Rescue Merkle VC) | 526.81 ms | 3.86 µs | 1.79 ms | 5.85 ms |
| 1000 | Merkle tree (Rescue) | 147.11 ms | 581.00 ns | 832.22 µs | 153.91 ms |
| 10000 | IBSL (Rescue Merkle VC) | 5.12 s | 9.05 µs | 2.73 ms | 8.00 ms |
| 10000 | Merkle tree (Rescue) | 2.34 s | 724.00 ns | 1.02 ms | **2.33 s** |

**STARK-compiled:**

| n | circuit | cycles | prove | proof size | verify |
|---|---|---|---|---|---|
| 1000 | IBSL chain | 25 | 10.68 ms | 22,880 B | 552.51 µs |
| 1000 | plain path | 11 | 4.94 ms | 19,129 B | 236.17 µs |
| 10000 | IBSL chain | 42 | 16.85 ms | 27,896 B | 293.38 µs |
| 10000 | plain path | 15 | 3.91 ms | 19,711 B | 201.84 µs |

**This is the one table where IBSL's structural advantage shows.** Insert at
n=10000: IBSL **8.00 ms** vs the plain tree's **2.33 s** — ~290× faster, because
IBSL touches only the affected path while the tree rebuilds. That gap widens
with n (at n=1000 it is 5.85 ms vs 153.91 ms, ~26×). Everywhere else in this
document IBSL is paying for a structure whose benefit isn't being measured.

## 8. IBSL over BDLOP lattice commitments

`ibsl-bdlop 0.15 1000 10000`

| n | p | height | build | prove | verify | proof size | shape |
|---|---|---|---|---|---|---|---|
| 1000 | 0.15 | 5 | 246.34 ms | 11.98 µs | 5.45 ms | 35,777 B | 5 (com, r) pairs |
| 10000 | 0.15 | 6 | 2.45 s | 19.02 µs | 10.13 ms | 61,180 B | 6 (com, r) pairs |

> **Not a secure instantiation.** `lettuce` documents its BDLOP as "not sound"
> and ships no security-parameter analysis; ring dimension N=64 is chosen for
> benchmark speed. The opening is non-succinct by construction — it reveals the
> randomness `r` and the verifier recovers the whole message. These are size
> sketches only.

## 9. IBSL over Greyhound lattice PCS

`sde64 -icx -- … ibsl-greyhound 0.15 1000 10000`

| n | p | height | proof size | verifies |
|---|---|---|---|---|
| 1000 | 0.15 | 5 | 10,430 B | ✓ |
| 10000 | 0.15 | 6 | 12,566 B | ✓ |

> **Timings deliberately omitted.** This CPU has no AVX512 and labrador requires
> it, so this ran under Intel SDE — 50–100× slow and non-uniform, hitting the
> AVX512 NTT hot path hardest. **Proof sizes and verification results are real;
> any timing from this run is meaningless.** For the record the whole run took
> 97.35 s wall at 491 MB peak RSS, emulated.

Proof ≈ height × ~2.05 KB, and the per-level eval proof is ~flat in fan-out
(Greyhound is succinct: size = 2·kappa1·N·LOGQ/8). Size counted is the eval
proof plus the revealed vector; the simple polcom flow also ships a
non-succinct Labrador witness that is not counted — see §10 of `RESULTS.md`.

---

## Cost of the sweep

Sequential, in this order. Total **~12.3 minutes**.

| run | wall | peak RSS |
|---|---|---|
| probe | 0.27 s | 138 MB |
| zkcreds-merkle (Groth16) | 5.47 s | 109 MB |
| zkcreds-merkle-raw | 9.70 s | 6 MB |
| ibsl-merkle p=0.5 | 4.02 s | 16 MB |
| ibsl-merkle p=0.15 | 3.31 s | 11 MB |
| ibsl-bdlop p=0.15 | 2.85 s | 53 MB |
| ibsl STARK/Rescue bench | 18.29 s | 19 MB |
| ibsl-kzg native | 242.58 s | 312 MB |
| kzg-groth16 | 352.99 s | **2.32 GB** |
| ibsl-greyhound (SDE) | 97.35 s | 491 MB |

All ten exited 0.

## Reproducibility, and one discrepancy

**The backend move is verified behaviour-preserving.** Every backend that moved
out of this crate into `ibsl/src/vc/` reproduces its previously recorded proof
size *exactly*, at matched p and n:

| backend | recorded (2026-07-15) | this sweep |
|---|---|---|
| IBSL-Greyhound, n=10000, p=0.15 | 12,566 B (§10a) | **12,566 B** ✓ |
| IBSL-MerkleVC, n=10000, p=0.15 | 854 B (§10a) | **854 B** ✓ |
| IBSL-BDLOP, n=10000, p=0.15 | ~61 KB (§9a) | **61,180 B** ✓ |

**Why the p=0.5 heights differ from the 2026-07-14 record — and why it doesn't
matter:** n=1000 comes out height 11 (was 10) and n=10000 height 15 (was 13),
which carries into §4 and §5 (238,851 constraints at n=1000, vs 216,905 recorded
for 10 levels). Proof sizes scale with the levels, so nothing is inconsistent
internally.

Height is a random variable, and **both values are ordinary draws.** Sampling
the height distribution at p=0.5 over many seeds (heights depend only on
`coin()`, not on the backend):

| n | mean height | distribution |
|---|---|---|
| 1000 | 10.71 | h=9: 3% · **h=10: 39%** · **h=11: 44%** · h=12: 12% · h=13: 1% · h=14: 1% |
| 10000 | 13.88 | h=12: 2% · **h=13: 33%** · h=14: 47% · **h=15: 15%** · h=17: 3% |

At n=1000, height 11 is the *most likely* single outcome and height 10 is the
next; at n=10000, 15 is on the high side of a 13.88 mean but unremarkable.
Neither the old nor the new number is privileged.

What moved the draw is the **`coin()` rewrite** in `src/ibsl.rs` (uncommitted on
this branch as of writing). The committed version (b157d0b) hardcodes p=1/2 as a
parity test on the xorshift state; the working tree generalizes to arbitrary p
via a threshold:

```rust
self.rng & 1 == 1                  // committed: p = 1/2 only
self.rng < self.promote_threshold  // working tree: threshold = (p * 2^64) as u64
```

Both are p=0.5 in expectation and both consume the same xorshift stream from
seed 0xC0FFEE, but they are different *functions* of that stream, so a different
subset of nodes gets promoted. Same distribution, different sample. This is not
run-to-run flakiness — the seed fixes the draw, and re-running reproduces
height 11 exactly every time.

Reading the two documents together: §3/§4 of `RESULTS.md` are parity-coin
numbers, so at p=0.5 they are one sample and these are another — compare them as
such, not as before/after. The p=0.15 rows are directly comparable, because
§9a/§10a (2026-07-15) were already measured against the threshold coin.

If a future sweep wants heights stable across such changes, fix them explicitly
(pick a seed per n, or average over seeds) rather than relying on one draw.
