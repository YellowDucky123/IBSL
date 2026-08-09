# Groth16 head-to-head: zkcreds Merkle tree vs IBSL-KZG

Both sides prove *credential membership in zero knowledge with a Groth16
proof*, produced by the same Groth16 implementation — linkg16, the library
zkcreds-rs uses. What differs is the accumulator being proven against and,
by necessity, the curve:

| | zkcreds-rs Merkle tree | IBSL-KZG |
|---|---|---|
| Accumulator | sparse Merkle tree, Poseidon 2-to-1 hash | Interval-Based Skip List, KZG10 vector commitments |
| Statement proven | "my commitment is a leaf under public root" | "a chain of KZG openings links public sigma down to my key" |
| In-circuit work per level | 1 Poseidon hash (~330 constraints) | 1 KZG opening check: 2-pairing product + 2 G1 scalar muls + nonnative domain check (~22,000 constraints) |
| Curve (circuit / inner ops) | BLS12-381 (~128-bit) | MNT6-298 circuit over MNT4-298 KZG (~80-bit; a cycle is required so the pairing checks are native in-circuit) |
| Public input | attrs commitment + Merkle root | sigma (root commitment) coordinates |
| Hidden | leaf position, auth path | key, positions, all intermediate commitments and openings |
| Trusted setup | Groth16 CRS per tree height | Groth16 CRS per chain length + KZG SRS (powers of tau) |

Machine: 12-core WSL2, 7 GB RAM, 2026-07-14. Same harness
(`~/ibsl-zkcreds-bench`), subcommands `zkcreds-merkle` and `kzg-groth16`.

## Results at matched capacity

zkcreds tree height h holds 2^(h-1) leaves; rows are paired so capacity ≥ n.

| n (IBSL) / capacity (tree) | system | constraints | CRS gen | prove | verify | proof size |
|---|---|---|---|---|---|---|
| 100 / 2^7 | zkcreds tree (h=8) | 10,887 | 311 ms | 354 ms | 1.96 ms | 192 B |
| | IBSL-KZG (8 levels) | 173,013 | 6.8 s | 5.5 s | 3.4 ms | 190 B |
| 1,000 / 2^10 | zkcreds tree (h=11) | 15,276 | 388 ms | 359 ms | 1.86 ms | 192 B |
| | IBSL-KZG (10 levels) | 216,905 | 8.4 s | 11.5 s | 7.4 ms | 190 B |
| 10,000 / 2^14 | zkcreds tree (h=15) | 21,128 | 562 ms | 484 ms | 1.91 ms | 192 B |
| | IBSL-KZG (13 levels) | 282,743 | 10.5 s | 9.9 s | 3.7 ms | 190 B |
| — / 2^31 | zkcreds tree (h=32) | 45,999 | 1.41 s | 1.01 s | 1.92 ms | 192 B |

Prover-side data structure costs (outside the circuit), for context:

| n | IBSL-KZG native: build | prove (chain of openings) | verify (pairings) | native proof size |
|---|---|---|---|---|
| 1,000 | 29.2 s (MNT4-298) / 24.6 s (BLS12-381) | 70 ms / 101 ms | 28 ms / 31 ms | ~1,050 B |
| 10,000 | 281 s / 217 s | 94 ms / 130 ms | 35 ms / 36 ms | ~1,365 B |

(The zkcreds tree build is hashing-only and comparatively negligible:
inserting a leaf updates one Poseidon path.)

## Reading the numbers

- **Proof size and verify time are a wash.** Both are a single Groth16
  proof: ~190 B, single-digit-millisecond verification, independent of n.
  This is the point of compiling either accumulator down to Groth16.
- **Constraints: ~13-16x more for IBSL-KZG** at equal capacity. One
  Poseidon hash per Merkle level (~330 constraints) vs one full KZG
  opening verification per IBSL level (~22k: the 2-pairing product is
  9.3k, the two G1 scalar muls 6.7k, the nonnative z = omega^pos domain
  check 8.4k — pairing checks are cheap on the MNT cycle, but nothing is
  as cheap as a hash).
- **Prove time: ~15-25x slower for IBSL-KZG** (5.5-11.5 s vs 0.35-0.5 s),
  tracking the constraint ratio, worsened slightly by MNT6-298's larger
  320-bit field arithmetic vs BLS12-381's 255-bit scalar field.
- **CRS: ~20x larger generation time** for IBSL-KZG, same ratio driver.
  IBSL-KZG additionally needs the KZG powers-of-tau SRS (a second,
  universal trusted setup); the Merkle side's only setup is the Groth16
  CRS itself.
- **Where IBSL-KZG wins is outside the circuit**: its native proof is
  already compact (~1 KB) and verifies in ~30 ms of pairings with no
  Groth16 wrapper at all, so a deployment can serve verifiers that don't
  need zero-knowledge without ever invoking the prover above. (Native
  forms of both accumulators reveal the path/positions — the Groth16
  wrapper is what buys hiding in either case.) IBSL's structural
  advantages (updates touching only the affected path, interval-guided
  search) are not exercised by this membership benchmark.

## Caveats

- Curves differ by necessity (see table header): the IBSL-KZG side runs
  at ~80-bit security (MNT-298 cycle), the zkcreds side at ~128-bit
  (BLS12-381). A production IBSL-KZG would use a larger cycle (e.g.
  MNT-753, several times slower) or a different outer proof system; treat
  the ratios as favorable-to-IBSL-KZG lower bounds.
- The IBSL-KZG circuit's CRS is generated per chain length L; a
  deployment would fix L at the maximum skip-list height and pad.
- The seam map linking IBSL levels is a coordinate-packing prototype, not
  a vetted hash (see `../src/vc/mnt_kzg.rs`); a Poseidon seam would add only a
  few hundred constraints per level.
- Single-run timings (prove/verify averaged over a few iterations); no
  statistics.
