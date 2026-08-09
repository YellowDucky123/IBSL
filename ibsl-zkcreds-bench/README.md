# ibsl-zkcreds-bench

Benchmark harness comparing membership proofs in **zkcreds-rs** (Groth16
Merkle tree) against **IBSL** (Interval-Based Skip List) backends, and —
the main event — running **IBSL-KZG inside the Groth16 used by zkcreds-rs**
(linkg16).

Layout of the three repos this harness expects as siblings:

```
~/IBSL                # the IBSL crate (used as a library)
~/zkcreds-rs          # https://github.com/rozbb/zkcreds-rs (one-line fix: linkg16 dep ssh -> https)
~/ibsl-zkcreds-bench  # this crate
```

## Subcommands

```
cargo run --release -- zkcreds-merkle [h1 h2 ...]
    zkcreds-rs's own TreeMembershipProver circuit (Poseidon two-to-one hash,
    BLS12-381), driven directly through linkg16's Groth16: constraint count,
    CRS generation, prove, verify, proof size. Heights default to
    11 15 18 32 (capacity 2^(h-1) leaves).

cargo run --release -- ibsl-kzg [n1 n2 ...]
    IBSL with its KZG10 backend (BLS12-381, ark 0.6), native operations:
    build, prove (chain of KZG openings), verify (2 pairings per level),
    proof size. Defaults: 1000 10000.

cargo run --release -- kzg-selftest
    Sanity check of the MNT4-298 KZG vector-commitment backend under
    Ibsl<V> (native prove/verify round trip).

cargo run --release -- kzg-groth16 [n1 n2 ...]
    IBSL-KZG membership re-verified INSIDE Groth16 (linkg16). KZG lives on
    MNT4-298; the circuit is over MNT6-298, whose scalar field equals
    MNT4-298's base field, so every KZG pairing check
        e(com - v*G + z*W, H) = e(W, beta*H)
    is native in-circuit arithmetic (~22k constraints per IBSL level).
    Public input: the root commitment sigma. Hidden: the key, the path
    positions, all intermediate commitments and openings. Default: 1000.

cargo run --release -- probe
    Constraint-cost microprobe for the MNT4-in-MNT6 gadgets (pairing,
    scalar mul, nonnative arithmetic) used to size the circuit above.
```

## Why the curve change for `kzg-groth16`

IBSL's own KZG backend lives on BLS12-381. Verifying a KZG opening is a
pairing equation, and a Groth16 circuit over BLS12-381's scalar field
cannot check BLS12-381 pairings without simulating ~381-bit base-field
arithmetic (millions of constraints per pairing; no gadget exists in the
arkworks 0.3 ecosystem zkcreds-rs uses). The standard construction is a
pairing-friendly cycle: MNT4-298 and MNT6-298, where each curve's base
field is the other's scalar field, and `ark-r1cs-std` 0.3 ships a
`PairingVar` for exactly this. The KZG backend is otherwise a faithful
port of IBSL's `vc/kzg.rs` (same insecure seeded SRS stance, same
interpolation domain), with one substitution: the seam map
`to_field(commitment)` packs 249 x-coordinate bits + the y-parity bit
instead of hashing bytes with SHA-256, so the chain linkage is nearly free
in-circuit. Both 298-bit curves offer ~80-bit security (fine for
benchmarking; production would use a larger cycle or a different outer
system).

## Caveats

- The Groth16 CRS here is generated per chain length L (the circuit shape
  depends on it). A deployment would fix L to the maximum height and pad.
- The MNT4-298 KZG SRS comes from a seeded RNG (insecure by construction,
  same as IBSL's demo BLS setup).
- The seam map is not a vetted collision-resistant hash (see module docs
  in `../src/vc/mnt_kzg.rs`); swapping in Poseidon over MNT6-Fr would add a few
  hundred constraints per level.
- Timings are single runs (few-iteration averages for prove/verify) on one
  machine; no statistics.
