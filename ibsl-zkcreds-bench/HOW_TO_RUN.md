# How to run every benchmark

Every benchmark in the project, what it measures, and what it costs to run.
Results from the last full sweep are in [`BENCHMARKS_2026-07-17.md`](BENCHMARKS_2026-07-17.md).

There are **two crates**, and benchmarks live in both:

| Crate | Path | Holds |
|---|---|---|
| `ibsl` | `~/IBSL` | The library — the IBSL structure, all VC backends (`src/vc/`), the STARK compiler, and its own native bench. |
| `ibsl-zkcreds-bench` | `~/IBSL/ibsl-zkcreds-bench` | Benchmark drivers only. Compares IBSL against zkcreds-rs. Owns no backend — it calls them from `ibsl`. |

If you are adding a backend, it goes in `~/IBSL/src/vc/`, not here. This crate
is only allowed to be ahead on *benchmarking*.

---

## 1. The `ibsl` crate's own bench (STARK / Rescue)

```bash
cd ~/IBSL
cargo run --release -- bench 1000 10000
```

IBSL over the Rescue Merkle VC vs a plain Rescue Merkle tree, natively and
then compiled to a Winterfell STARK (transparent, no trusted setup). Reports
build/prove/verify/insert, plus the STARK's cycles, proof size, and verify time
for both the IBSL chain circuit and the plain path circuit.

**~18 s** for both sizes. Also writes `~/IBSL/bench_results.md` — note it
**overwrites** that file each run.

Other entry points in this crate:

```bash
cargo run --release        # demo: every backend, over 20 credentials
cargo test                 # 36 tests; the two KZG ones take ~90 s
cargo test merkle          # filter by name
```

---

## 2. The comparison harness

```bash
cd ~/IBSL/ibsl-zkcreds-bench
cargo build --release
BIN=./target/release/ibsl-zkcreds-bench
```

Backends that cost a dependency are enabled on the `ibsl` dependency in
`Cargo.toml` (`features = ["mnt-kzg"]`), so they need no flag here.
Greyhound is the exception — see §3.

### zkcreds-rs baselines

```bash
$BIN zkcreds-merkle 11 15          # ~5 s
$BIN zkcreds-merkle-raw 1000 10000 # ~10 s
```

`zkcreds-merkle` takes **tree heights, not n** — capacity is 2^(h-1), so h=11
≈ n=1000 and h=15 ≈ n=10000. It runs zkcreds-rs's Groth16 Merkle membership
circuit (Poseidon over BLS12-381) through linkg16. `zkcreds-merkle-raw` runs
the same tree natively with no SNARK, and is the honest comparison point for
IBSL's native numbers.

### IBSL, native

```bash
$BIN ibsl-kzg 1000 10000            # ~4 min — build dominates
$BIN ibsl-merkle 0.15 1000 10000    # ~3 s
```

The leading float is the skip-list promotion probability `p`; a first argument
containing `.` is parsed as `p`, everything after is a size. Default: 0.5 for
`ibsl-merkle`. `p` is the main lever on proof size — see §7/§9a/§10 of
`RESULTS.md`.

`ibsl-merkle` prints both the sibling-hash-chain proof (Merkle mode, the row
comparable to `zkcreds-merkle-raw`) and the commitment-carrying proof.

### IBSL inside Groth16

```bash
$BIN kzg-selftest                # ~1 s — sanity-check MntKzgVc before the slow run
$BIN kzg-groth16 1000 10000      # ~8 min, peak ~2.6 GB
$BIN probe                       # <1 s — constraint counts only, no n
```

`kzg-groth16` re-verifies IBSL-KZG's opening chain inside a Groth16 circuit
over the MNT4-298/MNT6-298 cycle, so the pairing checks are native field
arithmetic. It reports constraints, CRS gen, prove, verify, proof size, and the
native IBSL numbers beside them. This box has 7 GB RAM — it fits, but don't run
it alongside anything heavy.

`probe` just counts constraints for the in-circuit primitives (pairings, scalar
muls). It takes no `n`, so it is size-independent by construction.

---

## 3. Greyhound — needs AVX512, so needs Intel SDE here

This machine is an i7-10750H (Comet Lake): **no AVX512**. Labrador's Greyhound
requires AVX512 + VAES, so the binary SIGILLs (exit 132) if run natively. It
must run under Intel's Software Development Emulator.

**Install SDE** (once — do *not* put it in `/tmp`, it will be cleaned up):

```bash
cd ~ && mkdir -p sde && cd sde
curl -LO https://downloadmirror.intel.com/850782/sde-external-9.53.0-2025-03-16-lin.tar.xz
tar xf sde-external-9.53.0-2025-03-16-lin.tar.xz
export SDE=~/sde/sde-external-9.53.0-2025-03-16-lin/sde64
$SDE -icx -- /bin/true && echo "SDE works"
```

**Build and run:**

```bash
cd ~/IBSL/ibsl-zkcreds-bench
cargo build --release --features greyhound
$SDE -icx -- ./target/release/ibsl-zkcreds-bench ibsl-greyhound 0.15 1000 10000
```

The `greyhound` feature forwards to `ibsl/greyhound`, which makes `~/IBSL/build.rs`
compile the labrador C sources from `~/labrador` with `-march=icelake-server`
(Ice Lake, not Skylake — `aesctr.c` needs VAES). The whole binary runs under
SDE; only the Greyhound code needs it.

> **Under SDE, proof sizes and verification results are real. ALL TIMINGS ARE
> VOID.** Emulation is 50–100× slow and non-uniform, hitting the AVX512 NTT
> hot path hardest. Never quote a Greyhound timing from this machine.

---

## Reproducing the whole sweep

Run them sequentially — parallel runs contaminate the timings:

```bash
cd ~/IBSL && cargo run --release -- bench 1000 10000
cd ~/IBSL/ibsl-zkcreds-bench
cargo build --release --features greyhound
BIN=./target/release/ibsl-zkcreds-bench
SDE=~/sde/sde-external-9.53.0-2025-03-16-lin/sde64
$BIN probe
$BIN zkcreds-merkle 11 15
$BIN zkcreds-merkle-raw 1000 10000
$BIN ibsl-merkle 0.5 1000 10000
$BIN ibsl-merkle 0.15 1000 10000
$BIN ibsl-kzg 1000 10000
$BIN kzg-groth16 1000 10000
$SDE -icx -- $BIN ibsl-greyhound 0.15 1000 10000
```

Total ≈ 25 min, dominated by `ibsl-kzg` and `kzg-groth16`.
