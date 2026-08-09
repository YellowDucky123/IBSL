# IBSL over Greyhound — real positional opening + single-proof aggregation

Date: 2026-07-24. Machine: 12-core WSL2, 7 GB RAM, **no AVX512** → all
Greyhound runs under Intel SDE (`sde64 -icx`). **Under SDE, proof sizes and
verification results are real; all timings are void** (emulation is 50–100×
slow and non-uniform — the timing columns below are kept only to show relative
prove/verify cost, not wall-clock truth).

## What changed

The previous Greyhound backend did **not** use Greyhound's opening algorithm.
It committed each slot value as the constant term of one ring element, then
"opened" a node by *revealing the whole child vector* plus a bare evaluation
proof — O(fan-out) field elements per level, and no Labrador proof at all. The
per-node framing in the old notes ("a poor per-node backend") was an artifact
of that wrapper, not of Greyhound.

Two things are fixed in the shim (`~/labrador/greyhound_shim.c`) and the Rust
FFI (`src/vc/greyhound.rs`):

1. **True positional opening.** A node commits to the **interpolant** of its
   slot values: `p(z_i) = m[i]` at public points `z_i = i+1`. Opening slot `i`
   is a Greyhound evaluation proof at `x = z_i`. The opening reveals *only*
   that slot's value — the committed vector never goes on the wire. (Same
   Lagrange-basis idea that makes KZG a vector commitment.) `N = 64`
   coefficients per ring element, so one commitment holds up to `16·64 = 1024`
   slots, far above any IBSL fan-out.

2. **One aggregated Labrador proof per IBSL proof, not per node.** Each
   evaluation proof reduces (`polcom_reduce`) to a Labrador *principal
   statement*. Instead of proving each with its own composite, the L
   statements along a membership path are stacked block-diagonally into one
   principal statement (witness slots concatenated, each block's constraint
   indices shifted by `4·j`) and a **single** `composite_prove_principle`
   covers the whole path. This is wired through the existing `AggregatableVc`
   trait (`Ibsl::prove_agg` / `verify_agg`).

A commitment is `H(u1)` (16 B); `check` recomputes `H(u1)` from the opening and
compares — that comparison is what binds an opening to a commitment.

## Results (verified under SDE)

Every row below **verifies** (both modes). "eval proofs" = Greyhound's own
`(u1, u2)` per level, present in both modes; "Labrador" = the composite
proof(s) that certify the evaluations.

| n | p | levels | mode | eval proofs | Labrador | **total proof** | agg savings |
|---|---|---|---|---|---|---|---|
| 30 | 0.15 | 3 | per node | 6.0 KB | 56.0 KB (3×) | 62.0 KB | |
| 30 | 0.15 | 3 | **aggregated** | 6.0 KB | 30.8 KB (1×) | **36.8 KB** | **1.69×** |
| 30 | 0.5 | 5 | per node | 10.0 KB | 93.2 KB (5×) | 103.2 KB | |
| 30 | 0.5 | 5 | **aggregated** | 10.0 KB | 34.1 KB (1×) | **44.1 KB** | **2.34×** |
| 200 | 0.5 | 7 | per node | 14.0 KB | 130.5 KB (7×) | 144.5 KB | |
| 200 | 0.5 | 7 | **aggregated** | 14.0 KB | 35.8 KB (1×) | **49.8 KB** | **2.90×** |
| 10000 | 0.15 | 6 | per node | 12.0 KB | 112.0 KB (6×) | 124.0 KB | |
| 10000 | 0.15 | 6 | **aggregated** | 12.0 KB | 34.9 KB (1×) | **46.9 KB** | **2.64×** |

The n=10000 / p=0.15 / height-6 row is the exact configuration behind the old
"12,566 B" Greyhound figure (RESULTS.md §10a). The **eval-proofs column here is
12.0 KB** — the same number — confirming the old figure counted *only* the
Greyhound eval proofs and omitted the Labrador proof entirely. The 34.9 KB
aggregated Labrador is the previously-missing self-contained proof, and it sits
in the same ~30–36 KB band as heights 3 and 7 (it does not grow with depth).
(n=10000 under SDE: 3m38s wall, 1.0 GB peak RSS — dominated by building 10k
Greyhound commitments, not proving.)

The one aggregated Labrador proof stays ~**30–36 KB regardless of path
length**, while the per-node total grows linearly (~18.6 KB composite ×
levels). The aggregated proof additionally carries the L node commitments (16 B
each) in `AggProof::steps` — negligible (48–112 B). So the savings grow with
tree height: the deeper the membership path, the more aggregation wins.

- One node commitment: **16 B**.
- One Greyhound eval proof `(u1, u2)`: **2048 B** (`2·kappa1·N·LOGQ/8`).
- One aggregated Labrador composite over the whole path: **~30–36 KB**.

## Parameter note

`MIN_LEN = 16` ring elements. Greyhound's parameter search does not produce a
*provable* parameter set at len 8 or 32 (the composite fails to verify even in
upstream's own `test_small2` flow); 16 and 64+ are sound, and 16 is the
smallest working choice, so every IBSL node pads up to it.

## A subtlety worth recording: comkey stability

`init_comkey` **grows the global `comkey` by reallocation** — the buffer
moves. `polcom_reduce` stores raw pointers into it (`cnst->phi[i] =
&comkey[…]`), so a statement built *before* a growth is left dangling and its
proof fails to verify. Merged (aggregated) statements are G× larger and are
exactly what triggers a mid-flight growth. Because existing key entries are
regenerated verbatim across a growth, the shim just marks `comkey_len`, does
the work, and retries once if the key moved (`GH_KEY_RETRIES`). This is the
cause of the "Aggregated dot-product constraint doesn't hold" failures seen
before the fix.

## How to reproduce

```bash
SDE=~/sde/sde-external-9.53.0-2025-03-16-lin/sde64
cd ~/IBSL/ibsl-zkcreds-bench
cargo build --release --features greyhound
$SDE -icx -- ./target/release/ibsl-zkcreds-bench ibsl-greyhound 0.5 30
```

Correctness tests (positional open, commitment binding, both IBSL modes):

```bash
cd ~/IBSL
cargo test --features greyhound --test greyhound --no-run
$SDE -icx -- ./target/debug/deps/greyhound-*  --test-threads=1
```
