# IBSL flat-hash chain: Winterfell STARK vs Stwo Circle STARK

2026-07-30. Driver: `ibsl-zkcreds-bench ibsl-flat-stwo [p] [n...]`
(needs `--features stwo` **and a nightly toolchain** — `nightly-2026-01-15`
was used here; the stwo crate uses unstable std features and does not build
on stable).

The same IBSL membership statement, proven by two different STARK provers.

| side | in-circuit hash | field | prover | commitment hash |
|---|---|---|---|---|
| Winterfell | Rescue-128 | f128 | `ibsl::stark::flat` (MerkleAir) | BLAKE3 |
| Stwo | Poseidon2, width 16 | M31 | `ibsl::stark::stwo` (`ChainEval`) | Poseidon252 |

Both structures are built from the same keys, the same promotion probability
and the same RNG seed, so the two chains are shape-identical: same height,
same number of 2-to-1 merges. The driver asserts that
(`chain.merges.len() == cycles`). Digests are 32 bytes on both sides (2 f128
elements vs 8 M31), so the native proofs line up too.

## Results, p = 0.15, 10 evenly spread member keys per row

| n | height | merges | wf proof | wf prove | wf verify | stwo trace | stwo proof | stwo prove | stwo verify | Greyhound total (ref) |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 000 | 5 | 10 | 20 384 B | 7.9 ms | 259 µs | 16 x 301 | **44 968 B** | 57 ms | 15.9 ms | 42 200 B |
| 10 000 | 6 | 24 | 24 714 B | 15.5 ms | 304 µs | 32 x 301 | **48 744 B** | 109 ms | 21.5 ms | 46 900 B |

Security is matched: 28 queries, blowup 8, no grinding, ~84-bit conjectured
on both sides. The Winterfell column reproduces the sizes recorded in
`BENCHMARKS_2026-07-17.md` §9-10 exactly. Timings are from an otherwise idle
machine; sizes are deterministic.

### The Greyhound column

These are **total** proofs — Greyhound eval proofs *plus* the LaBRADOR
composite: 42.2 KB at 5 levels (batched, `GREYHOUND_BATCHING.md`) and 46.9 KB
at 6 levels (merged, `GREYHOUND_AGGREGATION.md`; batching was never re-run at
n = 10 000, and its 6-level datapoint is 43.7 KB, so this slightly
over-states it).

They are **not** the "10 430 / 12 566 B" of `BENCHMARKS_2026-07-17.md` §9-10,
which this file and `ibsl_flat_stark.rs` both quoted until 2026-07-30. Those
counted the Greyhound eval proofs alone and omitted the LaBRADOR proof — i.e.
the bulk of it. `GREYHOUND_AGGREGATION.md:58` records the correction: the
eval-proofs column at n = 10 000 / p = 0.15 / height 6 *is* 12.0 KB, matching
the old figure exactly, and the missing 34.9 KB is the composite that makes
the proof self-contained. Both drivers now carry the corrected constants.

So the real standing at this security level: Winterfell ~20-25 KB, Stwo
~45-49 KB, Greyhound ~42-47 KB. Stwo is at rough parity with the lattice PCS,
not 4x worse; Winterfell is the smallest of the three. (Trust models still
differ — both STARKs are transparent and hide the key and the chain; the
Greyhound rows are native openings.)

### Where the Stwo bytes go

| n | queried trace values | OODS samples | trace decommitments | FRI |
|---|---|---|---|---|
| 1 000 | 29 856 | 5 104 | 4 896 | 1 408 |
| 10 000 | 32 344 | 5 104 | 6 528 | 2 016 |

Two thirds of the proof is queried trace values, which cost
`n_queries x n_columns x 4 B` — independent of chain length. That is why the
Stwo proof barely grows from n = 1 000 to n = 10 000 (+8%) while Winterfell's
grows 21%, and it is the lever that matters: **this trace is 301 columns wide
and only 16-32 rows tall.** A layout with one Poseidon2 *round* per row
instead of one whole permutation would be ~35 columns and ~22x more rows,
cutting queried values roughly 9x at the price of a deeper Merkle tree and
more FRI layers. Not implemented here.

## Two findings worth recording

**1. Stwo caps constraint degree at 3.** Its current "lifted protocol" only
accepts `max_constraint_log_degree_bound == log_size + 1`; anything higher
fails the prover's own OODS sanity check with `ConstraintsNotSatisfied`, and
within that bound constraints of degree >= 4 fail too. This is not a quirk of
this circuit — upstream's own Poseidon2 example test is `#[ignore]`d with
*"AIRs with constraint degree >= 2 are not supported yet in the lifted
protocol"* (`crates/examples/src/poseidon/mod.rs`, HEAD 88e95ba, 2026-07-23).
Verified independently on a minimal 2-column component: degree 2 and 3 prove,
degree >= 4 does not, at any lifting size.

Consequence: the Poseidon2 x^5 S-box cannot be one constraint. Each S-box
commits an auxiliary `aux = x^2` and writes x^5 as `aux * aux * x`, degree 3.
That is one extra column per S-box — 16 per full round, 1 per partial round —
taking the permutation block from 158 to **300 columns**. The proof would be
materially smaller if Stwo lifted the cap.

**2. `PcsConfig::lifting_log_size` must be set explicitly when
`max_constraint_log_degree_bound > log_size`.** Its default is applied at
proving time, after the trace trees are already committed at their own
height, so query indices drawn on the larger composition domain run off the
end of the shorter columns and the prover panics inside `decommit`. Moot once
constraints are degree <= 3 (the sizes coincide), but it is what the first
attempt hit.

## Soundness note on the preprocessed columns

The circuit uses two preprocessed selector columns, `is_first` (kills the
chain constraint's wrap-around at row 0) and `is_last` (pins the end of the
chain to sigma). Stwo's examples commit the preprocessed tree and never check
its contents, which would let a prover move `is_last` and stop the chain
early. `stwo::verify` closes this: it regenerates both columns from the
public parameters `(log_n_rows, last_row)` and requires the recomputed root
to equal `proof.commitments[0]`. Test: `moved_last_row_rejected`.

## Reproducing

```sh
cd ibsl-zkcreds-bench
CARGO_TARGET_DIR=<nightly-target> rustup run nightly-2026-01-15 \
    cargo run --release --features stwo -- ibsl-flat-stwo 0.15 1000 10000
```

Use a separate `CARGO_TARGET_DIR` for nightly so the stable `target/` is not
thrashed. Tests: `cargo test --release --features stwo --lib stark::stwo`
(7 tests, nightly).
