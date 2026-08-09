# Greyhound batching in the IBSL — the paper's version

Date: 2026-07-25. Machine: 12-core WSL2, 7 GB RAM, **no AVX512** → all runs
under Intel SDE (`sde64 -icx`). **Under SDE, proof sizes and verification
results are real; all timings are void.**

Supersedes the aggregated mode described in `GREYHOUND_AGGREGATION.md`, which
was a Labrador-level statement merge, not Greyhound batching. Both still exist
in the C; the Rust `AggregatableVc` impl now uses the batched one.

## What changed

Greyhound's paper batches in §3.2 (Figure 2) and §4.4. The batching is a
**shared commitment**, formed *before* Labrador ever runs:

```
v := D_0 ŵ_0 + D_1 ŵ_1 + … + D_{L-1} ŵ_{L-1}
```

One `v` for the whole path instead of one `u2` per level. The previous
aggregated mode did something different — it took `L` *finished* principal
statements and stacked them block-diagonally, which shares the Labrador
composite but leaves every block with its own `u1` **and** `u2`. So the wire
still carried `2L` commitments. Batching brings that to `L+1`: the `u1_j` stay
per-level because they *are* the node commitments and are on the wire anyway.

Two things this surfaced that are worth recording:

1. **The `D_j` must be disjoint blocks of the commitment key.** With a shared
   `D`, `v = Σ_j D ŵ_j` binds nothing about the individual `ŵ_j` — a prover can
   move mass between them. Upstream reads `A`, `B` and `D` all from `comkey[0…]`
   (fine for one instance); `greyhound_batch.c` gives each instance its own `D_j`
   slice past everything else the protocol reads.

2. **The old merged mode never rechecked its own norm bound.** A batched
   principal statement carries ONE norm bound covering every block, and it has
   to be the *sum* of their norms — nothing stops a cheating prover
   concentrating the budget in one block, so a per-block bound is not sound.
   `build_merged` in the shim sums the blocks' `betasq` but only checks it
   against `JLMAXNORMSQ`; the commitment parameters were chosen by
   `polcom_reduce` for a *single* instance's norm and are never revisited.
   The batched path does check, in `polcom_batch_reduce` — which is why it needs
   larger commitment parameters (`polcom_commit_batch`, sized at commit time for
   `GH_BATCH_MAX` levels). **That cost is real and is included below.**

## Results (all verified under SDE)

Every row below verifies in both modes. "eval proofs" is Greyhound's own
commitments — `2L` per node, `L+1` batched. "Labrador" is the composite(s).

| n | p | levels | mode | eval proofs | Labrador | **total** |
|---|---|---|---|---|---|---|
| 30 | 0.15 | 3 | per node | 7.5 KB | 58.9 KB (3×) | 66.4 KB |
| 30 | 0.15 | 3 | **batched** | 5.0 KB | 31.5 KB (1×) | **36.5 KB** |
| 30 | 0.5 | 5 | per node | 12.5 KB | 98.3 KB (5×) | 110.8 KB |
| 30 | 0.5 | 5 | **batched** | 7.5 KB | 34.8 KB (1×) | **42.3 KB** |
| 1000 | 0.15 | 5 | per node | 12.5 KB | 98.3 KB (5×) | 110.8 KB |
| 1000 | 0.15 | 5 | **batched** | 7.5 KB | 34.7 KB (1×) | **42.2 KB** |
| 60 | 0.5 | 6 | per node | 15.0 KB | 118.0 KB (6×) | 133.0 KB |
| 60 | 0.5 | 6 | **batched** | 8.8 KB | 34.9 KB (1×) | **43.7 KB** |
| 200 | 0.5 | 7 | per node | 17.5 KB | 137.6 KB (7×) | 155.1 KB |
| 200 | 0.5 | 7 | **batched** | 10.0 KB | 36.0 KB (1×) | **46.0 KB** |
| 100 | 0.5 | 8 | per node | 20.0 KB | 157.2 KB (8×) | 177.2 KB |
| 100 | 0.5 | 8 | **batched** | 11.2 KB | 36.5 KB (1×) | **47.7 KB** |

## Batched vs the old merged mode

This is the honest comparison, and it is a modest win — not a dramatic one.

| levels | merged (old) | batched (new) | |
|---|---|---|---|
| 3 | 36.8 KB | 36.5 KB | −1% |
| 5 | 44.1 KB | 42.3 KB | −4% |
| 7 | 49.8 KB | 46.0 KB | −7.6% |

The eval-proof column improves a lot (`2L → L+1` commitments), but a batch-ready
commitment is 1.25 KB instead of 1.0 KB (`kappa1` 4 → 5) because of the summed
norm bound, which eats most of it. Algebraically the wire cost goes from
`2L × 1.0` to `(L+1) × 1.25`, so batching wins from **L = 2** and tends to a
37.5% ceiling on eval data as L grows. The composite also grows slightly
(35.8 → 36.0 KB at L=7) for the same parameter reason.

So: the batched mode is *somewhat* smaller and, unlike the merged mode, its
commitment parameters actually cover the norm bound its own statement asserts.
The soundness fix is the bigger part of the change; the bytes are a bonus.

## What is still not batched

`u = Σ_j B_j t̂_j` from relation (7). The paper sums the outer commitments too,
but in the IBSL each `u1_j` is a node commitment that has to be on the wire
regardless (it binds into its parent's slot), so summing them saves zero bytes.
It would only remove `L−1` constraints from the statement, and would force
every node to be committed under a level-indexed key slice. Not worth it.

Also note **Remark 3.5**: with one polynomial per evaluation point — which is
exactly the IBSL path, `k = L` distinct points, `L_j = 1` — the paper says its
batching "does not differ from trivially concatenating proofs" *asymptotically*.
The concrete win here is entirely the shared `v`; there is no asymptotic gain to
be had at `L_j = 1`. Getting more would mean opening several node polynomials at
the *same* point, which is an encoding change, not a protocol one.

## Where the code is

| | |
|---|---|
| `~/labrador/greyhound_batch.{c,h}` | batch commit, eval, reduce, comkey reservation |
| `~/labrador/greyhound_shim.c` | `gh_batch_prove` / `gh_batch_verify` / accessors |
| `~/labrador/test_batch.c` | standalone C round-trip, `./test_batch [nb] [len]` |
| `~/IBSL/src/vc/greyhound.rs` | `AggregatableVc` impl, now the batched path |

### A trap worth remembering

`init_comkey` grows the global commitment key by allocating a new buffer and
freeing the old one — **the key moves**. `polcom_batch_reduce` stores raw
pointers into it (`cnst->phi[j] = &comkey[…]`), and both `principle_prove` and
`principle_reduce` begin with `init_statement`, which sizes the key from the
statement's multiplicity. Past about six batched levels that is larger than
anything the commitments asked for, so the key moved out from under a statement
already pointing into it and the prover read freed memory (SDE: *"Could not read
memory … nbytes=64"*, at n=100 but not n=60). `polcom_batch_reserve_prove` /
`_verify` force that first growth on a throwaway statement, before any
constraint points into the key. Growth later in the composite recursion is
harmless — `principle_prove` is done with the principal statement by then.
