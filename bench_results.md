# IBSL vs plain Merkle tree — benchmark

Both structures use the Rescue hash over Winterfell's f128 — the configuration the STARK circuit (`crate::stark`) arithmetises. Sizes: [1000, 10000]. Single-run timings (per-op figures are averages over the op counts noted below).

- search: avg over 200 probes (members and misses alternating)
- prove / verify / proof size: avg over 10 evenly spread member keys
- insert / delete: avg over 2 fresh (odd) keys each
- STARK: one membership proof of the middle key per circuit; options 28 queries, blowup 8, ~96-bit conjectured; FRI hasher BLAKE3

## n = 1000 keys

### Native

| structure | build | search | prove | verify | insert | delete | proof size | proof shape |
|---|---|---|---|---|---|---|---|---|
| IBSL (Rescue Merkle VC) | 526.81ms | 780.00ns | 3.86µs | 1.79ms | 5.85ms | 4.59ms | 926 B | 11 (com, pi) pairs |
| Merkle tree (Rescue) | 147.11ms | 15.00ns | 581.00ns | 832.22µs | 153.91ms | 158.16ms | 328 B | 1 path, 10 siblings |

### STARK (Rescue circuit, f128)

| circuit | path cycles | trace rows | prove | proof size | verify |
|---|---|---|---|---|---|
| IBSL chain circuit | 25 | 256 | 10.68ms | 22880 B | 552.51µs |
| plain path circuit | 11 | 128 | 4.94ms | 19129 B | 236.17µs |

## n = 10000 keys

### Native

| structure | build | search | prove | verify | insert | delete | proof size | proof shape |
|---|---|---|---|---|---|---|---|---|
| IBSL (Rescue Merkle VC) | 5.12s | 1.82µs | 9.05µs | 2.73ms | 8.00ms | 6.99ms | 1368 B | 15 (com, pi) pairs |
| Merkle tree (Rescue) | 2.34s | 71.00ns | 724.00ns | 1.02ms | 2.33s | 2.36s | 456 B | 1 path, 14 siblings |

### STARK (Rescue circuit, f128)

| circuit | path cycles | trace rows | prove | proof size | verify |
|---|---|---|---|---|---|
| IBSL chain circuit | 42 | 512 | 16.85ms | 27896 B | 293.38µs |
| plain path circuit | 15 | 128 | 3.91ms | 19711 B | 201.84µs |

## Caveats

- IBSL insert/delete recompute commitments only along the affected path (O(log n) node commits, as in the paper), so IBSL updates are independent of n and much cheaper than a rebuild — the structural update advantage. Only the initial build commits every node.
- IBSL vector commitments are sized to each node's actual fan-out (typically 2-4 children with p = 1/2 promotion), so a node commit costs a handful of Rescue permutations and witness lengths vary per node.
- The plain Merkle tree still rebuilds globally on update (its own documented simplification), one tree of ~2n hashes, so its update cost grows with n where IBSL's does not.
- Timings are single runs on this machine, not statistics.

