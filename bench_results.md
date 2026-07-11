# IBSL vs plain Merkle tree — benchmark

Both structures use the Rescue hash over Winterfell's f128 — the configuration the STARK circuit (`crate::stark`) arithmetises. Sizes: [1000, 10000, 100000]. Single-run timings (per-op figures are averages over the op counts noted below).

- search: avg over 200 probes (members and misses alternating)
- prove / verify / proof size: avg over 10 evenly spread member keys
- insert / delete: avg over 2 fresh (odd) keys each
- STARK: one membership proof of the middle key per circuit; options 28 queries, blowup 8, ~96-bit conjectured; FRI hasher BLAKE3

## n = 1000 keys

### Native

| structure | build | search | prove | verify | insert | delete | proof size | proof shape |
|---|---|---|---|---|---|---|---|---|
| IBSL (Rescue Merkle VC) | 555.89ms | 1.37µs | 4.21µs | 1.86ms | 528.43ms | 532.45ms | 937 B | 10 (com, pi) pairs |
| Merkle tree (Rescue) | 144.92ms | 14.00ns | 483.00ns | 763.06µs | 148.36ms | 151.71ms | 328 B | 1 path, 10 siblings |

### STARK (Rescue circuit, f128)

| circuit | path cycles | trace rows | prove | proof size | verify |
|---|---|---|---|---|---|
| IBSL chain circuit | 28 | 256 | 8.79ms | 22687 B | 245.87µs |
| plain path circuit | 11 | 128 | 5.56ms | 19129 B | 232.16µs |

## n = 10000 keys

### Native

| structure | build | search | prove | verify | insert | delete | proof size | proof shape |
|---|---|---|---|---|---|---|---|---|
| IBSL (Rescue Merkle VC) | 5.28s | 1.67µs | 4.17µs | 2.27ms | 5.13s | 5.19s | 1163 B | 13 (com, pi) pairs |
| Merkle tree (Rescue) | 2.35s | 77.00ns | 755.00ns | 1.10ms | 2.35s | 2.31s | 456 B | 1 path, 14 siblings |

### STARK (Rescue circuit, f128)

| circuit | path cycles | trace rows | prove | proof size | verify |
|---|---|---|---|---|---|
| IBSL chain circuit | 33 | 512 | 17.32ms | 28800 B | 341.05µs |
| plain path circuit | 15 | 128 | 4.34ms | 19711 B | 214.64µs |

## n = 100000 keys

### Native

| structure | build | search | prove | verify | insert | delete | proof size | proof shape |
|---|---|---|---|---|---|---|---|---|
| IBSL (Rescue Merkle VC) | 52.34s | 47.07µs | 7.02µs | 3.19ms | 51.64s | 51.67s | 1590 B | 18 (com, pi) pairs |
| Merkle tree (Rescue) | 18.82s | 1.00µs | 5.55µs | 1.25ms | 18.80s | 18.73s | 552 B | 1 path, 17 siblings |

### STARK (Rescue circuit, f128)

| circuit | path cycles | trace rows | prove | proof size | verify |
|---|---|---|---|---|---|
| IBSL chain circuit | 44 | 512 | 17.10ms | 27931 B | 355.07µs |
| plain path circuit | 18 | 256 | 8.29ms | 22238 B | 221.18µs |

## Caveats

- This IBSL implementation recomputes ALL commitments after every insert/delete (a documented simplification; the paper updates only the O(log n) affected path), so IBSL updates here cost about one full rebuild and do NOT show the theoretical update advantage.
- IBSL vector commitments are sized to each node's actual fan-out (typically 2-4 children with p = 1/2 promotion), so a node commit costs a handful of Rescue permutations and witness lengths vary per node.
- The plain Merkle tree rebuilds on update too, but its rebuild is one tree of ~2n hashes total, not ~2n node-trees of 1023 hashes.
- Timings are single runs on this machine, not statistics.

