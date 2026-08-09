# Why the benchmarked IBSL is ~1000x slower than the plain Merkle tree

(Analysis of an earlier `bench_results.md` run. STATUS: fix 1 below — the
MAX_FANOUT padding — is DONE: `MerkleVc` sizes each tree to the vector
actually committed. Item 3 of the accounting — `prove` re-deriving node
trees — is also DONE: `commit` now returns a prover-side `Opener` (Merkle:
the tree layers) stored in each node, so proving recomputes nothing
(n=1000 native prove: 717ms -> 3.8us). `bench_results.md` holds the
post-fix numbers. Fix 2 — path-only recompute on insert/delete — is still
TODO and is why update times still track build times.)

It's not the IBSL design — it's two implementation shortcuts, and the measured
numbers are almost exactly accounted for by them. A faithful IBSL should be
within a small constant factor of the flat tree, not 1000x.

## The accounting

Every measured gap traces back to hash counts (a Rescue permutation is ~69us
on this machine, and both structures pay the same per hash):

**1. Every node commit pads to the full MAX_FANOUT = 512** (`src/ibsl.rs`
`MAX_FANOUT`; `MerkleVc::commit` pads to the `setup` width). A node with 2
children — or a leaf committing to the single-element vector `[key]` — still
hashes a full 512-leaf tree = **1023 permutations**. The build does this for
~2n nodes:

- IBSL build: ~2,000 nodes x 1023 ≈ 2M permutations x 69us ≈ **139s**
  (measured 138.9s)
- Flat tree build: ~2,000 permutations ≈ **138ms** (measured 138.3ms)

That's the entire 1000x ratio. With p = 1/2 promotion, typical fanout is
~2–4, so a right-sized node commit is ~3–7 hashes, not 1023. This one
artifact is ~150–300x of the slowdown.

**2. `recompute()` is global** (`src/ibsl.rs`, documented simplification):
every insert/delete recommits *all* nodes, so update ≈ build ≈ 138s. The
paper updates only the O(log n) affected path — with right-sized trees that's
~tens of hashes, i.e. **milliseconds**. The flat tree meanwhile rebuilds all
2n hashes (138ms) and can never do better; this is the column IBSL is
supposed to *win*.

**3. `prove` re-derives each node's whole 512-leaf tree per opening**
(`MerkleVc::open` calls `layers()`): 10 levels x 1023 ≈ 706ms (measured
718ms). Right-sized, that's microseconds.

## The one honest number in the table

Native **verify** has no padding artifact in play (checking 9 siblings costs
9 merges regardless): 6.9ms vs 0.8ms ≈ 8.6x — that's 10 levels x 10 hashes
vs one 11-hash path. With realistic fanout-2 trees it'd be ~3x. *That* is
the true structural price of commitments-of-commitments, and it's what the
STARK ratio (100 vs 11 trace cycles) reflects too.

## Fixes, ranked by effort

So: yes, the simplified version. The design's asymptotics are fine — this
implementation trades them away for simplicity in exactly two places. To
make the benchmark reflect the real design:

1. **Size each node's Merkle tree to its actual fanout** (commit at
   `children.len().next_power_of_two()`) — small change to
   `MerkleVc`/`ibsl.rs`, fixes build/prove/insert constants, ~2 orders of
   magnitude. Witness lengths become variable, which the STARK segments
   already handle.
2. **Path-only recompute** on insert/delete — restores the O(log n) update
   advantage, the actual selling point vs. the flat tree.
