//! Basic implementation of the Interval Based Skip List (IBSL) from
//! "New Construction on Zk-Creds Credential System".
//!
//! What is covered (in simplified form):
//!   - Setup (Appendix A.2): bottom-up build with probabilistic promotion
//!     (p = 1/2), shortcut paths via the redundant-node rule, interval
//!     labelling (Definition 1), and authenticated node commitments (below).
//!   - Search: interval-guided descent (Definition 2 / Section A.1).
//!   - Insert (Appendix A.3): cases 1 and 2. The overflow split (case 5) and
//!     the fan-out invariant (Definition 3) are NOT implemented.
//!   - Delete (Appendix A.4): leaf + tower removal with pointer bypassing.
//!     No rebalancing (A.5).
//!   - Prove / Verify: membership proof along the search path, checked
//!     against the root commitment sigma.
//!
//! Authentication is layered commitments-of-commitments. A leaf commits to
//! its own key; every node above commits to the vector of the *compact*
//! (public-facing) commitment values of ALL of its children, in order:
//!
//! ```text
//! c_leaf = Com(key)        c_v = Com(f(c_1), ..., f(c_m))
//! ```
//!
//! where c_1..c_m are the commitments of v's children and f maps a compact
//! commitment value into the scalar field. Each node keeps its compact
//! value plus the prover-side opener state `commit` produced, so proving
//! opens positions by lookup with no recomputation; only the compact value
//! is embedded in the parent's vector and published. A membership proof for k is a list of
//! (commitment, opening) pairs, one per level top-down along the path:
//!
//! ```text
//! pi = {(com_1, pi_com_1), ..., (com_n, pi_com_n)}
//! ```
//!
//! where com_1 is the root (sigma), com_n is the leaf, and each opening
//! pi_com_i reveals the next thing inside com_i — f(com_{i+1}) for an upper
//! node, or the key k itself at the leaf. Verification checks the first
//! commitment is the trusted sigma and then verifies every pair on its own.
//!
//! Merkle mode (`prove_hash` / `verify_hash`, any `HashVc` backend): the same
//! tree, but the proof drops the carried per-level commitments and becomes a
//! plain Merkle-style sibling-hash chain — the verifier recomputes each node's
//! hash bottom-up from the child hash below plus the opened siblings, and
//! checks the top equals sigma. At promotion p = 0.5 (fan-out ~2) this is on
//! par with a plain binary Merkle tree's authentication path.
//!
//! The commitment scheme is pluggable: `Ibsl<V>` works with any
//! `VectorCommitment` backend — KZG10 (kzg.rs) or a Merkle tree (merkle.rs)
//! over any of the hashes in `crate::hashes` — and so is the scalar field
//! itself (`crate::field::NodeDigest`): arkworks' BLS12-381 Fr for the KZG /
//! Poseidon / byte-hash backends, Winterfell's f128 for the Rescue backend
//! whose proofs `crate::stark` re-verifies in a STARK.
//!
//! Insert and delete recompute intervals and commitments only along the
//! affected path (O(log n) commits, as in the paper): the owner of k's key
//! range at each level plus the same-level predecessors whose child ranges
//! the update splits or merges. Only the initial build commits everything.
//!
//! Simplifications, on purpose:
//!   - nodes live in a `HashMap` keyed by an allocated id; after a delete the
//!     nodes no longer reachable from any head are garbage-collected;
//!   - keys are u64 (in the credential system these would be commitments com_i);
//!   - the KZG SRS comes from an insecure seed-derived setup (see kzg.rs).

use crate::field::NodeDigest;
use crate::vc::{AggregatableVc, HashVc, VectorCommitment};
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};

type NodeId = usize;

const MAX_HEIGHT: usize = 32;

/// Upper bound on a node's fan-out (children per node) the VC is set up
/// for; committing a wider vector panics. No fan-out invariant (Definition
/// 3) is enforced, and insert's Case-2 dismissals can pile children onto a
/// level head, so this needs generous headroom over the geometric typical
/// case.
const MAX_FANOUT: usize = 512;

/// Keys of the base layer are bounded by the sentinels -inf and +inf.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Key {
    NegInf,
    Val(u64),
    PosInf,
}

impl Key {
    /// Injective, order-preserving embedding into the scalar field:
    /// -inf -> 0, v -> v + 1, +inf -> 2^64 + 1. Generic over the field so
    /// any backend (arkworks Fr, Winterfell f128, ...) can plug in.
    pub(crate) fn field<F: NodeDigest>(&self) -> F {
        match self {
            Key::NegInf => F::from_u128(0),
            Key::Val(v) => F::from_u128(*v as u128 + 1),
            Key::PosInf => F::from_u128((1u128 << 64) + 1),
        }
    }
}

type Interval = (Key, Key);

fn in_interval(k: Key, iv: Interval) -> bool {
    iv.0 <= k && k <= iv.1
}

struct Node<V: VectorCommitment> {
    key: Key,
    level: usize, // 1 = base layer L_1
    interval: Interval,
    /// May point to a node at a *lower* level: that is a shortcut path.
    right: Option<NodeId>,
    down: Option<NodeId>,
    /// The children this node owns, left to right (empty at L_1).
    children: Vec<NodeId>,
    /// The compact (public-facing) commitment value, plus the prover-side
    /// opener state `commit` produced with it (Merkle: the tree layers), so
    /// `prove` opens positions by lookup without recomputing anything. A
    /// leaf commits to [key]; an upper node to its children's compact
    /// commitment values.
    commitment: V::Commitment,
    opener: Option<V::Opener>,
}

impl<V: VectorCommitment> Node<V> {
    fn new(key: Key, level: usize) -> Self {
        Node {
            key,
            level,
            interval: (key, key),
            right: None,
            down: None,
            children: Vec::new(),
            commitment: V::empty_commitment(),
            opener: None,
        }
    }
}

/// One `(com_i, pi_com_i)` pair of the proof: `commitment` is this node's own
/// commitment com_i, and `witness` (pi_com_i) opens position `position` of it
/// to the next thing down the path — f(com_{i+1}) for an upper node, or the
/// key k itself for the leaf. A proof is one such pair per level, top-down,
/// with the first pair's `commitment` being the root (sigma).
#[derive(Debug)]
pub struct Step<V: VectorCommitment> {
    pub commitment: V::Commitment,
    pub position: usize,
    pub witness: V::Witness,
}

/// pi = {(com_1, pi_com_1), ..., (com_n, pi_com_n)}, top-down.
pub type Proof<V> = Vec<Step<V>>;

/// One `(com_i, position)` pair of an *aggregated* proof: like `Step`, but
/// the per-level opening witness is gone — a single proof-wide aggregate
/// (see `AggProof`) covers every level at once.
#[derive(Debug)]
pub struct AggStep<V: VectorCommitment> {
    pub commitment: V::Commitment,
    pub position: usize,
}

/// pi_agg = ({(com_1, pos_1), ..., (com_n, pos_n)}, W): the chain's
/// commitments and positions plus ONE aggregated opening witness for all n
/// levels, replacing the n per-level witnesses of `Proof`. For the KZG
/// backend the aggregate is two G1 points however long the chain is, so
/// the proof is n commitments + n positions + O(1).
pub struct AggProof<V: AggregatableVc> {
    pub steps: Vec<AggStep<V>>,
    pub witness: V::AggWitness,
}

/// One step of a *Merkle-mode* proof (`Ibsl::prove_hash`): just the opened
/// `position` and its opening `witness` (the sibling hashes). Unlike `Step`
/// it carries NO commitment — the verifier recomputes each node's hash
/// bottom-up from the child hash below plus these siblings, exactly as a
/// Merkle authentication path is checked.
#[derive(Debug)]
pub struct HashStep<V: VectorCommitment> {
    pub position: usize,
    pub witness: V::Witness,
}

/// A Merkle-mode membership proof: one `(position, siblings)` step per level,
/// top-down (`[0]` is the root's step, the last is the leaf's). The trusted
/// root is supplied to `verify_hash` separately, so the proof is purely the
/// sibling hashes and positions along the path — the same shape as a plain
/// Merkle tree's authentication path, one mini-path per skip-list level.
pub type HashProof<V> = Vec<HashStep<V>>;

// Manual impl: derive(Clone) would demand V: Clone, which the scheme's
// parameter struct need not be.
impl<V: VectorCommitment> Clone for HashStep<V> {
    fn clone(&self) -> Self {
        HashStep {
            position: self.position,
            witness: self.witness.clone(),
        }
    }
}

// Manual impl: derive(Clone) would demand V: Clone, which the scheme's
// parameter struct need not be.
impl<V: VectorCommitment> Clone for Step<V> {
    fn clone(&self) -> Self {
        Step {
            commitment: self.commitment.clone(),
            position: self.position,
            witness: self.witness.clone(),
        }
    }
}

impl<V: VectorCommitment> Clone for AggStep<V> {
    fn clone(&self) -> Self {
        AggStep {
            commitment: self.commitment.clone(),
            position: self.position,
        }
    }
}

impl<V: AggregatableVc> Clone for AggProof<V> {
    fn clone(&self) -> Self {
        AggProof {
            steps: self.steps.clone(),
            witness: self.witness.clone(),
        }
    }
}

/// IBSL IS DEFINITION IS HERE!!!
pub struct Ibsl<V: VectorCommitment> {
    vc: V,
    /// Nodes keyed by an allocated id (no longer an arena index, so ids stay
    /// stable when other nodes are removed).
    nodes: HashMap<NodeId, Node<V>>,
    /// Monotonic id source for `alloc`.
    next_id: NodeId,
    /// heads[i] = the NegInf sentinel of level i+1. The last head is the root.
    heads: Vec<NodeId>,
    rng: u64,
    /// A node is promoted when a `coin()` sample falls below this threshold,
    /// so the promotion probability is `promote_threshold / 2^64`. Expected
    /// fan-out is ~1/p and expected height ~log_{1/p}(n): lowering p widens
    /// and flattens the tree, shortening the KZG proof chain.
    promote_threshold: u64,
}

impl<V: VectorCommitment> Ibsl<V> {
    // ---------------------------------------------------------- Setup (A.2)

    /// Build with the standard skip-list promotion probability p = 1/2
    /// (fan-out ~2, height ~log2 n).
    pub fn new(keys: &[u64], seed: u64) -> Self {
        Self::new_with_promotion(keys, seed, 0.5)
    }

    /// Build with an arbitrary promotion probability `p` in (0, 1). Lower p
    /// means wider nodes (fan-out ~1/p) and a shallower tree (height
    /// ~log_{1/p} n), hence fewer commitments per membership proof — at the
    /// cost of larger per-node vector commitments.
    pub fn new_with_promotion(keys: &[u64], seed: u64, p: f64) -> Self {
        assert!(p > 0.0 && p < 1.0, "promotion probability must be in (0, 1)");
        let mut s = Ibsl {
            vc: V::setup(MAX_FANOUT),
            nodes: HashMap::new(),
            next_id: 0,
            heads: Vec::new(),
            rng: seed | 1,
            // p * 2^64, saturating (f64->u64 casts saturate in Rust).
            promote_threshold: (p * 2f64.powi(64)) as u64,
        };

        // L_1: -inf -> com_1 -> ... -> com_n -> +inf
        let mut ks = keys.to_vec();
        ks.sort_unstable();
        ks.dedup();
        let head = s.alloc(Node::new(Key::NegInf, 1));
        s.heads.push(head);
        let mut prev = head;
        for k in ks {
            let id = s.alloc(Node::new(Key::Val(k), 1));
            s.nodes.get_mut(&prev).unwrap().right = Some(id);
            prev = id;
        }
        let tail = s.alloc(Node::new(Key::PosInf, 1));
        s.nodes.get_mut(&prev).unwrap().right = Some(tail);

        // Sweep upward: each node of L_i is extended into L_{i+1} with
        // probability p = 1/2. The head sentinel is always extended.
        loop {
            let lvl = s.heads.len();
            let mut promoted: Vec<NodeId> = Vec::new();
            let mut prev: Option<NodeId> = None;
            let mut prev2: Option<NodeId> = None;
            for &id in s.level_nodes(lvl).iter().skip(1) {
                if s.nodes[&id].key == Key::PosInf {
                    continue;
                }

                if s.coin() {
                    // If node is promoted
                    promoted.push(id);

                    if s.nodes[&id].level != 1 {
                        if let (Some(p2), Some(p)) = (prev2, prev) {
                            let down = s.nodes[&p].down;
                            s.nodes.get_mut(&p2).unwrap().right = down;
                            s.nodes.remove(&p);
                            prev = None;
                        }

                        if let Some(p) = prev {
                            s.nodes.get_mut(&p).unwrap().right = None;
                        }

                        prev = None;
                        prev2 = None;
                        continue;
                    }
                } 

                prev2 = prev;
                prev = Some(id);
            }

            let new_lvl = lvl + 1;
            let nh = s.alloc(Node::new(Key::NegInf, new_lvl));
            s.nodes.get_mut(&nh).unwrap().down = Some(s.heads[lvl - 1]);
            s.heads.push(nh);

            if promoted.is_empty() || new_lvl >= MAX_HEIGHT {
                // Individual Root: the top level holds a single node.
                break;
            }

            let mut prev = nh;
            for (i, &low) in promoted.iter().enumerate() {
                if i + 1 == promoted.len() {
                    // Redundant-node rule: the rightmost extension would have
                    // right(v) = NULL, so it is dismissed and its predecessor
                    // takes a shortcut path down to the promoted node itself.
                    s.nodes.get_mut(&prev).unwrap().right = Some(low);
                } else {
                    let key = s.nodes[&low].key;
                    let c = s.alloc(Node::new(key, new_lvl));
                    s.nodes.get_mut(&c).unwrap().down = Some(low);
                    s.nodes.get_mut(&prev).unwrap().right = Some(c);
                    prev = c;
                }
            }
        }

        s.recompute();
        s
    }

    pub fn height(&self) -> usize {
        self.heads.len()
    }

    /// The commitment scheme's public parameters (a verifier needs them).
    pub fn vc(&self) -> &V {
        &self.vc
    }

    fn root(&self) -> NodeId {
        *self.heads.last().unwrap()
    }

    /// sigma <- S_root: the public commitment to the membership state.
    pub fn root_commitment(&self) -> V::Commitment {
        let r = self.root();
        self.nodes[&r].commitment.clone()
    }

    // --------------------------------------------------------------- Search

    /// Search(S, k): go right while k is not in v.interval, otherwise go
    /// down; at L_1 scan right and compare keys (Definition 2).
    pub fn search(&self, k: u64) -> bool {
        let key = Key::Val(k);
        let mut v = self.root();
        loop {
            let n = &self.nodes[&v];
            if n.level == 1 {
                break;
            }

            if in_interval(key, n.interval) {
                v = n.down.unwrap();
            } else if n.right.map_or(false, |r| key >= self.nodes[&r].interval.0) {
                v = n.right.unwrap();
            } else {
                // k is past this subtree but before the next one (or the
                // level chain is cut here): drop down and let the lower
                // level's intact chain carry the scan right.
                v = n.down.unwrap();
            }
        }

        loop {
            let n = &self.nodes[&v];
            match n.key.cmp(&key) {
                Ordering::Equal => return true,
                Ordering::Greater => return false,
                Ordering::Less => match n.right {
                    Some(r) => v = r,
                    None => return false,
                },
            }
        }
    }

    // --------------------------------------------------------- Insert (A.3)

    pub fn insert(&mut self, k: u64) {
        let key = Key::Val(k);
        if self.search(k) {
            return;
        }

        // Walk the search path, remembering the last node visited per level
        // (the standard skip-list update array).
        let mut pred_at: Vec<Option<NodeId>> = vec![None; self.heads.len()];
        let mut v = self.root();
        loop {
            let (lvl, iv, right, down) = {
                let n = &self.nodes[&v];
                (n.level, n.interval, n.right, n.down)
            };
            pred_at[lvl - 1] = Some(v);
            if lvl == 1 {
                break;
            }
            if in_interval(key, iv) {
                v = down.unwrap();
            } else if let Some(r) = right {
                if key >= self.nodes[&r].interval.0 {
                    v = r;
                } else {
                    // k falls in the gap after this subtree: its predecessor
                    // is the rightmost leaf below, so descend, not right.
                    v = down.unwrap();
                }
            } else {
                v = down.unwrap();
            }
        }

        // Insert the leaf at L_1 behind its predecessor.
        let mut pred = pred_at[0].unwrap();
        while let Some(r) = self.nodes[&pred].right {
            if self.nodes[&r].key < key {
                pred = r;
            } else {
                break;
            }
        }
        let mut leaf = Node::new(key, 1);
        leaf.right = self.nodes[&pred].right;
        let leaf = self.alloc(leaf);
        self.nodes.get_mut(&pred).unwrap().right = Some(leaf);

        // k's tower, bottom-up: the leaf plus every Case-1 extension.
        let mut created = vec![leaf];
        let mut grew = false;

        // Promote: flip b in {0,1} until b = 0 (A.3).
        let mut below = leaf;
        let mut lvl = 2;
        while lvl <= MAX_HEIGHT && self.coin() {
            if lvl > self.heads.len() {
                let mut nh = Node::new(Key::NegInf, lvl);
                nh.down = Some(self.root());
                let nh = self.alloc(nh);
                self.heads.push(nh);
                grew = true;
            }

            // Predecessor of k at this level.
            let mut pred = pred_at
                .get(lvl - 1)
                .copied()
                .flatten()
                .unwrap_or(self.heads[lvl - 1]);
            loop {
                match self.nodes[&pred].right {
                    Some(r) if self.nodes[&r].level == lvl && self.nodes[&r].key < key => pred = r,
                    _ => break,
                }
            }

            match self.nodes[&pred].right {
                Some(r) if self.nodes[&r].level == lvl => {
                    // Case 1: normal splice between two same-level nodes.
                    let mut c = Node::new(key, lvl);
                    c.right = Some(r);
                    c.down = Some(below);
                    let c = self.alloc(c);
                    self.nodes.get_mut(&pred).unwrap().right = Some(c);
                    created.push(c);
                    below = c;
                }
                _ => {
                    // Case 2: the extension k' would be the rightmost node of
                    // this level, i.e. immediately redundant. It is dismissed
                    // and the predecessor shortcuts down to the copy below:
                    // right(z) = k.
                    self.nodes.get_mut(&pred).unwrap().right = Some(below);
                    break;
                }
            }
            lvl += 1;
        }

        if grew {
            // A whole new level appeared (not expected in practice — the top
            // level's lone head always dismisses promotions as Case 2 — but
            // handled defensively): rebuild everything.
            self.recompute();
        } else {
            // Paper: recompute commitments along the search path only.
            self.recompute_insert(key, &created);
        }
    }

    // --------------------------------------------------------- Delete (A.4)

    /// Revocation: the credential is actually removed, not nulled.
    pub fn delete(&mut self, k: u64) -> bool {
        let key = Key::Val(k);
        if !self.search(k) {
            return false;
        }

        let h = self.heads.len();
        // k's owner per level: levels 1..=t are k's own tower (owner key is
        // k itself); above sit the ancestors whose commitments must refresh.
        let owners = self.owner_path(key);
        let t = (1..=h)
            .take_while(|&l| self.nodes[&owners[l]].key == key)
            .count();

        // The tower's same-level predecessors, needed because they absorb
        // the removed nodes' children: pred_t is the child just before the
        // tower top in the parent's vector (never the first child — that one
        // shares the parent's key, which is < k); below that, each pred is
        // the last child of the pred one level up.
        let p = owners[t + 1];
        let pos = self.nodes[&p]
            .children
            .iter()
            .position(|&c| c == owners[t])
            .expect("tower top is a child of its parent");
        let mut preds = vec![usize::MAX; t + 1];
        if t >= 2 {
            preds[t] = self.nodes[&p].children[pos - 1];
            for l in (2..t).rev() {
                preds[l] = *self.nodes[&preds[l + 1]].children.last().unwrap();
            }
        }

        // Reassign children: the parent drops the tower top, and at every
        // tower level the predecessor absorbs the removed node's children —
        // minus its first child, which is the tower copy one level down and
        // is being removed too.
        self.nodes.get_mut(&p).unwrap().children.remove(pos);
        for l in 2..=t {
            let extra = self.nodes[&owners[l]].children[1..].to_vec();
            self.nodes.get_mut(&preds[l]).unwrap().children.extend(extra);
        }

        // Collect k's tower: its leaf and every extension of it. Scan the whole
        // map, not head-chains: shortcuts leave tower nodes off their level's
        // horizontal chain, and `level_nodes` would miss them.
        let tower: Vec<NodeId> = self
            .nodes
            .iter()
            .filter(|(_, n)| n.key == key)
            .map(|(&id, _)| id)
            .collect();
        let tower_set: HashSet<NodeId> = tower.iter().copied().collect();

        // Bypass every pointer into a removed node (same-level predecessors and
        // shortcut sources alike). Again scan the whole map so off-chain sources
        // are redirected too; otherwise their `right` would dangle at a node we
        // are about to drop.
        for &t in &tower {
            let bypass = self.nodes[&t].right;
            let sources: Vec<NodeId> = self
                .nodes
                .iter()
                .filter(|(&id, n)| id != t && n.right == Some(t))
                .map(|(&id, _)| id)
                .collect();
            for s in sources {
                self.nodes.get_mut(&s).unwrap().right = bypass;
            }
        }

        // The tower nodes are now referenced by nobody; drop them (and any
        // node the bypassing left unreachable) from the map.
        //self.gc();
        for &t in &tower {
            self.nodes.remove(&t);
        }

        debug_assert!(
            !self
                .nodes
                .values()
                .any(|n| n.right.map_or(false, |r| tower_set.contains(&r))
                    || n.down.map_or(false, |d| tower_set.contains(&d))),
            "delete left a pointer into a removed tower node"
        );

        // No rebalancing (A.5) in this basic version. Recompute intervals
        // and commitments bottom-up along the affected path only.
        for l in 2..=t {
            self.commit_node(preds[l]);
        }
        self.commit_node(p);
        for l in t + 2..=h {
            self.commit_node(owners[l]);
        }
        true
    }

    // -------------------------------------------------------- Prove / Verify

    /// Prove(S, k) -> pi = {(com_1, pi_com_1), ..., (com_n, pi_com_n)}: one
    /// (commitment, opening) pair per level, top-down along the search path.
    /// com_1 is the root (sigma) and com_n is the leaf. Each pair's opening
    /// pi_com_i reveals the next thing inside com_i: f(com_{i+1}) for an upper
    /// node, or the key k itself at the leaf.
    pub fn prove(&self, k: u64) -> Option<Proof<V>> {
        let path = self.proof_path(k)?;
        Some(
            path.iter()
                .map(|&(id, pos)| {
                    let n = &self.nodes[&id];
                    Step {
                        commitment: n.commitment.clone(),
                        position: pos,
                        witness: self.vc.open(n.opener.as_ref().expect("set by recompute"), pos),
                    }
                })
                .collect(),
        )
    }

    /// The `(node, opened position)` pairs of k's membership chain,
    /// top-down: each upper node opens the child whose key range holds k
    /// (the last child with key <= k), and the leaf opens slot 0 (its own
    /// key). None if k is not a member.
    fn proof_path(&self, k: u64) -> Option<Vec<(NodeId, usize)>> {
        let key = Key::Val(k);
        let mut path = Vec::new();
        let mut v = self.root();
        while self.nodes[&v].level > 1 {
            let n = &self.nodes[&v];
            let pos = n.children.iter().rposition(|c| self.nodes[c].key <= key)?;
            path.push((v, pos));
            v = n.children[pos];
        }
        if self.nodes[&v].key != key {
            return None;
        }
        path.push((v, 0));
        Some(path)
    }

    /// What step i of the chain must open to: the seam value of the next
    /// commitment down, or the key itself at the leaf.
    fn step_value(&self, path: &[(NodeId, usize)], i: usize, k: u64) -> V::DigestType {
        if i + 1 < path.len() {
            V::to_field(&self.nodes[&path[i + 1].0].commitment)
        } else {
            Key::Val(k).field()
        }
    }

    /// Verify(sigma, k, pi): check each `(com_i, pi_com_i)` pair on its own —
    /// pi_com_i must open com_i at its position to the next thing down the
    /// path: f(com_{i+1}) for every upper pair, and the key k for the leaf
    /// pair. The first commitment must be the trusted root (sigma), which
    /// anchors the chain. (In the credential system these checks are what get
    /// proven inside the zero-knowledge circuit, so that neither com_i nor pi
    /// is revealed.)
    pub fn verify(vc: &V, root: &V::Commitment, k: u64, pi: &[Step<V>]) -> bool {
        if pi.is_empty() {
            return false;
        }
        // com_1 must be the trusted sigma.
        if V::commitment_bytes(&pi[0].commitment) != V::commitment_bytes(root) {
            return false;
        }
        let n = pi.len();
        for (i, s) in pi.iter().enumerate() {
            // What pi_com_i must open com_i to: the next commitment down the
            // path, or the key k itself at the leaf (the last pair).
            let value = if i + 1 < n {
                V::to_field(&pi[i + 1].commitment)
            } else {
                Key::Val(k).field()
            };
            if !vc.check(&s.commitment, s.position, value, &s.witness) {
                return false;
            }
        }
        true
    }

    // ------------------------------------------------------------- internals

    fn alloc(&mut self, n: Node<V>) -> NodeId {
        let id = self.next_id;
        self.next_id += 1;
        self.nodes.insert(id, n);
        id
    }
}

/// Aggregated prove/verify: available whenever the backend can collapse a
/// batch of openings into one witness (`AggregatableVc`; KZG does, via a
/// SHPLONK batch opening — see vc/kzg.rs).
impl<V: AggregatableVc> Ibsl<V> {
    /// Prove(S, k) with every per-level opening collapsed into ONE
    /// aggregated witness: pi_agg carries the same chain of commitments and
    /// positions as `prove`, but a single constant-size opening proof
    /// replaces the L per-level ones (KZG: two G1 points, ~96 bytes,
    /// regardless of chain length).
    pub fn prove_agg(&self, k: u64) -> Option<AggProof<V>> {
        let path = self.proof_path(k)?;
        let values: Vec<V::DigestType> =
            (0..path.len()).map(|i| self.step_value(&path, i, k)).collect();
        let claims: Vec<(&V::Opener, &V::Commitment, usize, V::DigestType)> = path
            .iter()
            .zip(&values)
            .map(|(&(id, pos), &v)| {
                let n = &self.nodes[&id];
                (n.opener.as_ref().expect("set by recompute"), &n.commitment, pos, v)
            })
            .collect();
        let witness = self.vc.aggregate_open(&claims);
        Some(AggProof {
            steps: path
                .iter()
                .map(|&(id, pos)| AggStep {
                    commitment: self.nodes[&id].commitment.clone(),
                    position: pos,
                })
                .collect(),
            witness,
        })
    }

    /// Verify(sigma, k, pi_agg): same chain checks as `verify` — com_1 must
    /// be the trusted sigma, and each com_i must open at its position to
    /// f(com_{i+1}) (or to k at the leaf) — except all L opening checks are
    /// discharged by the one aggregated witness.
    pub fn verify_agg(vc: &V, root: &V::Commitment, k: u64, pi: &AggProof<V>) -> bool {
        if pi.steps.is_empty() {
            return false;
        }
        if V::commitment_bytes(&pi.steps[0].commitment) != V::commitment_bytes(root) {
            return false;
        }
        let n = pi.steps.len();
        let claims: Vec<(&V::Commitment, usize, V::DigestType)> = pi
            .steps
            .iter()
            .enumerate()
            .map(|(i, s)| {
                let value = if i + 1 < n {
                    V::to_field(&pi.steps[i + 1].commitment)
                } else {
                    Key::Val(k).field()
                };
                (&s.commitment, s.position, value)
            })
            .collect();
        vc.aggregate_check(&claims, &pi.witness)
    }
}

/// Merkle mode: prove/verify a membership chain as a plain sibling-hash
/// authentication path, available whenever the backend's node commitment is
/// a hash of its slots (`HashVc` — the Merkle-tree backends, see vc/merkle.rs).
///
/// The tree is identical to the default (commitment) mode — every node's
/// commitment is already `H(children hashes)`. What changes is the PROOF: it
/// no longer carries the per-level commitments (`Step::commitment`) that the
/// default `verify` re-derives the seam from. Instead the verifier walks the
/// path bottom-up, recomputing each node's hash from the child hash below and
/// the opened siblings, and checks the final hash equals the root — exactly a
/// Merkle authentication path, just chained one mini-path per skip-list level.
/// At promotion p = 0.5 (fan-out ~2, one sibling per level) that is on par
/// with a plain binary Merkle tree's path over the same n keys.
impl<V: HashVc> Ibsl<V> {
    /// Prove(S, k) as a Merkle-style sibling-hash chain: one `(position,
    /// siblings)` step per level top-down, and nothing else. `None` if k is
    /// not a member.
    pub fn prove_hash(&self, k: u64) -> Option<HashProof<V>> {
        let path = self.proof_path(k)?;
        Some(
            path.iter()
                .map(|&(id, pos)| {
                    let n = &self.nodes[&id];
                    HashStep {
                        position: pos,
                        witness: self.vc.open(n.opener.as_ref().expect("set by recompute"), pos),
                    }
                })
                .collect(),
        )
    }

    /// Verify(sigma, k, pi) for a Merkle-mode proof: recompute the path
    /// bottom-up — the leaf's hash from k and its siblings, then each parent's
    /// hash from the child hash just computed (mapped into the field the same
    /// way `commit_node` does) and that level's siblings — and accept iff the
    /// top hash equals the trusted root sigma. Any malformed step (bad
    /// position or witness width) rejects.
    pub fn verify_hash(vc: &V, root: &V::Commitment, k: u64, pi: &[HashStep<V>]) -> bool {
        let Some((leaf, uppers)) = pi.split_last() else {
            return false;
        };
        // Leaf: opens slot 0 to the key itself, yielding the leaf's own hash.
        let mut cur = match vc.recompute(leaf.position, Key::Val(k).field(), &leaf.witness) {
            Some(c) => c,
            None => return false,
        };
        // Walk up: each upper node opens the child hash just computed.
        for step in uppers.iter().rev() {
            let value = V::to_field(&cur);
            cur = match vc.recompute(step.position, value, &step.witness) {
                Some(c) => c,
                None => return false,
            };
        }
        V::commitment_bytes(&cur) == V::commitment_bytes(root)
    }
}

// Internals, continued (split around the AggregatableVc block above).
impl<V: VectorCommitment> Ibsl<V> {
    /// xorshift64 coin flip biased to the configured promotion probability:
    /// the fresh 64-bit state is uniform over the nonzero u64s, so the flip
    /// succeeds with probability ~`promote_threshold / 2^64`.
    fn coin(&mut self) -> bool {
        self.rng ^= self.rng << 13;
        self.rng ^= self.rng >> 7;
        self.rng ^= self.rng << 17;
        self.rng < self.promote_threshold
    }

    /// The nodes that live at level `lvl`, left to right. The chain ends at
    /// the first shortcut pointer (which leads to a lower level) or at NULL.
    fn level_nodes(&self, lvl: usize) -> Vec<NodeId> {
        let mut out = Vec::new();
        let mut cur = Some(self.heads[lvl - 1]);
        while let Some(id) = cur {
            if self.nodes[&id].level != lvl {
                break;
            }
            out.push(id);
            cur = self.nodes[&id].right;
        }
        out
    }

    /// Recompute one node's interval and commitment from its stored
    /// `children` (which must already be correct, and already re-committed
    /// if they changed): a leaf commits to its own key, an upper node to the
    /// vector of its children's compact commitment values.
    fn commit_node(&mut self, id: NodeId) {
        let (interval, values) = {
            let n = &self.nodes[&id];
            if n.level == 1 {
                ((n.key, n.key), vec![n.key.field()])
            } else {
                let first = *n.children.first().expect("upper node without children");
                let last = *n.children.last().unwrap();
                let interval = (self.nodes[&first].interval.0, self.nodes[&last].interval.1);
                let values: Vec<V::DigestType> = n
                    .children
                    .iter()
                    .map(|c| V::to_field(&self.nodes[c].commitment))
                    .collect();
                (interval, values)
            }
        };
        assert!(
            values.len() <= MAX_FANOUT,
            "fan-out {} exceeds the VC width {MAX_FANOUT}",
            values.len()
        );
        let (commitment, opener) = self.vc.commit(&values);
        let n = self.nodes.get_mut(&id).unwrap();
        n.interval = interval;
        n.commitment = commitment;
        n.opener = Some(opener);
    }

    /// The node owning k's key range at every level, top-down:
    /// `owners[l]` is the level-l node with the greatest key <= k
    /// (`owners[height]` is the root, `owners[1]` the leaf-level
    /// predecessor-or-self of k; `owners[0]` is unused). Descends the stored
    /// `children` vectors, so it reflects the tree as of the last commit
    /// pass — exactly the parent chain `prove`'s `proof_path` would walk.
    fn owner_path(&self, key: Key) -> Vec<NodeId> {
        let h = self.heads.len();
        let mut owners = vec![usize::MAX; h + 1];
        let mut v = self.root();
        for l in (2..=h).rev() {
            owners[l] = v;
            let n = &self.nodes[&v];
            let pos = n
                .children
                .iter()
                .rposition(|c| self.nodes[c].key <= key)
                .expect("head sentinels bound every key from below");
            v = n.children[pos];
        }
        owners[1] = v;
        owners
    }

    /// Incremental commit pass after `insert` (paper A.3: recompute along
    /// the search path only). `created[i]` is k's new node at level i+1.
    /// Affected nodes, and nobody else: at each tower level the old owner of
    /// k's range loses its children past k to the new node; the level above
    /// the tower gains the tower top as a child; every ancestor higher up
    /// keeps its children but must re-commit (a child's commitment changed)
    /// and re-span its interval.
    fn recompute_insert(&mut self, key: Key, created: &[NodeId]) {
        let h = self.heads.len();
        let t = created.len();
        // Owners as of BEFORE this insert: the created nodes are not in any
        // `children` vector yet, so the descent sees the pre-insert tree.
        let owners = self.owner_path(key);

        self.commit_node(created[0]);

        // Tower levels: split the old owner's children around k.
        for l in 2..=t {
            let a = owners[l];
            let split = self.nodes[&a]
                .children
                .partition_point(|c| self.nodes[c].key < key);
            let moved = self.nodes.get_mut(&a).unwrap().children.split_off(split);
            let node_l = created[l - 1];
            let n = self.nodes.get_mut(&node_l).unwrap();
            n.children.push(created[l - 2]);
            n.children.extend(moved);
            self.commit_node(a);
            self.commit_node(node_l);
        }

        // The tower top becomes a child of k's owner one level above it.
        // (t < height always: the top level holds only its head, so a
        // promotion there is dismissed as Case 2 before reaching this.)
        let p = owners[t + 1];
        let pos = self.nodes[&p]
            .children
            .partition_point(|c| self.nodes[c].key < key);
        self.nodes.get_mut(&p).unwrap().children.insert(pos, created[t - 1]);
        self.commit_node(p);
        for l in t + 2..=h {
            self.commit_node(owners[l]);
        }
    }

    /// Recompute children, intervals, and commitments bottom-up for the
    /// WHOLE structure (used by the initial build): a leaf commits to its
    /// own key, an upper node to its children's compact commitment values.
    fn recompute(&mut self) {
        // Every node reachable from a head, bucketed by level. Shortcuts mean a
        // level is NOT a single horizontal chain from its head, so we must
        // gather nodes by graph traversal, not by walking `right` from heads.
        let mut by_level: Vec<Vec<NodeId>> = vec![Vec::new(); self.heads.len() + 1];
        let mut seen: HashSet<NodeId> = HashSet::new();
        let mut stack: Vec<NodeId> = self.heads.clone();
        while let Some(id) = stack.pop() {
            if !seen.insert(id) {
                continue;
            }
            let n = &self.nodes[&id];
            by_level[n.level].push(id);
            if let Some(r) = n.right {
                stack.push(r);
            }
            if let Some(d) = n.down {
                stack.push(d);
            }
        }
        // Keys are unique within a level (one tower copy per level, one head
        // sentinel), so key order IS left-to-right order.
        for lvl in 1..=self.heads.len() {
            by_level[lvl].sort_by_key(|id| self.nodes[id].key);
        }

        // L_1: a leaf commits to the element itself.
        for &id in &by_level[1] {
            self.nodes.get_mut(&id).unwrap().children = Vec::new();
            self.commit_node(id);
        }

        // Upper levels: node v owns every level-below node whose key lies in
        // [v.key, key of v's level-successor). The first child always exists
        // (v's own copy one level down) and the last node of a level owns
        // through +inf, so intervals span the whole keyspace at every level.
        for lvl in 2..=self.heads.len() {
            let uppers = by_level[lvl].clone();
            let lowers = &by_level[lvl - 1];
            let mut j = 0;
            for (i, &id) in uppers.iter().enumerate() {
                let hi = uppers.get(i + 1).map(|nid| self.nodes[nid].key);
                let mut kids: Vec<NodeId> = Vec::new();
                while j < lowers.len() {
                    let ck = self.nodes[&lowers[j]].key;
                    if hi.map_or(false, |h| ck >= h) {
                        break;
                    }
                    kids.push(lowers[j]);
                    j += 1;
                }
                self.nodes.get_mut(&id).unwrap().children = kids;
                self.commit_node(id);
            }
        }
    }
}
