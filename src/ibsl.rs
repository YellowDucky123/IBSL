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
//!     c_leaf = Com(key)        c_v = Com(f(c_1), ..., f(c_m))
//!
//! where c_1..c_m are the commitments of v's children and f maps a compact
//! commitment value into the scalar field. Each node keeps the whole
//! commitment — the committed vector (preimage) alongside the compact value
//! — so it can produce openings; only the compact value is embedded in the
//! parent's vector and published. A membership proof for k is a list of
//! (commitment, opening) pairs, one per level top-down along the path:
//!
//!     pi = {(com_1, pi_com_1), ..., (com_n, pi_com_n)}
//!
//! where com_1 is the root (sigma), com_n is the leaf, and each opening
//! pi_com_i reveals the next thing inside com_i — f(com_{i+1}) for an upper
//! node, or the key k itself at the leaf. Verification checks the first
//! commitment is the trusted sigma and then verifies every pair on its own.
//!
//! The commitment scheme is pluggable: `Ibsl<V>` works with any
//! `VectorCommitment` backend — KZG10 (kzg.rs) or a Merkle tree (merkle.rs)
//! over any of the hashes in `crate::hashes` — and so is the scalar field
//! itself (`crate::field::IbslField`): arkworks' BLS12-381 Fr for the KZG /
//! Poseidon / byte-hash backends, Winterfell's f128 for the Rescue backend
//! whose proofs `crate::stark` re-verifies in a STARK.
//!
//! Simplifications, on purpose:
//!   - intervals and commitments are recomputed globally after every update
//!     (O(n)) instead of only along the affected path (O(log n) as in the
//!     paper);
//!   - nodes live in a `HashMap` keyed by an allocated id; after a delete the
//!     nodes no longer reachable from any head are garbage-collected;
//!   - keys are u64 (in the credential system these would be commitments com_i);
//!   - the KZG SRS comes from an insecure seed-derived setup (see kzg.rs).

use crate::field::IbslField;
use crate::vc::VectorCommitment;
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
    pub(crate) fn field<F: IbslField>(&self) -> F {
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
    /// The whole commitment: the committed vector (the preimage, needed to
    /// open positions of it) plus its compact public value below. A leaf's
    /// vector is [key]; an upper node's vector is the compact commitment
    /// values of its children.
    values: Vec<V::Field>,
    commitment: V::Commitment,
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
            values: Vec::new(),
            commitment: V::empty_commitment(),
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
}

impl<V: VectorCommitment> Ibsl<V> {
    // ---------------------------------------------------------- Setup (A.2)

    pub fn new(keys: &[u64], seed: u64) -> Self {
        let mut s = Ibsl {
            vc: V::setup(MAX_FANOUT),
            nodes: HashMap::new(),
            next_id: 0,
            heads: Vec::new(),
            rng: seed | 1,
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

        // Promote: flip b in {0,1} until b = 0 (A.3).
        let mut below = leaf;
        let mut lvl = 2;
        while lvl <= MAX_HEIGHT && self.coin() {
            if lvl > self.heads.len() {
                let mut nh = Node::new(Key::NegInf, lvl);
                nh.down = Some(self.root());
                let nh = self.alloc(nh);
                self.heads.push(nh);
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

        // Paper: recompute commitments along pi only. Basic version: all.
        self.recompute();
    }

    // --------------------------------------------------------- Delete (A.4)

    /// Revocation: the credential is actually removed, not nulled.
    pub fn delete(&mut self, k: u64) -> bool {
        let key = Key::Val(k);
        if !self.search(k) {
            return false;
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

        // No rebalancing (A.5) in this basic version.
        self.recompute();
        true
    }

    // -------------------------------------------------------- Prove / Verify

    /// Prove(S, k) -> pi = {(com_1, pi_com_1), ..., (com_n, pi_com_n)}: one
    /// (commitment, opening) pair per level, top-down along the search path.
    /// com_1 is the root (sigma) and com_n is the leaf. Each pair's opening
    /// pi_com_i reveals the next thing inside com_i: f(com_{i+1}) for an upper
    /// node, or the key k itself at the leaf.
    pub fn prove(&self, k: u64) -> Option<Proof<V>> {
        let key = Key::Val(k);
        let mut pi = Vec::new();
        let mut v = self.root();
        while self.nodes[&v].level > 1 {
            let n = &self.nodes[&v];
            // The child whose key range holds k: the last one with key <= k.
            let pos = n.children.iter().rposition(|c| self.nodes[c].key <= key)?;
            pi.push(Step {
                commitment: n.commitment.clone(),
                position: pos,
                witness: self.vc.open(&n.values, pos),
            });
            v = n.children[pos];
        }
        // Leaf pair: its commitment opens at position 0 to the key itself.
        let leaf = &self.nodes[&v];
        if leaf.key != key {
            return None;
        }
        pi.push(Step {
            commitment: leaf.commitment.clone(),
            position: 0,
            witness: self.vc.open(&leaf.values, 0),
        });
        Some(pi)
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

    /// xorshift64 coin flip, p = 1/2.
    fn coin(&mut self) -> bool {
        self.rng ^= self.rng << 13;
        self.rng ^= self.rng >> 7;
        self.rng ^= self.rng << 17;
        self.rng & 1 == 1
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

    /// Recompute children, intervals, and commitments bottom-up: a leaf
    /// commits to its own key, an upper node commits to the vector of its
    /// children's compact commitment values.
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
            let key = self.nodes[&id].key;
            let values: Vec<V::Field> = vec![key.field()];
            let commitment = self.vc.commit(&values);
            let n = self.nodes.get_mut(&id).unwrap();
            n.interval = (key, key);
            n.children = Vec::new();
            n.values = values;
            n.commitment = commitment;
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
                let first = *kids.first().expect("upper node without children");
                let last = *kids.last().unwrap();
                // Interval = the span of the children: [min(first), max(last)].
                let interval = (self.nodes[&first].interval.0, self.nodes[&last].interval.1);
                let values: Vec<V::Field> = kids
                    .iter()
                    .map(|c| V::to_field(&self.nodes[c].commitment))
                    .collect();
                assert!(
                    values.len() <= MAX_FANOUT,
                    "fan-out {} exceeds the VC width {MAX_FANOUT}",
                    values.len()
                );
                let commitment = self.vc.commit(&values);
                let n = self.nodes.get_mut(&id).unwrap();
                n.interval = interval;
                n.children = kids;
                n.values = values;
                n.commitment = commitment;
            }
        }
    }
}

