//! Basic implementation of the Interval Based Skip List (IBSL) from
//! "New Construction on Zk-Creds Credential System".
//!
//! What is covered (in simplified form):
//!   - Setup (Appendix A.2): bottom-up build with probabilistic promotion
//!     (p = 1/2), shortcut paths via the redundant-node rule, interval
//!     labelling (Definition 1), and authenticated digests h_v = H(d_v || RP || RD).
//!   - Search: interval-guided descent (Definition 2 / Section A.1).
//!   - Insert (Appendix A.3): cases 1 and 2. The overflow split (case 5) and
//!     the fan-out invariant (Definition 3) are NOT implemented.
//!   - Delete (Appendix A.4): leaf + tower removal with pointer bypassing.
//!     No rebalancing (A.5).
//!   - Prove / Verify: membership proof as an authentication path along the
//!     search path, checked against the root digest sigma.
//!
//! Simplifications, on purpose:
//!   - intervals and digests are recomputed globally after every update (O(n))
//!     instead of only along the affected path (O(log n) as in the paper);
//!   - removed arena slots are leaked rather than reused;
//!   - keys are u64 (in the credential system these would be commitments com_i).

use sha2::{Digest as _, Sha256};
use std::cmp::Ordering;

pub type Hash = [u8; 32];
type NodeId = usize;

const NULL_HASH: Hash = [0u8; 32];
const MAX_HEIGHT: usize = 32;

/// Keys of the base layer are bounded by the sentinels -inf and +inf.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Key {
    NegInf,
    Val(u64),
    PosInf,
}

impl Key {
    fn bytes(&self) -> [u8; 9] {
        let mut b = [0u8; 9];
        match self {
            Key::NegInf => b[0] = 0,
            Key::Val(v) => {
                b[0] = 1;
                b[1..].copy_from_slice(&v.to_be_bytes());
            }
            Key::PosInf => b[0] = 2,
        }
        b
    }
}

type Interval = (Key, Key);

fn in_interval(k: Key, iv: Interval) -> bool {
    iv.0 <= k && k <= iv.1
}

/// h_v = H(level || key || interval || RP || RD), where RP is the digest of
/// the node behind the right pointer and RD the digest behind the down
/// pointer (NULL_HASH when the pointer is absent).
fn node_hash(level: usize, key: Key, iv: Interval, hr: &Hash, hd: &Hash) -> Hash {
    let mut h = Sha256::new();
    h.update((level as u64).to_be_bytes());
    h.update(key.bytes());
    h.update(iv.0.bytes());
    h.update(iv.1.bytes());
    h.update(hr);
    h.update(hd);
    h.finalize().into()
}

#[derive(Clone, Debug)]
struct Node {
    key: Key,
    level: usize, // 1 = base layer L_1
    interval: Interval,
    /// May point to a node at a *lower* level: that is a shortcut path.
    right: Option<NodeId>,
    down: Option<NodeId>,
    digest: Hash,
}

impl Node {
    fn new(key: Key, level: usize) -> Self {
        Node {
            key,
            level,
            interval: (key, key),
            right: None,
            down: None,
            digest: NULL_HASH,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dir {
    Down,
    Right,
}

/// One node on the authentication path pi. `sibling` is the digest of the
/// branch NOT taken (right digest when descending, down digest when moving
/// right), so the verifier can recompute h_v for every node on the path.
#[derive(Clone, Debug)]
pub struct ProofStep {
    pub key: Key,
    pub level: usize,
    pub interval: Interval,
    pub sibling: Hash,
    pub dir: Dir,
}

pub struct Ibsl {
    nodes: Vec<Node>,
    /// heads[i] = the NegInf sentinel of level i+1. The last head is the root.
    heads: Vec<NodeId>,
    rng: u64,
}

impl Ibsl {
    // ---------------------------------------------------------- Setup (A.2)

    pub fn new(keys: &[u64], seed: u64) -> Self {
        let mut s = Ibsl {
            nodes: Vec::new(),
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
            s.nodes[prev].right = Some(id);
            prev = id;
        }
        let tail = s.alloc(Node::new(Key::PosInf, 1));
        s.nodes[prev].right = Some(tail);

        // Sweep upward: each node of L_i is extended into L_{i+1} with
        // probability p = 1/2. The head sentinel is always extended.
        loop {
            let lvl = s.heads.len();
            let mut promoted: Vec<NodeId> = Vec::new();
            for &id in s.level_nodes(lvl).iter().skip(1) {
                if s.nodes[id].key == Key::PosInf {
                    continue;
                }
                if s.coin() {
                    promoted.push(id);
                }
            }

            let new_lvl = lvl + 1;
            let nh = s.alloc(Node::new(Key::NegInf, new_lvl));
            s.nodes[nh].down = Some(s.heads[lvl - 1]);
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
                    s.nodes[prev].right = Some(low);
                } else {
                    let c = s.alloc(Node::new(s.nodes[low].key, new_lvl));
                    s.nodes[c].down = Some(low);
                    s.nodes[prev].right = Some(c);
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

    fn root(&self) -> NodeId {
        *self.heads.last().unwrap()
    }

    /// sigma <- S_root: the public commitment to the membership state.
    pub fn root_digest(&self) -> Hash {
        self.nodes[self.root()].digest
    }

    // --------------------------------------------------------------- Search

    /// Search(S, k): go right while k is not in v.interval, otherwise go
    /// down; at L_1 scan right and compare keys (Definition 2).
    pub fn search(&self, k: u64) -> bool {
        let key = Key::Val(k);
        let mut v = self.root();
        loop {
            let n = &self.nodes[v];
            if n.level == 1 {
                break;
            }
            if in_interval(key, n.interval) {
                v = n.down.unwrap();
            } else if let Some(r) = n.right {
                v = r; // possibly a shortcut path to a lower level
            } else {
                v = n.down.unwrap();
            }
        }
        loop {
            let n = &self.nodes[v];
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
                let n = &self.nodes[v];
                (n.level, n.interval, n.right, n.down)
            };
            pred_at[lvl - 1] = Some(v);
            if lvl == 1 {
                break;
            }
            if in_interval(key, iv) {
                v = down.unwrap();
            } else if let Some(r) = right {
                v = r;
            } else {
                v = down.unwrap();
            }
        }

        // Insert the leaf at L_1 behind its predecessor.
        let mut pred = pred_at[0].unwrap();
        while let Some(r) = self.nodes[pred].right {
            if self.nodes[r].key < key {
                pred = r;
            } else {
                break;
            }
        }
        let mut leaf = Node::new(key, 1);
        leaf.right = self.nodes[pred].right;
        let leaf = self.alloc(leaf);
        self.nodes[pred].right = Some(leaf);

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
                match self.nodes[pred].right {
                    Some(r) if self.nodes[r].level == lvl && self.nodes[r].key < key => pred = r,
                    _ => break,
                }
            }

            match self.nodes[pred].right {
                Some(r) if self.nodes[r].level == lvl => {
                    // Case 1: normal splice between two same-level nodes.
                    let mut c = Node::new(key, lvl);
                    c.right = Some(r);
                    c.down = Some(below);
                    let c = self.alloc(c);
                    self.nodes[pred].right = Some(c);
                    below = c;
                }
                _ => {
                    // Case 2: the extension k' would be the rightmost node of
                    // this level, i.e. immediately redundant. It is dismissed
                    // and the predecessor shortcuts down to the copy below:
                    // right(z) = k.
                    self.nodes[pred].right = Some(below);
                    break;
                }
            }
            lvl += 1;
        }

        // Paper: recompute hashes along pi only. Basic version: recompute all.
        self.recompute();
    }

    // --------------------------------------------------------- Delete (A.4)

    /// Revocation: the credential is actually removed, not nulled.
    pub fn delete(&mut self, k: u64) -> bool {
        let key = Key::Val(k);
        if !self.search(k) {
            return false;
        }

        // Collect k's tower: its leaf and every extension of it.
        let mut tower: Vec<NodeId> = Vec::new();
        for lvl in 1..=self.heads.len() {
            for id in self.level_nodes(lvl) {
                if self.nodes[id].key == key {
                    tower.push(id);
                }
            }
        }

        // Bypass every pointer into a removed node (same-level predecessors
        // and shortcut sources alike).
        for &t in &tower {
            let bypass = self.nodes[t].right;
            let mut sources: Vec<NodeId> = Vec::new();
            for lvl in 1..=self.heads.len() {
                for id in self.level_nodes(lvl) {
                    if id != t && self.nodes[id].right == Some(t) {
                        sources.push(id);
                    }
                }
            }
            for s in sources {
                self.nodes[s].right = bypass;
            }
        }

        // No rebalancing (A.5) in this basic version.
        self.recompute();
        true
    }

    // -------------------------------------------------------- Prove / Verify

    /// Prove(S, k) -> pi: the search path from the root to k's leaf, with the
    /// digest of the untaken branch at every node.
    pub fn prove(&self, k: u64) -> Option<Vec<ProofStep>> {
        let key = Key::Val(k);
        let mut steps = Vec::new();
        let mut v = self.root();
        loop {
            let n = &self.nodes[v];
            if n.level == 1 {
                match n.key.cmp(&key) {
                    Ordering::Equal => {
                        steps.push(self.step(v, Dir::Down));
                        return Some(steps);
                    }
                    Ordering::Greater => return None,
                    Ordering::Less => match n.right {
                        Some(r) => {
                            steps.push(self.step(v, Dir::Right));
                            v = r;
                        }
                        None => return None,
                    },
                }
            } else if in_interval(key, n.interval) {
                steps.push(self.step(v, Dir::Down));
                v = n.down.unwrap();
            } else if let Some(r) = n.right {
                steps.push(self.step(v, Dir::Right));
                v = r;
            } else {
                steps.push(self.step(v, Dir::Down));
                v = n.down.unwrap();
            }
        }
    }

    fn step(&self, id: NodeId, dir: Dir) -> ProofStep {
        let n = &self.nodes[id];
        let sibling = match dir {
            Dir::Down => n.right.map(|r| self.nodes[r].digest).unwrap_or(NULL_HASH),
            Dir::Right => n.down.map(|d| self.nodes[d].digest).unwrap_or(NULL_HASH),
        };
        ProofStep {
            key: n.key,
            level: n.level,
            interval: n.interval,
            sibling,
            dir,
        }
    }

    /// Verify(sigma, k, pi): recompute the digests bottom-up along pi and
    /// compare against the root digest. (In the credential system this check
    /// is what gets proven inside the zero-knowledge circuit, so that neither
    /// com_i nor pi is revealed.)
    pub fn verify(root_digest: &Hash, k: u64, steps: &[ProofStep]) -> bool {
        let last = match steps.last() {
            Some(s) => s,
            None => return false,
        };
        if last.level != 1 || last.key != Key::Val(k) || last.dir != Dir::Down {
            return false;
        }
        let mut h = NULL_HASH;
        for s in steps.iter().rev() {
            h = match s.dir {
                Dir::Down => node_hash(s.level, s.key, s.interval, &s.sibling, &h),
                Dir::Right => node_hash(s.level, s.key, s.interval, &h, &s.sibling),
            };
        }
        &h == root_digest
    }

    // ------------------------------------------------------------- internals

    fn alloc(&mut self, n: Node) -> NodeId {
        self.nodes.push(n);
        self.nodes.len() - 1
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
            if self.nodes[id].level != lvl {
                break;
            }
            out.push(id);
            cur = self.nodes[id].right;
        }
        out
    }

    /// Recompute intervals (Definition 1) and digests, bottom-up and right to
    /// left, so that every right/down dependency is already fresh.
    fn recompute(&mut self) {
        for lvl in 1..=self.heads.len() {
            let ids = self.level_nodes(lvl);
            for &id in ids.iter().rev() {
                let interval = if lvl == 1 {
                    let k = self.nodes[id].key;
                    (k, k)
                } else {
                    let d = self.nodes[id].down.expect("upper node without down");
                    let min = self.nodes[d].interval.0;
                    let max = match self.nodes[id].right {
                        // Individual Root: covers the whole keyspace.
                        None => Key::PosInf,
                        // right(v) in L_i: [min(down), min(right)]
                        Some(r) if self.nodes[r].level == lvl => self.nodes[r].interval.0,
                        // right(v) in L_j, j < i (shortcut): [min(down), max(right)]
                        Some(r) => self.nodes[r].interval.1,
                    };
                    (min, max)
                };
                let hr = match self.nodes[id].right {
                    Some(r) => self.nodes[r].digest,
                    None => NULL_HASH,
                };
                let hd = match self.nodes[id].down {
                    Some(d) => self.nodes[d].digest,
                    None => NULL_HASH,
                };
                let n = &mut self.nodes[id];
                n.interval = interval;
                n.digest = node_hash(lvl, n.key, interval, &hr, &hd);
            }
        }
    }
}

