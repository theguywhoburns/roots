//! Read-only router views: snapshot queries for diagnostics and the admin adapter.
//! Pure borrows over the composed tables; the lib never prints (see `dump`).

use crate::address::KEY_LEN;
use crate::router::Router;
use crate::traits::Snapshot;

impl Router {
    pub fn parent(&self) -> Option<[u8; KEY_LEN]> {
        self.tree.infos.get(&self.pubkey).map(|i| i.parent)
    }

    pub fn root_and_depth(&self) -> Option<([u8; KEY_LEN], usize)> {
        let mut next = self.pubkey;
        let mut depth = 0;
        loop {
            let info = self.tree.infos.get(&next)?;
            if info.parent == next {
                return Some((next, depth));
            }
            depth += 1;
            if depth > 1024 {
                return None;
            }
            next = info.parent;
        }
    }

    pub fn known_nodes(&self) -> usize {
        self.tree.infos.len()
    }

    /// Debug snapshot of tree + path + link state. Returns text instead of
    /// printing: the lib never writes to stderr; binaries decide (gated
    /// behind `ROOTS_DBG_DUMP` in `src/main.rs`).
    pub fn dump(&self) -> String {
        let mut out = String::new();
        let mut peers: Vec<_> = self.tree.peers.keys().collect();
        peers.sort();
        for k in peers {
            let p = &self.tree.peers[k];
            // `kind` is roots-only diagnostics (our `dump` format, never on
            // the wire): `go` vs `roots`. Gated behavior fixes key off this.
            let kind = if p.kind.is_roots() { "roots" } else { "go" };
            out.push_str(&format!(
                "PEER key={} prio={} order={} impl={kind}\n",
                hex::encode(k),
                p.prio,
                p.order
            ));
        }
        let mut keys: Vec<_> = self.tree.infos.keys().collect();
        keys.sort();
        for k in keys {
            let i = &self.tree.infos[k];
            out.push_str(&format!(
                "INFO key={} parent={} seq={} port={}\n",
                hex::encode(k),
                hex::encode(i.parent),
                i.res.req.seq,
                i.res.port
            ));
        }
        let mut paths: Vec<_> = self.path.entries.keys().collect();
        paths.sort();
        for k in paths {
            let e = &self.path.entries[k];
            out.push_str(&format!(
                "PATH key={} path={:?} seq={}\n",
                hex::encode(k),
                e.path,
                e.seq
            ));
        }
        out.push_str(&format!("SELF coords={:?}\n", self.root_path()));
        out
    }

    /// True when we hold a live source route to `key` (for diagnostics).
    pub fn has_path(&self, key: &[u8; KEY_LEN]) -> bool {
        self.path.entries.contains_key(key)
    }

    /// True when an E2E session exists for `key` (for diagnostics).
    pub fn has_session(&self, key: &[u8; KEY_LEN]) -> bool {
        self.sess.sessions.contains_key(key)
    }

    /// Learned source route + notify seq for `key` (for diagnostics).
    pub fn path_details(&self, key: &[u8; KEY_LEN]) -> Option<(Vec<u64>, u64)> {
        self.path.entries.get(key).map(|e| (e.path.clone(), e.seq))
    }

    /// All learned source routes as `(key, path, seq)`, sorted by key
    /// (for diagnostics / admin adapter).
    pub fn get_paths(&self) -> Vec<([u8; KEY_LEN], Vec<u64>, u64)> {
        let mut out: Vec<_> = self
            .path
            .entries
            .iter()
            .map(|(k, e)| (*k, e.path.clone(), e.seq))
            .collect();
        out.sort_by_key(|(k, _, _)| *k);
        out
    }

    /// Peer keys with an open E2E session, sorted (for diagnostics).
    pub fn get_sessions(&self) -> Vec<[u8; KEY_LEN]> {
        let mut out: Vec<_> = self.sess.sessions.keys().copied().collect();
        out.sort();
        out
    }

    /// Direct link peers as `(key, port, priority, up, lag_ms)`, sorted by
    /// key: `up` tracks the last SigReq round-trip, `lag_ms` saturates at
    /// `u32::MAX` while unmeasured (for diagnostics / admin adapter).
    pub fn link_peers(&self) -> Vec<([u8; KEY_LEN], u64, u8, bool, u128)> {
        let mut out: Vec<_> = self
            .tree
            .peers
            .iter()
            .map(|(k, p)| (*k, p.port, p.prio, p.responded, p.lag.as_millis()))
            .collect();
        out.sort_by_key(|(k, _, _, _, _)| *k);
        out
    }

    /// Spanning-tree entries as `(key, parent, seq)`, sorted by key
    /// (for diagnostics / admin adapter).
    pub fn tree_entries(&self) -> Vec<([u8; KEY_LEN], [u8; KEY_LEN], u64)> {
        let mut out: Vec<_> = self
            .tree
            .infos
            .iter()
            .map(|(k, i)| (*k, i.parent, i.res.req.seq))
            .collect();
        out.sort_by_key(|(k, _, _)| *k);
        out
    }
}

impl Snapshot for Router {
    fn parent(&self) -> Option<[u8; KEY_LEN]> {
        self.parent()
    }
    fn root_and_depth(&self) -> Option<([u8; KEY_LEN], usize)> {
        self.root_and_depth()
    }
    fn known_nodes(&self) -> usize {
        self.known_nodes()
    }
    fn has_path(&self, key: &[u8; KEY_LEN]) -> bool {
        self.has_path(key)
    }
    fn has_session(&self, key: &[u8; KEY_LEN]) -> bool {
        self.has_session(key)
    }
    fn path_details(&self, key: &[u8; KEY_LEN]) -> Option<(Vec<u64>, u64)> {
        self.path_details(key)
    }
    fn get_paths(&self) -> Vec<([u8; KEY_LEN], Vec<u64>, u64)> {
        self.get_paths()
    }
    fn get_sessions(&self) -> Vec<[u8; KEY_LEN]> {
        self.get_sessions()
    }
    fn link_peers(&self) -> Vec<([u8; KEY_LEN], u64, u8, bool, u128)> {
        self.link_peers()
    }
    fn tree_entries(&self) -> Vec<([u8; KEY_LEN], [u8; KEY_LEN], u64)> {
        self.tree_entries()
    }
    fn dump(&self) -> String {
        self.dump()
    }
}
