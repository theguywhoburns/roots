//! Router traits: narrow contracts between algorithm tables and the driver.
//!
//! The god-object failure was every module touching every field. Now each
//! table owns its state (`tree.rs:TreeState`, `pathfind.rs:PathState`,
//! `bloom.rs:BloomState`, `session.rs:SessionState`, `proto.rs:ProtoState`)
//! and cross-table work goes through explicit refs orchestrated by the
//! driver (`src/driver.rs`). Async I/O stays in `impl Router`; traits below
//! are the sync seams (expiry, views) plus the transport template.

use crate::address::KEY_LEN;

/// Read-only diagnostics snapshot (admin adapter, `dump`, tests).
pub trait Snapshot {
    fn parent(&self) -> Option<[u8; KEY_LEN]>;
    fn root_and_depth(&self) -> Option<([u8; KEY_LEN], usize)>;
    fn known_nodes(&self) -> usize;
    fn has_path(&self, key: &[u8; KEY_LEN]) -> bool;
    fn has_session(&self, key: &[u8; KEY_LEN]) -> bool;
    fn path_details(&self, key: &[u8; KEY_LEN]) -> Option<(Vec<u64>, u64)>;
    fn get_paths(&self) -> Vec<([u8; KEY_LEN], Vec<u64>, u64)>;
    fn get_sessions(&self) -> Vec<[u8; KEY_LEN]>;
    fn link_peers(&self) -> Vec<([u8; KEY_LEN], u64, u8, bool, u128)>;
    fn tree_entries(&self) -> Vec<([u8; KEY_LEN], [u8; KEY_LEN], u64)>;
    fn dump(&self) -> String;
}
