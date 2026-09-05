# Program Design: rust-client

## Files
- `src/lib.rs` — crate root, re-exports `Client`, `address`, `handshake`, `link`, `error`.
- `src/address.rs` — `AddrForKey`/`SubnetForKey`/`GetKey` port of Go `src/address/address.go` (new, no existing file).
- `src/handshake.rs` — `Meta` TLV encode/decode/check + password sign/verify (new; mirrors Go `src/core/version.go`).
- `src/link.rs` — TCP dial + accept + `handler` orchestration (new; mirrors Go `src/core/link.go` + `link_tcp.go` for Slice 1/2).
- `src/error.rs` — single `Error` enum for handshake/link/address failures (new; no existing error type).
- `src/main.rs` — existing demo only: parse args, `connect`, print peer key/address (thin probe, no logic).
- `Cargo.toml` — add `tokio` (net/time), `ed25519-dalek`, `blake2`, `thiserror` (or `std::io::Error` mapping if we cut a dep).
- `tests/interop_go.rs` (Slice 1) — spawns/binds stock Go node, asserts Rust dial succeeds (new).

## Types & signatures
```rust
// address.rs
pub struct Address(pub [u8; 16]);
pub struct Subnet(pub [u8; 8]);
pub fn addr_for_key(public_key: &[u8; 32]) -> Address;
pub fn subnet_for_key(public_key: &[u8; 32]) -> Subnet;
pub fn key_for_addr(addr: &Address) -> [u8; 32]; // lossy, trailing bits zero-filled pre-inversion

// handshake.rs
pub const PROTOCOL_MAJOR: u16 = 0;
pub const PROTOCOL_MINOR: u16 = 5;
pub struct Meta { pub major: u16, pub minor: u16, pub public_key: [u8; 32], pub priority: u8 }
impl Meta {
  pub fn encode(&self, secret: &ed25519_dalek::SigningKey, password: &[u8]) -> Vec<u8>;
  pub fn decode(buf: &[u8], password: &[u8]) -> Result<Self, Error>;
  pub fn check(&self) -> Result<(), Error>;
}

// link.rs
// link.rs — transports are compile-time primitives: new protocols = new `Transport` impl, no registry.
pub trait Transport {
  async fn dial(addr: &str, timeout: std::time::Duration) -> Result<tokio::net::TcpStream, Error>;
}
pub struct Tcp; // Slice 1 impl; future: Tls, Quic, Ws, ...
impl Transport for Tcp { async fn dial(addr: &str, timeout: std::time::Duration) -> Result<tokio::net::TcpStream, Error>; }
pub struct LinkOptions { pub password: Vec<u8>, pub priority: u8, pub pinned_key: Option<[u8; 32]>, pub allowed_keys: Vec<[u8; 32]> }
pub struct PeerConn<T: Transport = Tcp> { pub remote_key: [u8; 32], pub stream: tokio::net::TcpStream, pub _t: std::marker::PhantomData<T> }
pub async fn dial(uri: &str, local: &ed25519_dalek::SigningKey, opts: &LinkOptions) -> Result<PeerConn<Tcp>, Error>;
pub async fn listen(bind: &str, local: &ed25519_dalek::SigningKey, opts: &LinkOptions) -> Result<tokio::net::TcpListener, Error>;
pub async fn accept(listener: &tokio::net::TcpListener, local: &ed25519_dalek::SigningKey, opts: &LinkOptions) -> Result<PeerConn<Tcp>, Error>;

// lib.rs
pub struct Client { pub key: ed25519_dalek::SigningKey }
impl Client {
  pub fn new(key: ed25519_dalek::SigningKey) -> Self;
  pub fn address(&self) -> Address;
  pub fn subnet(&self) -> Subnet;
  pub async fn connect(&self, uri: &str, opts: &LinkOptions) -> Result<PeerConn, Error>;
}

// error.rs
pub enum Error { InvalidPreamble, InvalidLength, BadPassword, BadVersion(u16, u16), SelfDial, KeyNotAllowed, Io(std::io::Error), BadUri(String) }
```

## Call stack
- Dial (Slice 1): `Client::connect` → `link::dial` (TCP connect 5s) → `Meta::encode` → write (6s deadline) → read header+body → `Meta::decode` → `Meta::check` → self/pin/allowlist checks → `PeerConn`.
- Listen (Slice 2): `link::listen` (bind) → loop `accept` → same encode/write/read/verify with `inbound=true` → `PeerConn` → (later) session/router handoff.
- Address: `Client::address/subnet` → `addr_for_key/subnet_for_key` (pure, no I/O).

## Test plan
- `address_vectors_go`: Go `address_test.go` pubkey → assert `200:8484:...` bytes and `0300::` subnet prefix.
- `address_roundtrip_lossy`: `addr → key_for_addr → addr_for_key` preserves recoverable prefix bits.
- `meta_roundtrip`: `encode` then `decode` with same password yields original fields.
- `meta_bad_password`: decode with wrong password asserts `BadPassword`.
- `meta_bad_version`: mutated major/minor asserts `BadVersion`.
- `self_dial_rejected`: handshake against own pubkey asserts `SelfDial` (unit, no net).
- `interop_go_tcp` (Slice 1 gate): Rust `connect` to stock Go `tcp://127.0.0.1:port` succeeds; Go `getPeers` shows Rust key.
- `listen_accept_local` (Slice 2 gate): Rust `listen` + Go dial completes both directions.

## Least confident decisions
1. `tokio` vs bare `std::net` + threads — leaning `tokio` for later quic/ws and deadlines, but Slice 1 could be sync.
2. Password cap at 64B (`blake2b.Size`) to match Go — confirm truncation vs reject on longer input.
3. `priority: u8` max-wins rule ported verbatim — untested effect on Rust-side path selection until router exists.
4. `thiserror` vs hand-rolled `std::fmt::Display` — prefer fewer deps, but `thiserror` is conventional.
5. URI query parsing (`?password=&priority=&key=`) — minimal hand parser vs `url` crate.
6. Slice 2 router scope: minimal path/traffic subset vs fuller ironwood port — needs re-estimate once Slice 1 interop is green.
