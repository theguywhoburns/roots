# Program Design: go-client-parity

Gate 2 approved option B (workspace) and named five work items. This gate makes
the invisible decisions: the exact file moves, every new public signature, which
side of the lib/client line each multicast piece crosses, how vectors get
captured without a Go compiler, and the named tests.

Go citations verified 2026-09-24 against `reference/yggdrasil-go` `422836e`
(v0.5.14 — the same version as the installed oracle binary) and
`reference/ironwood` `d50055b`.

## Files

### Workspace mechanics (the "no workspace" line in AGENTS.md is superseded)

| File | Change | Why |
|---|---|---|
| `Cargo.toml` | add `[workspace] members = ["client"]`, `resolver = "3"`; delete the `[[bin]]` block; delete `tun`/`serde_json` from `[dev-dependencies]` (they move to the client) | Root stays the `roots` package, so `src/`, `examples/`, `tests/`, `reference/`, `docs/` paths in AGENTS.md and every plan doc stay valid. A member-relative layout (`crates/…`) would move 22 source files for no gain. |
| `Cargo.lock` | regenerated at root, committed | `--locked` in CI needs it. |
| `src/main.rs` | **moved** to `client/src/main.rs` (git mv) | The demo probe is client policy. |
| `client/Cargo.toml` | new: `name = "roots-client"`, `[[bin]] name = "roots"`, deps `roots = { path = ".." }`, tokio, serde_json, hex, ed25519-dalek, rand, tun, regex | `[[bin]]` cannot see `[dev-dependencies]`, which is what forced option B. |
| `client/src/lib.rs` | new, empty-ish: `mod` declarations only | Lets `client/tests/` exist. |
| `client/src/config.rs` | new | Go-shaped config: read/generate/normalise. → landed in Slice 6 as read/generate/**no normalise** (`-normaliseconf` is not implemented; see the Slice 6 corrections below). |
| `client/src/node.rs` | new | The single-task node loop (`Router` + `LinkSet` + command queue). Absorbs `Client::run_peer` and `drive`. |
| `client/src/links.rs` | new | Link manager: dial/listen tasks, per-URI backoff, the `link_id` dedup map Go has in `links.add`. |
| `client/src/admin.rs` | moved from `examples/admin.rs`, rewritten for parity | |
| `client/src/multicast.rs` | new | The syscall half: UDP6 socket, `SO_REUSEADDR`, `JoinGroup`, interface scan + regex, timers. |
| `client/src/tun.rs` | new | TUN device + the resolve-and-hold bridge, moved out of `examples/tun_ping.rs`. |
| `client/tests/admin_loopback.rs` | new | |

`examples/` stays in the `roots` package: they are *specimens of the library*,
not the client, and keep smoltcp as a dev-dep.

> **Corrections, 2026-09-24 (Slice 3, after the split was built).**
>
> 1. `tun` and `serde_json` could **not** leave the root `[dev-dependencies]` in
>    this slice: `examples/tun_ping.rs`, `examples/admin.rs` and
>    `examples/proto_probe.rs` still use them and only move to `client/src/` in
>    Slices 14 and 7. Deleting them here breaks the build the slice is supposed
>    to prove. The client therefore declares only `roots`, `tokio`,
>    `ed25519-dalek`, `rand`, `hex`; the dev-dep deletion finishes with those
>    two moves. The invariant this row existed for is unaffected and measurable
>    today: `cargo tree -p roots -e normal` has no client-only crate in it.
> 2. `tests/reconnect.rs` → `client/tests/reconnect.rs` (git mv) too. It is the
>    only caller of `run_peer`, so the table's `client/src/lib.rs` row ("lets
>    `client/tests/` exist") is load-bearing earlier than planned: without the
>    `pub mod node;` there, the test cannot reach the loop it exists to test.
> 3. CI must pass `--workspace` to clippy and test. From a non-virtual root,
>    cargo selects the root package only, so without it the client's bin, its
>    `node.rs` and its reconnect test would ship unlinted and unrun. `cargo fmt
>    --check` already walks every member from the root and needed no change.
> 4. `cargo run` from the root fails with "no bin target named `roots` in
>    default-run packages" — every documented invocation is now
>    `cargo run -q -p roots-client -- …`.
>
> **Corrections, 2026-09-24 (Slice 6, config).**
>
> 1. `client/tests/allowlist.rs` (new, 2 tests) is not in the table above. It is
>    where `AllowedPublicKeys` gets its first end-to-end exercise, so the config →
>    `LinkOptions` → `complete_accept` wiring has a test that a socket can fail.
> 2. `src/address.rs` did **not** arrive "already complete": its `Display` impls
>    zero-pad (`0200:13e1:0000:…`) where Go's `net.IP.String()` does not
>    (`200:13e1:0:…`). Slice 6 found this by feeding the real Go binary a
>    committed config, not by reading the module. See the row below.
> 3. `tests/go_vectors.rs` gained address/subnet **string** vectors. The byte
>    vectors that were there could not catch a formatting bug; these can.
> 4. `-normaliseconf`, `-exportkey`, `-autoconf`, `-logto`, `-user` and HJSON
>    output are dropped from the config slice. They are print paths around a
>    running node, and nothing in the parity metric needs them; `-json` is
>    accepted so a Go-shaped invocation line does not fail, and means nothing.
> 5. **`-useconffile` alone must not reach the demo probe.** The first draft of
>    `config_stage` returned `None` for a file source because the original slice
>    text said "a `-useconffile` with no identity flag falls through to the
>    probe", and the live check disproved both halves of that: an ordinary
>    `yggdrasil -useconffile /etc/yggdrasil.conf` **runs a node**, and our probe
>    dials a hard-coded default peer — so falling through would have made an
>    operator's config load start dialling out. A config source is now handled by
>    `ConfigLoaded` (identity printed, or a refusal to run a node we do not have
>    yet, `AGENTS.md`). `-genconf` stays the one flag whose meaning is a print-and-
>    exit *before* the identity stage, which is what `main.go:120-131` says; the
>    load cases at `main.go:105-119` have **no** `return`, and Go can print a key
>    from `-genconf` at all only because `main.go:93` already called
>    `config.GenerateConfig()` — which is why our `generate()` owns a fresh
>    identity instead of requiring a document.
>    Consequence worth remembering when Slice 7 lands: our config currently sets
>    `Listen: []`, so a node that did run would be dial-only and the probe would
>    still be the only thing reaching a peer.

### Library changes

| File | Change |
|---|---|
| `src/lib.rs` | delete `Client::run_peer` (121-155) and `drive` (162-195). `Client` keeps identity + connect/listen/accept sugar and stops being the only way to dial. |
| `src/link.rs` | `LinkSet` owns `AnyConn` (drops the `'a` lifetime), gains per-link accounting (`up`, `rx`, `tx`) and a `read_frame` that funnels every set-level read; `write` splits into hard/soft (see Seams). |
| `src/multicast.rs` | new, **no sockets, no `tokio::spawn`, no `std::env`** — advertisement codec, membership hash, the announce/listen state machine, `link_id`. |
| `src/driver.rs` | adapt the two read sites to `LinkSet::read_frame`; add `send_or_resolve`. |
| `src/traffic.rs`, `src/pathfind.rs`, `src/tree.rs`, `src/bloom.rs` | `links.write` → `write`/`write_via` per call site (11 sites). |
| `src/views.rs` | `peer_cost`, `next_hop`, `link_stats`, `pending_routes`. |
| `src/router.rs` | `frames: [u64; FRAME_KINDS]` + const assertion; `dropped_no_link` counter. |
| `src/address.rs` | ~~nothing (already complete)~~ — Slice 6 rewrote `Address`/`Subnet`'s `Display` to Go's `net.IP.String()` / `net.IPNet.String()` text. Byte derivation was always right; the string was not. |
| `src/peer.rs` | `PeerState` unchanged; `PeerConn`/`AnyConn` gain `inbound`. |

### Docs

`docs/protocol/` gets the ten pages Gate 2 listed, each with a **Provenance**
line naming either a Go `file:line` (for structure) or a capture
(`yggdrasil-0.5.14 binary, <what>, 2026-09-24`) for its vector. `AGENTS.md`
Layout + Boundary + Commands sections updated for the workspace in the same
slice that lands it.

## Types & signatures

### Seams in the library (the only two behavioural additions Gate 2 promised)

```rust
// src/link.rs — owned, 'static, countable.
pub struct LinkSet {
    entries: Vec<LinkEntry>,                      // was Vec<(key, &'a mut dyn Link)>
    last_write: HashMap<[u8; KEY_LEN], Instant>,  // unchanged: survives remove(), that IS the invariant
}
struct LinkEntry { peer: [u8; KEY_LEN], link: AnyConn, up: Instant, rx: u64, tx: u64 }

#[derive(Clone, Copy, Debug)]
pub struct LinkStats { pub up: Duration, pub rx_bytes: u64, pub tx_bytes: u64, pub inbound: bool }

impl LinkSet {
    pub fn new() -> Self;
    pub fn single(conn: AnyConn) -> Self;                         // was single(peer, &mut conn)
    pub fn add(&mut self, conn: AnyConn) -> Option<AnyConn>;      // returns the displaced link
    pub fn get(&mut self, peer: &[u8; KEY_LEN]) -> Option<&mut AnyConn>;
    pub fn remove(&mut self, peer: &[u8; KEY_LEN]) -> Option<AnyConn>; // caller reclaims or drops
    pub fn peers(&self) -> Vec<[u8; KEY_LEN]>;
    pub fn is_empty(&self) -> bool;
    pub fn len(&self) -> usize;
    pub fn idle_for(&self, peer: &[u8; KEY_LEN]) -> Duration;
    pub fn stats(&self, peer: &[u8; KEY_LEN]) -> Option<LinkStats>;
    /// Hard send: the caller named a link peer it believes is up. A missing
    /// entry is a bug, not a drop, and now says so (Gate 2's footgun).
    pub async fn write(&mut self, target: [u8; KEY_LEN], ftype: FrameType, payload: &[u8])
        -> Result<(), Error>;
    /// Soft send: forwarding to a next hop we may not have a link for.
    /// Go drops silently (`router.go` `peers[key]` lookup); we report it and
    /// the caller counts it. Ok(false) == no link, frame discarded.
    pub async fn write_via(&mut self, target: [u8; KEY_LEN], ftype: FrameType, payload: &[u8])
        -> Result<bool, Error>;
    /// Every set-level read goes here so rx accounting is real.
    pub async fn read_frame(&mut self, peer: &[u8; KEY_LEN]) -> Result<(FrameType, Vec<u8>), Error>;
}

// AnyConn carries what admin needs and what the set keys on.
pub struct AnyConn {
    pub remote_key: [u8; KEY_LEN],
    pub priority: u8,
    pub inbound: bool,                            // NEW: set by complete_accept, false by complete_dial
    pub kind: crate::peer::PeerKind,
    pub stream: Box<dyn LinkStream>,
}
```

Which `links.write` call becomes which: **hard** — `tree.rs:250,263,546`,
`driver.rs:223,264` (all address `peer_key`/`conn_peer`, a link we are serving);
**soft** — `traffic.rs:71`, `pathfind.rs:378,445,536`, `bloom.rs:349,394` (all
address a `greedy_next` choice or a fan-out target).

### Slice 4 corrections (recorded at implementation, 2026-09-24)

- **Counters are wire bytes.** `rx`/`tx` add `frame::wire_len(payload.len())`
  in both directions, so a frame costs what it costs on the socket (Go counts
  raw socket bytes, `yggdrasil-go/src/core/link.go:784-793`). The handshake
  bytes stay outside the counters — the known gap, stated on the test.
- **Two router-state reads moved onto the live set.** The table above kept
  `tree.rs:546` (`_sendReqs`) hard, which is right only if the loop iterates
  what Go iterates: `for pk, ps := range r.peers` (`router.go:189`). So
  `send_all_reqs` now iterates `links.peers()`, and `fix` asks
  `links.peers().contains(&info.parent)` instead of `tree.peers`
  (`router.go:229`). Both are mutation-pinned (`router_books_can_name_a_peer_with_no_link`,
  `fix_refuses_a_parent_with_no_link`); a hard send against the old
  `tree.peers` iteration aborts the serve on a stale key.
- **`Transport::Stream` gained `+ 'static`.** The set owns its conns, so a
  borrowed stream cannot be a member.
- **Two additions the design did not anticipate**, both required to make the
  eviction claim true: `LinkSet::send` **retires** an entry whose `write_frame`
  fails (Go discards write errors outright, `peers.go:189`, and lets that
  peer's own reader tear it down), and `Router::fatal_link_error(&links, &err)`
  decides whether a failed serve step aborts `serve_links` — a link error only
  means the set shrank, so it is fatal exactly when nothing is left to serve.
  Without both, a link that was dead-but-not-yet-evicted aborted every
  survivor with `Io(ConnectionReset)`.
- **Divergence found and left in place**, because fixing it is the hardening
  slice's job: nothing prunes `tree.peers`, `tree.infos` or `bloom.on_tree` when
  a link dies, so a node keeps a parent it has no link for. Go prunes all of it
  in `removePeer` (`ironwood/network/router.go:147`). Slice 4 makes the stale
  key *tolerable*; the lifecycle slice makes it *gone*.
  `a_stale_parent_is_kept_and_the_serve_survives_it` asserts the current shape
  as a tripwire and says so in its message.
- `TreeState::send_all_reqs` and `Router::use_response` are `pub(crate)` so a
  fixture can drive them; `use_response` is also how the `fix` test adopts its
  own lineage, rather than hand-writing an info no signature check would accept.

```rust
// src/driver.rs — resolve-and-hold, so TUN never blocks the loop.
pub enum Route { Sent, Queued }

/// Send `payload` to `dest` now, or start a DHT lookup and hold one payload
/// per destination until the notify lands (flushed by the existing code at
/// pathfind.rs:422-430). Single-slot-per-dest is Go's own behaviour
/// (`_bufferAndInit` overwrites `buf.data`), so a fast source overwrites.
pub async fn send_or_resolve(
    &mut self, links: &mut LinkSet, via: [u8; KEY_LEN],
    dest: &crate::address::Address, payload: Vec<u8>,
) -> Result<Route, Error>;
```

`resolve()` stays as-is for probes; `send_or_resolve` is built on the same rumor
slots, not on `resolve`.

```rust
// src/views.rs
pub fn peer_cost(&self, peer: &[u8; KEY_LEN]) -> u64;      // tree.rs:357 `cost`, made public
pub fn next_hop(&self, dest: &[u8; KEY_LEN]) -> Option<[u8; KEY_LEN]>; // root_path_for + greedy_next
pub fn link_stats(&self, peer: &[u8; KEY_LEN]) -> Option<LinkStats>;   // delegates to the set
pub fn pending_routes(&self) -> Vec<crate::address::Address>;          // rumors with a held payload
pub fn dropped_no_link(&self) -> u64;
```

`peer_cost` must copy Go exactly: `uint64(lags[p].Milliseconds())`, floored at
1, and a peer with no sample reads as **1 ms**, not `UNKNOWN_LATENCY`
(`ironwood/network/router.go:221-228`). `link_peers()` keeps its current tuple
shape; `inbound` comes from `LinkStats` instead.

### Multicast: decisions in the library, syscalls in the client

The split rule is an existing invariant, not a new one: **no `spawn`, no socket
policy in `src/`**. So the library owns the state machine and the wire, the
client owns `bind`/`join`/`read`/`write` and the interface scan.

```rust
// src/multicast.rs
pub const GROUP: &str = "[ff02::114]:9001";        // multicast.go:71, a hardcoded setup default
pub const PROTO_MAJOR: u16 = 0;                     // core/version.go:27
pub const PROTO_MINOR: u16 = 5;                     // core/version.go:28
pub const MAX_INTERVAL: Duration = Duration::from_secs(15);   // multicast.go:368

/// Big-endian: u16 major | u16 minor | 32 B pubkey | u16 port | u16 hashLen | hash.
/// Go's UnmarshalBinary checks `len(b) >= 40 + hashLen` and IGNORES trailing
/// bytes (advertisement.go:27-43) — we mirror both, including a hash shorter
/// than 64 B parsing fine and then failing the compare.
pub struct Advertisement { pub major: u16, pub minor: u16, pub pubkey: [u8; KEY_LEN],
                           pub port: u16, pub hash: Vec<u8> }
impl Advertisement { pub fn encode(&self) -> Vec<u8>;
                     pub fn decode(b: &[u8]) -> Result<Self, Error>; }

/// blake2b-512, key = the LOCAL interface's password, message = the PEER's
/// pubkey. Same construction as handshake::keyed_hash, different message.
pub fn membership_hash(password: &[u8], pubkey: &[u8; KEY_LEN]) -> [u8; 64];

/// Dedup identity: `urlForLinkInfo` — scheme://host/path with the query stripped
/// (core/link.go:766-769). addPeer, CallPeer and multicast all key on this.
pub fn link_id(uri: &str) -> String;

/// One interface the client matched against MulticastInterfaces and gave us.
pub struct InterfaceConfig { pub name: String, pub link_local: std::net::Ipv6Addr,
    pub beacon: bool, pub listen: bool, pub port: u16, pub priority: u8, pub password: Vec<u8> }

/// What the client is told to do. Ordering matters: Bind before Beacon.
pub enum Command {
    Bind   { iface: String, link_local: std::net::Ipv6Addr, port: u16, uri: String }, // tls listener, ?priority=&password=
    Beacon { iface: String, bytes: Vec<u8> },                                          // UDP payload to group:9001, zone=iface
    Dial   { uri: String, sintf: String, peer: [u8; KEY_LEN] },                         // ephemeral tls://[fe80::x%iface]:port?key=
    Unbind { iface: String },
}

pub struct Multicast { /* local_pubkey, ifaces, per-iface hash+priority+password,
                          per-iface listener port, per-iface (last_beacon, interval),
                          joined set */ }
impl Multicast {
    pub fn new(local_pubkey: [u8; KEY_LEN]) -> Self;
    /// Full replacement each tick (Go `_updateInterfaces` rebuilds the map;
    /// listeners whose iface or link-local address vanished get stopped).
    pub fn set_interfaces(&mut self, ifaces: Vec<InterfaceConfig>);
    /// Go `_announce` (multicast.go:247-377): join, bind-if-missing, beacon on
    /// the per-iface ramp (0,1s,2s,…,15s), one iface per call is fine.
    /// First beacon on a fresh iface waits one tick for `listener_up`.
    pub fn announce(&mut self, now: Instant) -> Vec<Command>;
    pub fn listener_up(&mut self, iface: &str, bound_port: u16);
    pub fn tick_interval(&self, iface: &str) -> Option<Duration>;   // diagnostics + tests
    /// Go `listen` (multicast.go:379-455): decode, require major && minor &&
    /// not-self, look up `zone` in our iface set, verify the keyed hash, then
    /// hand back an ephemeral dial URI. None = dropped, with the reason.
    pub fn receive(&mut self, zone: &str, from: std::net::SocketAddrV6, buf: &[u8], now: Instant)
        -> Option<Command>;
}
```

`receive` deliberately does **not** dedup. Go's `listen` calls `CallPeer` for
every valid beacon and the link manager rejects duplicates with
`ErrLinkAlreadyConfigured` after kicking the live link (`core/link.go:236-243`).
The client reproduces that: `links.rs` holds `HashMap<(String /*link_id*/, String /*sintf*/), ()>`
and a redial-eligibility flag per entry, so a duplicate ephemeral dial kicks
instead of stacking.

### The client's node loop (Go's actor shape, one task)

```rust
// client/src/config.rs — Go key names, Go defaults, JSON in and out.
// Shipped as of Slice 6. The sketch below was written from memory of Go's
// config and was wrong in three places, all corrected against
// `src/config/config.go:42-58`: `NodeConfig` has no `TunnelLocalTraffic` and no
// `Port` (both belong to older releases), `NodeInfo` is `null`-able so it maps
// to `Option<Map<…>>`, and `priority` is a `uint64` in
// `MulticastInterfaceConfig` even though it is a `uint8` on the wire
// (`config.go:60-67`).
pub struct Config { … }          // Go's field order; #[serde(default = "defaults",
                                 // rename_all = "PascalCase")], `IfMTU` renamed explicitly
pub struct MulticastIface { pub regex: String, pub beacon: bool, pub listen: bool,
    pub port: u16, pub priority: u64, pub password: String }
/// Go's defaults are per-platform (`src/config/defaults_linux.go:7-25`); we
/// mirror the Linux column: AdminListen `unix:///var/run/yggdrasil.sock`,
/// MulticastInterfaces `[{Regex:".*",Beacon:true,Listen:true}]`, IfMTU 65535,
/// IfName "auto". `MaximumIfMTU` is declared there and never read, so we do not
/// carry it, and `DefaultConfigFile` belongs to `yggdrasilctl`, not the node.
/// Consequence: the admin socket has to speak `unix://` too, not
/// just `tcp://` — Go dispatches on scheme (`admin.go:91,123`) and today's
/// `examples/admin.rs` only binds TCP.
pub fn defaults() -> Config;                         // mirrors defaults_linux.go, fresh key
impl Config {
    pub fn generate() -> String;                     // -genconf: defaults, AdminListen blanked
    pub fn load(source: &ConfigSource) -> Result<Config, ConfigError>;
    pub fn from_json(text: &str) -> Result<Config, ConfigError>;  // strip nulls, then postprocess
    pub fn signing_key(&self) -> Result<SigningKey, ConfigError>; // 64 B seed||pub, KeyMismatch checked
    pub fn address(&self) -> Result<Address, ConfigError>;
    pub fn subnet(&self) -> Result<Subnet, ConfigError>;
    pub fn link_options(&self) -> Result<LinkOptions, ConfigError>;  // AllowedPublicKeys -> allowlist
    pub fn to_json(&self) -> String;
}
pub enum ConfigSource { Stdin, File(String) }        // -useconf / -useconffile
pub struct Flags { genconf, useconf, useconffile, address, subnet, publickey,
                   json, help, rejected: Option<String>, positionals: Vec<String> }
impl Flags {
    pub fn parse(args: &[String]) -> Flags;          // Go's `flag` wording on rejection
    pub fn source(&self) -> Option<ConfigSource>;    // -useconf beats -useconffile
}

// client/src/node.rs — owns the Router, the LinkSet and the queue. Nothing else may.
pub enum Cmd {
    Dial { uri: String, persistent: bool },   // addPeer / CallPeer / multicast
    Drop { uri: String, sintf: String },      // removePeer: stop redialing, keep the link
    Accept { },                               // a listener got a handshake'd conn
    Packet { dest: Ipv6Addr, bytes: Vec<u8> },// from TUN
    Quit,
}
pub struct Node { key: SigningKey, router: Router, links: LinkSet,
                  rx: tokio::sync::mpsc::UnboundedReceiver<Cmd>, tx: mpsc::UnboundedSender<Cmd>,
                  outbox: Vec<([u8; 32], Vec<u8>)>, tick: Duration }
impl Node {
    pub fn new(key: SigningKey) -> (Self, mpsc::UnboundedSender<Cmd>);
    /// The only loop. `tick` bounds one serve slice; commands drain between slices.
    pub async fn run(&mut self) -> Result<(), roots::Error>;
    pub fn sender(&self) -> mpsc::UnboundedSender<Cmd>;
}
// Redial driver, moved out of Client (was run_peer / drive): policy data
// (SupervisedPeer, due_indices, backoff_cap) stays in the library.
pub async fn serve_until_closed(node: &Node, uri: String, key: [u8; 32]) -> roots::Error;

// client/src/admin.rs
struct Admin { tx: mpsc::UnboundedSender<Cmd>, /* link uri map, listener cfg */ }
/// Binds `tcp://host:port` or `unix://path` (Go supports both; `none` disables).
async fn serve_admin(uri: &str, tx: mpsc::UnboundedSender<Cmd>) -> Result<(), roots::Error>;
/// One connection: decode JSON values until EOF, honour `keepalive`, echo the
/// whole request back in `response.request` the way Go's struct does.
async fn admin_conn(sock: TcpStream, tx: mpsc::UnboundedSender<Cmd>) -> Result<(), roots::Error>;
enum SortBy { Default, Uptime, Cost }              // getpeers.go:68-76
fn sort_peers(entries: &mut Vec<PeerEntry>, by: SortBy);   // stable, Go's three comparators
```

### Slice 5 corrections (recorded at implementation, 2026-09-24)

- **`Cmd::Accept` carries the link**: `Accept { conn: AnyConn }`. The sketched
  `Accept { }` has no way to hand a handshake'd connection to the loop, and
  there is nothing to look it up from — the listener is not the node's.
- **`Cmd::Packet { dest: Ipv6Addr }` deferred to Slice 12** (it is the TUN
  command, and `send_or_resolve` is its dependency). In its place the loop gained
  `Cmd::Send { dest: [u8; KEY_LEN], bytes }`, because the slice's own proof needs
  a node that can put a payload on a session and no keyed form existed. Slice 12
  adds the address-keyed variant alongside it, not instead.
- **`Cmd::Dial` gained `sintf`** (`Dial { uri, sintf, persistent }`). The dedup
  key Go validates on is `(link_id, sintf)` (`link.go:54-57`); a URI-only dial
  cannot express the interface-peer case multicast dials into, and `Drop` already
  had `sintf`.
- **No `serve_until_closed`.** The sketch kept it as the redial driver inherited
  from `Client::run_peer`; `Links::start_due` + the node loop now own redial
  outright, so the helper would be a second policy home. `run_peer` and `drive`
  stay deleted, and `tests/reconnect.rs` was rewritten onto `Node` — there is
  exactly one redial path in the tree.
- **`Node` fields beyond the sketch**: `peers: Links`, `events` (the dial-task
  callback receiver), `quit`. `Node::with_tick` added so a test can shrink the
  slice; `new`/`sender` unchanged.
- **`link_id` lives in `client/src/links.rs`, not `src/multicast.rs`.** The
  library file table listed it there, but the same section says multicast's
  `receive` deliberately does not dedup and "the client reproduces that:
  `links.rs` holds `HashMap<(link_id, sintf), …>`". Dedup is link-manager
  bookkeeping, so its key function sits with it. Slice 10 constructs dial URIs
  and never needs to strip a query.
- **`Error::is_link()`** is a library addition the file table did not list. The
  loop needs Go's "link gone" vs "node broken" split (`peers.go:228`) without
  matching on `Error`'s variants from outside the crate.

## Call stack

**Startup** (`client/src/main.rs`): `Flags::parse` → `rejected`/`-h` → config →
`Node::new` → spawn listeners (`tls_listen`/`ws_listen`/`quic_listen`/`listen`)
each sending `Cmd::Accept` → spawn persistent dials
(`Cmd::Dial{persistent:true}` behind `SupervisedPeer`) →
spawn `admin::serve_admin` → spawn `multicast::run` (socket + timers +
`Multicast::announce`/`receive`, commands into `Node`) → spawn `tun::bridge` if
`IfName`/`IfMTU` ask for one → `Node::run`. Every task talks to the node only
through `Cmd`; only `run` touches `Router`/`LinkSet`.

**As shipped by Slice 6, the chain stops after config.** `config_stage` handles
`-genconf` (print and exit) and the load path, then prints `-address`/`-subnet`/
`-publickey` in Go's order and exits; a loaded config with nothing to print is
reported (`config loaded for address …`) and `exit(2)`, because wiring a whole
node to a config is Slice 7's admin work and dialling out with an identity the
operator only asked us to *read* would be worse. `TunnelLocalTraffic` is gone from
the sketch above: it is not a 0.5.14 `NodeConfig` field.

**Multicast beacon in** — client `recv_from` → `Multicast::receive(zone, from,
buf)` → decode → version/self checks → iface lookup → `membership_hash` compare →
`Command::Dial{uri: "tls://[fe80::x%eth0]:port?key=..&priority=..&password=.."}`
→ client `links::dial_once(uri, sintf)`: `link_id(uri)` already in the map →
kick, return `AlreadyConfigured` (debug log, as Go does) → else
`Client::connect_tls` → `Cmd::Dial` lands → `router.register` →
`links.add(conn)` → next `serve` slice drives it.

**TUN packet out** — `tun::bridge` reads a frame → `Cmd::Packet{dest, bytes}` →
`Node::run` drains → `router.send_or_resolve(links, via, dest, bytes)` → `Queued`
(a rumor lookup went out, payload held in `path.rumors[xkey(dest)].pending`) →
later a `PathNotify` arrives → existing flush at `pathfind.rs:422-430` →
`pathfinder_send` → session init → payload delivered; `Session` replies land in
`router.inbox` → `tun::bridge` writes them to the device.

**admin getPeers** — `yggdrasilctl getPeers` → `admin_conn` decodes one value →
`handlers["getpeers"]` → argument struct (`{"sort":…}`) → for each live link:
`router.link_peers()` + `router.link_stats(peer)` + `router.peer_cost(peer)` +
the client's own `uri`/`sintf` map → `sort_peers` → `json!` with Go's field names
→ `encoder.Encode` (pretty, one value per response) → loop iff `keepalive`.

## Vector capture (how the 10 unguarded kinds actually close)

No Go compiler here, so nothing is transcribed; everything is **captured from
the installed oracle binary** and checked in as hex. Two shapes:

1. **`examples/go_capture.rs`** (dev-dep example in the `roots` package, not the
   client): start `yggdrasil -useconf` with a JSON config that listens on
   `tcp://127.0.0.1:0`-ish fixed port, `AdminListen: "tcp://127.0.0.1:19xxx"`,
   `MulticastInterfaces: []`, `TunnelLocalTraffic: false`. Dial it with our
   `Tcp` transport while a `tee` wrapper records raw bytes both directions →
   that is the `meta` handshake + `SigReq`/`SigRes`/`Announce`/bloom/path
   traffic from Go, verbatim. Reverse direction: point the Go node's `Peers` at
   our listener (`examples/hs_answer.rs`) to capture what Go *sends* first.
2. **`examples/go_relay.rs`**: a `tcp_proxy`-style MITM between **two local Go
   nodes** (`Peers` pointing at each other) — captures Go↔Go frames we never
   produce ourselves, which is the only way to get a real `ack`/`key` rotation
   and a Go-generated `Announce` chain.

Each capture lands in `tests/go_vectors.rs` as `const GO_*: &str` with a
provenance comment (binary version, date, which link, Go `file:line` for the
structure). Session-key-dependent kinds (`init`, `ack`, `key`) are captured as
*decryptable* triples — Go private key + Go public key + bytes — the way
`GO_INIT` at `src/session.rs:724` already is, because a raw blob we cannot open
proves nothing.

**Ordering consequence:** `meta` is the cheapest real win and needs only one
running Go node, so the vector slices come *before* the doc pages that cite
them; `docs/protocol/20-handshake.md` is written in the same slice as its
vector, never after.

> **Correction, 2026-09-24 (Slice 2, after the harness was built). The decision
> to capture rather than transcribe stands and was right; four mechanics in the
> section above were wrong.**
>
> 1. `AdminListen: "tcp://127.0.0.1:19xxx"` is unnecessary — `""` disables admin
>    and removes a port to collide with. `TunnelLocalTraffic: false` does **not**
>    stop Go from creating a TUN: `cmd/yggdrasil/main.go:282` panics on
>    `operation not permitted` for any unprivileged start, so the oracle runs
>    under `unshare -Un --map-root-user` — and a fresh netns has `lo` down, which
>    the harness raises itself.
> 2. "Dial it with our `Tcp` transport while a `tee` wrapper records raw bytes"
>    cannot work: `link::dial` consumes the remote `meta` inside the handshake
>    and returns no raw bytes, which is the entire object of the exercise. The
>    harness holds a bare `TcpStream`, reads Go's `meta` verbatim (`read_meta`),
>    writes its own re-encoded bytes, then reads envelope frames
>    (`read_frame_raw`).
> 3. A **second identity is required**, not optional. A link whose `meta` carries
>    the listener's own key is accepted and then closed silently
>    (`ErrLinkToSelf`, `core/link.go:158`, checked at :662), so the `--frames`
>    window produced nothing until the harness dialled as a separate node.
>    `OUR_SEED` is now part of the design.
> 4. Shape 2 (`examples/go_relay.rs`, the Go↔Go MITM) turned out **not** to be
>    needed for the first kinds: one dialled listener already yields Go's write
>    path for `meta`, `SigReq`, `BloomFilter` and `Announce`, so Slice 2 shipped
>    without it. It stays in the plan at Slice 13, where a session `ack`/`key`
>    rotation is the only remaining thing that needs two Go nodes.

## Test plan

Named before they exist. Every "fail" column says what the test does to today's
code.

| Test | Asserts | Fails today? |
|---|---|---|
| `workspace_client_binary_builds` | `cargo test --workspace` green; `roots` lib builds with no `tun`/`serde_json`/`regex` in its graph (a `#[cfg]`-free check via `cargo tree`) | yes (deps are dev-only today, `Client` is in the lib) |
| `three_node_mesh_transit` (new `tests/mesh3.rs`, the outstanding prerequisite) | A—B—C line: A and C never share a link; C resolves A's address through B, A↔C session payloads arrive, and killing B's link to A leaves the surviving leg serving | yes (no such test) |
| `linkset_write_reports_missing_peer` | `write()` to an absent key is `Err`, `write_via()` is `Ok(false)` and bumps `dropped_no_link()` | yes (both silently `Ok(())` now) |
| `frame_kinds_match_table_len` | `FRAME_KINDS == FrameType::ALL.len()`, and `Router::frames` has that len | no (guards a future panic — the honest case) |
| `anyconn_records_direction` | `complete_dial` → `inbound == false`, `complete_accept` → `true`; survives `LinkSet::add`/`stats` | yes (field absent) |
| `link_stats_counts_frame_bytes` | rx/tx grow by exactly `uvarint(len+1) + 1 + len` per write and `1 + len` per read (the reader sees the body after the length prefix), `up` advances | yes (no counters) |
| `send_or_resolve_queues_then_delivers` | first call to an unknown dest → `Queued`, no session; after a notify → payload delivered without a second call; a second payload before the notify overwrites the first | yes (no such entry point) |
| `peer_cost_matches_go_semantics` | no-lag peer costs 1 ms, not `UNKNOWN_LATENCY` | no — `tree.rs:357-364` already `unwrap_or(0).max(1)`, matching `ironwood/network/router.go:221-228`. Pure guard, worth having because admin starts publishing the number |
| `multicast_advertisement_roundtrips_and_rejects` | encode→decode identity; `< 40 B` rejected; trailing bytes accepted; short hash parses | new file |
| `multicast_hash_over_peer_key` | `membership_hash(pw, pubkey)` equals a Go-captured 64 B hash | new file, needs capture |
| `multicast_ignores_minor_version_mismatch` | beacon with minor 6 → `receive` returns `None` | new file |
| `multicast_beacon_ramps_to_cap` | successive `announce` gaps 0,1s,…,15s; `set_interfaces` swap stops a vanished iface's listener | new file |
| `multicast_dial_uri_params` | URI is `tls://[fe80::..%eth0]:port?key=<hex>&priority=<n>&password=<pw>`, query order stable, no self-dial | new file |
| `link_id_strips_query` | `tls://h:p?password=x&a=b` → `tls://h:p` | new file |
| `go_meta_handshake_bytes_match_captured` | our `Meta::encode`/`keyed_hash` output equals Go's bytes for the same key + password, both the empty-password and keyed branches | needs capture; expected to pass once captured, and that is the point |
| `admin_keepalive_honours_second_request` | two requests on one connection, both answered (`"keepalive": true` on the first) | yes (connection closes after reply 1) |
| `admin_getpeers_sort_modes` | `""`/`uptime`/`cost` orderings each differ on a crafted 3-peer fixture, stable on ties | yes (arg ignored) |
| `admin_getpeers_field_parity` | every Go `PeerEntry` json name present with `omitempty` semantics: `up`, `inbound`, `cost`, `uptime`, `bytes_recvd`, `rate_sent`, … | yes (5 fields hardcoded) |
| `admin_remote_query_targets_resolved_hop` | remote query for key K goes out the link `next_hop(K)`, not `peers()[0]` | yes (uses `peers().next()`) |
| `admin_removepeer_keeps_live_link` | `removePeer` stops redial but the current link keeps serving; `getPeers` still lists it as up | yes (we drop it) |
| `admin_error_strings_match_go` | error strings byte-identical to Go: "unknown action 'x', try 'list' for help", "no request specified", "failed to find request" | yes (ours differ) |
| `admin_unix_socket_matches_tcp` | `unix:///tmp/…sock` and `tcp://127.0.0.1:…` answer `list` with identical bytes; `AdminListen: "none"` binds nothing | yes (TCP-only) |

Loopback only. No test in this plan needs internet, a TUN device, or a Go
compiler; the capture examples need the installed Go **binary** and are dev
tools, not tests — the vectors they produce are committed, so CI stays
hermetic.

## Least confident decisions

1. **Workspace at the root package instead of `crates/`.** Cheapest diff, keeps
   every documented path valid, but `roots = { path = ".." }` is an unusual
   edge and `cargo publish` semantics for a root-package-plus-member workspace
   are untested here. If publishing the crate ever matters, this is the thing
   that gets redone.
2. **`LinkSet` owning `AnyConn`.** It buys the command queue, kills the `'a`
   gymnastics in `admin.rs`, and keeps the send-clock invariant, but it means
   typed `PeerConn<T>` links can no longer be served directly — every caller
   pays one `AnyConn::new`. ~15 call sites churn. Alternative: keep `'a` and
   hand-roll the queue in the client with `unsafe`-free reborrow tricks; I don't
   want that.
3. **Tick-bounded command latency.** `Node::run` drains `Cmd` between serve
   slices, so a TUN packet or admin request waits up to `tick` (50 ms proposed).
   Fine for the demos; unproven for throughput. Escape hatch if it measures bad:
   shrink the read slice, or give TUN its own `Router` behind a mutex — which
   breaks the lock-free invariant and is a real decision, not a refactor.
4. **Multicast state machine in the lib, sockets in the client.** Chosen because
   the lib has no `spawn` today and because the state machine is what
   `docs/protocol/a0-multicast.md` has to document. Cost: the client owns a
   fiddly pile of syscalls and the first beacon on a new interface is one tick
   late (Go's is immediate).
5. **`inbound`/byte counters as a `LinkSet` change**, not a `Router` one. The
   router would be a more natural home for peer statistics (Go keeps them on
   `peer`), but `Router` never sees raw reads — the set is the only place both
   directions pass. If we later move I/O behind the router, this moves back.
6. **Config unknown keys are an error.** RESOLVED THE OTHER WAY at Slice 6
   (2026-09-24). We are lenient, exactly like Go: Go's `DisallowUnknownFields`
   call sits in the admin decoder (`admin.go`) and is inert on the config path, so
   `encoding/json` ignores junk keys, and an unknown key in a config file is a
   *typo in a key Go renamed* far more often than it is a typo we can catch.
   Piped Go output is the case that must never break, so it decided the question.
   `unknown_keys_are_ignored_like_go` is the test. The strictness we do keep is
   about flags, not keys: an unknown *flag* is rejected with Go's `flag` wording,
   because `-suseconf` silently running the demo probe is a footgun an operator
   cannot see.
7. **A `null` in a config is an error.** Also resolved at Slice 6: Go's
   `encoding/json` leaves the destination untouched for `null`, at every depth, so
   a null is *identical to absent*. Reproduced by stripping nulls recursively
   before deserialising — the alternative is a per-field `deserialize_with` on 14
   fields that still would not cover nulls inside `MulticastInterfaces` entries.
   Divergences we chose to keep, and why they cannot hurt interop, are in
   `00-status.md` under "Slice 6 findings": JSON-only output (`-json` is a no-op),
   no HJSON/UTF-16 BOM sniff, `KeyMismatch` checked where Go trusts the tail, and
   no `-normaliseconf`/`-exportkey`/`-autoconf` until something asks for them.
