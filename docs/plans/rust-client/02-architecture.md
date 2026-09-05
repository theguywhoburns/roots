# Architecture: rust-client

## Fit
- `roots` is greenfield single binary (`src/main.rs`). It becomes a library-first crate: new `src/lib.rs` + modules (`address`, `handshake`, `link`), with `src/main.rs` kept as a thin demo/connectivity probe.
- Go `yggdrasil-go/src/core` maps to Rust `link` + `handshake` modules; Go `src/address` maps to Rust `address`; Go `ironwood` (routing/sessions) is NOT ported in full — Slice 1 stops at the link handshake, Slice 2 ports the minimal session/traffic subset needed for ping-level interop.
- No existing callers, storage, or services to preserve.

## Endpoints
- No HTTP/service routes (library, not a web service). The node's network surface is link-level, and both directions are in scope for the full node:
  - Outbound: `Client::connect(peer_uri)` dials `tcp://` (Slice 1), `tls://` next.
  - Inbound: `Client::listen(bind_uri)` accepts `tcp://` (Slice 2 with routing), `tls://` next. `quic/ws/wss/socks/unix` deferred.
- Slice 1 builds dial-only as the tracer; listen is Slice 2, not cut.

## Data
- none persistent. In-memory only: keypair (ed25519 64B priv / 32B pub), peer record `{uri, pubkey, priority}`, handshake `meta` struct. No tables, migrations, or queries.

## Flow
1. App calls `Client::connect(peer_uri)` with local ed25519 keypair.
2. `link` dials TCP (5s timeout) to host:port.
3. `handshake` builds `meta` (version 0.5 + pubkey + priority), appends `ed25519.Sign(blake2b512(password, pubkey))`, writes with 6s deadline.
4. `handshake` reads peer `meta`, checks preamble/length/version, verifies signature, rejects self/unauthorized key.
5. Authenticated `TcpStream` returned to caller (Slice 1 dial-only tracer); Slice 2 adds `listen` + hands both directions to session/router for encrypted mesh traffic.

## External
- Stock Go node (`yggdrasil-go` HEAD) used only as interop test peer — no code dependency, no patches.
- Rust crates (proposed): `tokio` (async net), `ed25519-dalek`, `blake2`, `rustls` (for later `tls://`). No env vars, no webhooks.
