# Slices: rust-client

- Slice 1 — tracer: lib skeleton + `address` + `Meta` codec + TCP `connect` dialing a stock Go node (outbound handshake only, returns `PeerConn`).
- Slice 2 — inbound: `listen`/`accept` with same handshake so a Go node can dial Rust; both directions verified live.
- Slice 3 — link liveness: ironwood frame codec (`uvarint len + type`) + keepalive so peers stay up past handshake.
- Slice 4 — E2E session: Ed→Curve25519 box session + traffic send/recv proving payload interop through Go (re-estimate scope once Slice 1 is green).
- Slice 5 — `tls://` dial+listen (same handshake over TLS, unauth certs like Go).
- Slice 6+ — one per step: `ws`/`quic`, TUN, admin (`getSelf/getPeers`), polish/backoff/reconnect.
