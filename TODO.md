# TODO

## Public-mesh TUN run (needs a TUN-capable host + second live node)

`examples/tun_ping.rs` is loopback-verified only (kernel ↔ TUN ↔ session ↔
loopback peer, RTT 3.1s incl. kernel, checked under `unshare -Urn` because
the sandbox blocks `TUNSETIFF`). Still unverified: the same plumbing
against the live mesh.

Steps on a host with TUN privileges (root or CAP_NET_ADMIN, `iproute2`):

1. `cargo run -q --example tun_ping` currently uses fixed keys/seeds over a
   loopback link. Extend it (or drive it) so side A peers a **public**
   node (`tcp://bode.theender.net:42069`) while side B resolves A over the
   DHT, or run two instances on two hosts and ping A's TUN address from B.
2. Confirm ICMPv6 echo request/reply round-trips through TUN + E2E
   session + public mesh, and that the kernel answers (watch `reply …
   bytes` + `RTT ~=` lines).
3. Check for MTU issues on the real path (TUN mtu 1280; session payloads
   must stay within the link `MAX_MESSAGE_SIZE` after framing overhead).
4. Record results in `docs/plans/rust-client/00-status.md` (Slice 15 line)
   and flip this entry to DONE.

Why it wasn't done in-sandbox: `/dev/net/tun` exists but the kernel
denies `TUNSETIFF` (`Operation not permitted`, even via `ip tuntap add`),
and `unshare -Urn` (where TUN works) has no internet route for public
peers.
