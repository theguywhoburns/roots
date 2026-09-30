# TODO

## Public-mesh TUN run (needs a TUN-capable host + second live node)

**Now a config away, not a program away.** Slice 14 moved the bridge into the
node itself, so this is two config files and a `ping` rather than a harness:
`IfName` set, a `Peers` entry naming a public node, and
`ip -6 route add <peer>/128 dev <ifname>` on each side (a TUN is addressed
`/128`, so a mesh address has no route until you add one — see
`docs/plans/go-client-parity/00-status.md`, Slice 14).

`proof/10-tun.sh` is already green end to end across two namespaces, both
directions, so the remaining gap is specifically **the public mesh**: a DHT
resolve across nodes neither side is configured with, and a real link's MTU
behaviour.

Steps on a host with TUN privileges (root or `CAP_NET_ADMIN`, `iproute2`):

1. Config A: `IfName: rootstun0`, `Peers: ["tcp://bode.theender.net:42069"]`.
   Config B: `IfName: rootstun0`, no configured peer at all — B must find A over
   the DHT. Start both, then on B: `ip -6 route add <A's address>/128 dev
   rootstun0 && ping -6 <A's address>`.
2. Confirm the echo round-trips TUN → session → public mesh → session → TUN, and
   that **no node is configured with the other** — that is the part `proof/10-tun.sh`
   cannot show, since it configures both ends.
3. Check MTU on the real path (the device is 1280 by default, but a config can
   ask for more; session payloads must fit the link's `MAX_MESSAGE_SIZE` after
   framing). Slice 14's `supported_mtu` only clamps the *floor* — there is no
   upper clamp, because Go's `MaximumIfMTU` is a per-platform default we have no
   equivalent of. That asymmetry is deliberate and untested above 1280.
4. Record results here and flip this entry to DONE.

Why it wasn't done in-sandbox: `unshare -Urn` (where `TUNSETIFF` succeeds) has no
internet route for public peers.

## One node key, one link slot: a peering dialled both ways never settles

`LinkSet` (`src/link.rs`) keys its slots by **node public key**, so
`add` displaces the incumbent and the node drops the returned `AnyConn`,
closing that socket (`client/src/node.rs:324,357`). When two nodes each
dial the other, the two directions trade slots forever.

Measured 2026-09-25 in `proof/8-getpeers.sh` phase C (Go↔ours) and with a
two-of-ours pair: exactly one direction is up at any instant, the live
row changes identity between samples, and the Go node logs 15
`Connected`/`Disconnected` lines in ten seconds. `docs/protocol/21-admin.md`
and the AGENTS.md gotcha record what `getPeers` shows meanwhile.

Decide one of:

1. Multi-link per node key in the set (what ironwood does — a *map* of
   peers per key, `network/peers.go:47-62`), which means the router must
   stop assuming one link per peer; or
2. Refuse the newcomer the way Go refuses a duplicate (`core/link.go:
   544-548` closes a link whose key it already holds), so a crossed
   peering settles on the direction that won instead of flapping.

Either way `src/link.rs:303-332` and the two `node.rs` call sites are the
change, and `two_directions_to_one_peer_get_two_rows` in
`client/tests/peer_rows.rs` — which currently asserts one row `up` and
says so — is the test to flip.

## Why our `latency` and `cost` run far above a Go peer's

Slice 8 filled both fields from Go's formulas and a single pair of samples
disagreed by ~100×: on one loopback link our node reported
`cost: 106` / `latency: 53070000` ns while the Go node on the other end of
the *same* link reported `cost: 160` / `latency: 520000`.

Neither number is a measured RTT, which is why no single sample proves
either side wrong: `cost` is a lag EWMA seeded at `rtt*2` and eased 7/8
toward the stored timestamps (ironwood `network/router.go:221-228`,
`:431-441`) and `latency` is `srrt - srst` over timestamps that age
between queries (`src/core/debug.go:84-86`). What is still open is the
*magnitude* — the EWMA seed, the 50 ms node tick, and the lazy keepalive
that arms `srrt` are the three candidates.

Do: run two of ours and two Go nodes against the same fixture for a few
minutes and watch the two numbers converge or not (`proof/8-getpeers.sh`
phase A already prints both sides; it just needs repeating over time).
Record the answer in `docs/protocol/21-admin.md`, which currently states
the numbers and the open question.
