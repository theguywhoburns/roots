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

## `GroupPassword` is accepted and ignored, so it silently breaks sessions

A config key we parse, print in `-genconf`, and do nothing with.

**Measured 2026-10-03** with `unshare -Urn cargo run -q --example go_capture --
--frames --group`: the same capture twice, changing only Go's `GroupPassword`.
The mechanism is confirmed and the *direction* was wrong in the first version of
this note.

Go folds `sha256("ironwood/encrypted\x00" ‖ password)`
(`encrypted/crypto.go:149-157`) into the **session signature preimage** —
`encrypted/session.go:502` signs with it, `:550` checks with it. So:

- **The box is unaffected.** It is keyed by `DH(e2c(recipient), fromPub)` and
  nothing else, so the message opens to **144 plaintext bytes** — exactly what
  the field widths imply. Measured, with
  `SessionInit::unsealed_plaintext`.
- **The signature is what fails.** So a node with `GroupPassword` set *can* open
  a link, *does* send a session `init`, and we **cannot verify it**.
- Symmetrically, Go cannot verify our `init`, so no session ever forms in either
  direction, and **nothing is logged on either side** — the frames arrive and the
  counter moves.

The correction matters because the earlier note said the failure lands on Go's
side ("a node with `GroupPassword` set will not verify our `init`"). It lands on
**ours first**, and a diagnostic that only looks at whether the peer accepts our
bytes would find nothing wrong.

`SessionInit::encrypt_msg` / `decrypt_msg` (`src/session.rs`) take no preimage
parameter, so this needs a library change before it needs a config one.

Do: add a preimage parameter threaded from `Config::group_password` through
`session_send_kind` into `encrypt_msg`/`decrypt_msg`, then prove it with the
`--group` capture **with our side also set**, which currently cannot form a
session and is the test that would have to turn green.

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
