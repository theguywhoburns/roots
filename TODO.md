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

## Our `latency` sits about one node tick above Go's — cause not isolated

**Measured 2026-10-03** by `proof/11-metrics.sh`, which holds one loopback link
up and samples both ends every 5 s. Four runs, three of which agree:

| run | ours `latency` | Go `latency` | ratio |
|-----|---------------:|-------------:|------:|
| 25 s | 50 880 000 ns | 600 000 ns | 84× |
| 25 s | 53 570 000 ns | 450 000 ns | 119× |
| 30 s | 53 670 000 ns | 410 000 ns | 130× |
| 180 s | 12 310 000 ns | 91 950 000 ns | **0.13×** |

Three findings, and the first two are about the question rather than the
numbers:

**1. Neither number moves.** Frozen for the whole 180 s window. `latency` is
`srrt - srst`, and both are armed only by a **non-keepalive** receive (ironwood
`network/peers.go:161-175`); the only traffic on this link is our two-byte
keepalive. So both values are the seeds from establishing the link. **There is
nothing to converge**, which is why a single sample could never have settled
this.

**2. The seeds move a lot between runs, and the sign of the disagreement
flips.** The 180 s run has *Go* 7× higher. So "ours runs ~100× above" is one
sample of a distribution, not a property of either implementation.

**3. When it does not flip, ours is 50–54 ms and Go's is 0.4–0.6 ms** on the
same link — and 50 ms is exactly `DEFAULT_TICK` (`client/src/node.rs:23`).

What is *not* established: that the tick is the cause. The arithmetic is right —
`src/tree.rs`'s own test asserts the value is "the gap since the send, not a
fixed number", in a 19–60 ms band after a 20 ms sleep — so the 50 ms is real
elapsed time between our `write_all` returning and our read of the `SigRes`.
Both ends of that interval are already correct individually: `write_frame` does
`write_all` + `flush` before `sent_at` is stamped, and `handle_response` stamps
`srrt` inline in the read path. So the candidate is *scheduling* — the serve
slice parking somewhere between the two — and the way to settle it is to run the
same fixture at a different `Node::with_tick` and see whether the number follows.

Do: `Node::from_client` already takes a tick (`client/src/node.rs:227`), and the
CLI hardcodes `DEFAULT_TICK` (`client/src/main.rs:112`), so a `--tick` flag or a
config key is all that is needed to make this a two-run experiment instead of a
hypothesis. If the reported latency tracks the tick, it is the tick.

Record the answer in `docs/protocol/21-admin.md`, which currently states the
numbers and the open question.
