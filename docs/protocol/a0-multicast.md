# a0-multicast.md — the multicast advertisement

Multicast peer discovery is how two nodes that have never heard of each other find
each other on the same wire. It is the only part of the protocol that is not a
frame on a link: one hardcoded UDP group, one fixed 104-byte datagram, no
handshake, no acknowledgement, and a blake2b digest that is the entire membership
check. Everything else — the `tls://` listener, the `meta` handshake, the tree —
happens after a beacon has produced a dial URI.

Ours is split the way Go's is: `src/multicast.rs` owns the codec and the announce
state machine and owns no socket; `client/src/multicast.rs` owns the UDP6 socket,
the interface scan and the timers. The library answers `Command`s, the client
carries them out.

## The endpoint

```
[ff02::114]:9001
```

Hardcoded in Go's constructor (`multicast.go:71`) and never read from config, so
ours is a constant too (`GROUP`, `src/multicast.rs:23`; `GROUP_PORT`,
`client/src/multicast.rs:27`, pinned by `the_group_is_the_hardcoded_default`).

**Why link-local.** An IPv6 multicast address carries its own scope and `ff02::/16`
is scope 2, *link*. That is not a preference: a packet to it is never routed and
the kernel picks the outgoing interface from the socket's zone, which is why Go
sets `destAddr.Zone = iface.Name` on every beacon (`multicast.go:362`) and refuses
any arrival that was not link-local (`:402-404`). Three consequences follow. The
bind address is `::` and only the *port* comes from the group (`:101`). An
interface only qualifies if it has a **link-local unicast** address, filtered on
`IsLinkLocalUnicast` (`multicast.go:159-165`) and bound there (`:328`); ours reads
the same property out of `/proc/net/if_inet6` against both the kernel's scope column
and the address (`client/src/multicast.rs:623-661`), because the two can disagree.
And **the interface is the scope identifier for the whole exchange**: a beacon names
none, so the receiver learns which one by which socket it arrived on. Go reads that
from `IPV6_PKTINFO` (`:443-447`); ours uses one socket per listening interface, so
it is true by construction (`client/src/multicast.rs:42-59`). It is *our*
interface, not the sender's — reading it off the source address picks the one
interface a beacon can never arrive on, and that bug cost two nodes never finding
each other (`client/src/main.rs:370-375`).

## The beacon — 104 bytes

`advertisement.go:17-43`. All integers are big endian, in declaration order, and
the datagram is exactly the struct: no envelope, no padding.

| offset | length | field |
|--------|-------:|-------|
| 0 | 2 | `MajorVersion` — must equal 0 exactly |
| 2 | 2 | `MinorVersion` — must equal 5 exactly |
| 4 | 32 | `PublicKey` — the advertiser's full ed25519 node key |
| 36 | 2 | `Port` — the port its listener **actually bound**, not the one configured |
| 38 | 2 | hash length, `uint16(len(Hash))` |
| 40 | 64 | the membership hash, `blake2b.Size` |

With `PEER` = `00 01 02 … 1f` (the key `multicast_hash_over_peer_key` is over),
port 9001 and a 64-byte hash — the exact bytes
`advertisement_roundtrips_and_rejects` asserts offset by offset:

```
00000005000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f23290040abababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababab
```

Three quirks are load-bearing and are Go's, not ours' (`src/multicast.rs:60-97`).
The length field is `uint16(len(Hash))`, so a 65540-byte hash **truncates** to 4
rather than being refused — ours keeps the truncation deliberately, because the
length is what the receiver compares, not a guard. Bytes after the hash are ignored,
and a buffer shorter than `headerLen` (40) or `headerLen + dl` is refused with Go's
text "invalid multicast beacon"; a hash shorter than 64 bytes decodes cleanly and
fails only at the comparison.

## The membership hash

```
blake2b-512(key = this interface's Password, data = the advertised PublicKey)
```

One function, two call sites (`src/multicast.rs:110-129`). The advertiser computes
it over its **own** key once per interface scan (`multicast.go:214-222`, stored at
`:230`); the receiver recomputes it over the **advertised** key with its own
password and compares byte for byte (`:431-442`). A beacon is acted on only when
the receiver independently arrives at the same 64 bytes, which is the
group-membership check: anything not in the group cannot produce a datagram that
survives the compare, and so cannot redirect us to a dial.

Three details a reimplementation gets wrong. It is over the **key**, not over the
datagram, so the version fields, the port and the length are not covered. The key
is the group password, and **an empty password is the unkeyed hash** —
`blake2b.New512(nil)` — which anyone can compute, so with no password the beacon
proves nothing about membership beyond "this key hashes to this value". And
`bytes.Equal` wants equal lengths, not a prefix, so a truncated or padded hash is
refused.

What the hash does **not** do is authenticate the beacon: anyone on the link can
send one claiming any key, and what they cannot do without the password is get it
past the compare. What proves the key holder is there is the `tls://` link the dial
produces, whose URI carries `?key=<hex>` and whose `meta` handshake verifies the
signature ([20-handshake.md](20-handshake.md)). Go's own config comment draws the
line: `AllowedPublicKeys` "does not affect outgoing peerings, nor does it affect
link-local peers discovered via multicast" (`config.go:51`).

## What a received beacon must pass

Every step is a silent `continue` — Go logs nothing for any of them
(`multicast.go:409-441`), and neither may we, because most beacons on a busy
segment are somebody else's.

| # | test | guarded by |
|---|------|------------|
| 1 | decodes at all | `advertisement_roundtrips_and_rejects` |
| 2 | `MajorVersion == 0` | `multicast_ignores_minor_version_mismatch` |
| 3 | `MinorVersion == 5` | the same |
| 4 | `PublicKey` is not ours | `multicast_never_dials_itself` |
| 5 | the arrival's destination was link-local and equal to the group | ours cannot arrive otherwise — one socket per interface |
| 6 | the **receiving** interface is one we know and has `Listen` | `src/multicast.rs:428-431` |
| 7 | our password over their key equals their hash | `src/multicast.rs:434-436` |

Step 3 is exact on both fields, not a range: 0.4, 0.6 and 0.65535 are all refused
even with a correct hash. Ours is `PROTO_MAJOR`/`PROTO_MINOR`
(`src/multicast.rs:26-30`, from `core/version.go:26-29`). Go does **not**
deduplicate: every beacon that gets this far produces a `CallPeer` and the link
manager refuses the ones it already holds (`multicast.go:452`,
`core/link.go:236-244`). Ours returns a `Dial` per beacon and the client owns that
refusal, which `multicast_never_dials_itself` states by feeding the same beacon
twice and expecting two dials.

## The config row

`MulticastInterfaceConfig` (`config.go:60-67`), with `Regex` a string in the config
and a compiled `*regexp.Regexp` by the time the module sees it (`options.go:18-25`,
`cmd/yggdrasil/main.go:257-266`):

| field | type | meaning |
|-------|------|---------|
| `Regex` | string | matched against the **interface name** |
| `Beacon` | bool | advertise ourselves on it |
| `Listen` | bool | join the group and dial peers that beacon |
| `Port` | uint16 | asked-for listener port; **0** in the generated config |
| `Priority` | uint64 | the link priority in the listener URI; `uint8` upstream, widened for gobind (`config.go:65`) |
| `Password` | string | the blake2b key, at most 64 bytes |

**The first matching row wins.** Go skips a row with neither `Beacon` nor `Listen`
*before* it matches (`multicast.go:208-210`), then walks the rows and `break`s on
the first hit (`:205-233`), so a disabled row cannot shadow a later one that would
have matched — `a_disabled_row_does_not_shadow_a_later_match`. `MatchString` is a
**substring** search unless the pattern is anchored, which is why the operators'
patterns (`.*`, `.*eth.*`, `^en[0-9]`) get the real engine rather than a
hand-rolled subset (`interface_patterns_behave_like_go_regexp_matchstring`).

**Go's "first" is not deterministic and ours is.** `m.config._interfaces` is a
`map[MulticastInterface]struct{}` (`multicast.go:70`, `options.go:8`) and the
matching loop ranges that map, so when two rows match one interface name the winner
depends on Go's map order; the order `main.go` built the option slice in is lost.
Ours is a `Vec` and `config_for` takes the first match in configuration order
(`client/src/multicast.rs`), which is what the config comment promises
(`config.go:50`). For every non-overlapping config the two agree; where rows
overlap we are deterministic and Go is not.

## Beacon, bind and dial

The announce pass runs about once a second (`multicast.go:373`) and, per interface,
stops listeners whose interface vanished or whose link-local address moved
(`:262-301`), joins the group if `Listen` (`:312-315`), `break`s out of the address
loop if not `Beacon` (`:316-318`), creates the listener if there is none
(`:321-338`), and beacons only if the ramp allows (`:347-349`). The ramp starts at
zero, so the first beacon is due immediately, and grows a second per beacon to a
15-second ceiling (`:366-369`; `multicast_beacon_ramps_to_cap` asserts the exact
gap sequence 0, 1, 2 … 15, 15).

The ports are the part that is easy to get wrong. The listener URI asks for
`info.port`, which the generated config sets to **0** (`defaults_linux.go:16-18`),
so the kernel chooses; the beacon then advertises the port the listener *got*, read
off `linfo.listener.Addr()` (`multicast.go:350-355`), never the requested one. Ours
cannot read a port off a listener it does not own, so the tick is split: `announce`
emits a `Bind`, and the client reports the bound port back through `listener_up`
(`src/multicast.rs:386-390`), which means **no beacon goes out until a bind has
landed** (`multicast_skips_a_beacon_when_its_listener_is_not_up`). Getting that
ordering wrong is a silent deadlock — a node with a bound listener that never
beacons — and an earlier version here did exactly that
(`client/src/multicast.rs:166-174`).

The two URIs, ours byte for byte against Go's:

```
bind  tls://[fe80::1]:9001?password=roots+multicast+test&priority=3
dial  tls://[fe80::2%eth0]:4242?key=<hex>&password=roots+multicast+test&priority=3
```

Query keys are in `url.Values.Encode` order, which sorts them, so `password` before
`priority` and `key` first (`multicast.go:323-330`, `:425`, `:443-451`; ours
`listen_uri`, `dial_uri`, `query_escape`, `src/multicast.rs:453-507`;
`multicast_dial_uri_params`). Go overwrites the datagram's source port with the
advertised one before printing the address (`:425`), so the dial never uses it.

**The zone stays a name; a bind needs a number.** The dial URI keeps `%eth0` because
the name is the wire form and the peer reads it, and Go passes the name separately
to `ListenLocal` (`multicast.go:331`). Ours takes a URI for its bind, and the
kernel's socket API wants a scope *id*, so the numeric index goes into the bind URI
only — `tls://[fe80::1%2]:0?…` — and stays a local detail
(`client/src/main.rs:342-365`, `interface_index`,
`client/src/multicast.rs:685-688`). The dial is one-shot: Go's `CallPeer` does not
add a persistent peer and does not redial (`core/api.go:213-223`), and
`persistent: false` is ours for the same thing, so a peer that goes away is found
again by the next beacon rather than by a backoff loop.

## Deviations from Go

- **One socket per listening interface**, not one per node, because Tokio's
  `recv_from` cannot surface the `IPV6_PKTINFO` Go reads (`multicast.go:443-447`).
  `SO_REUSEADDR` is what lets them share port 9001 — Go chose it over
  `SO_REUSEPORT` because with `SO_REUSEPORT` two nodes run by different users
  inevitably failed with `EADDRINUSE` (`multicast_unix.go:20-24`). Ours also drains
  non-blocking, capped at 32 datagrams per socket per tick
  (`client/src/multicast.rs:350-391`), against Go's one blocking datagram per
  iteration of an unbounded loop: faster, never different, and it stops one chatty
  peer starving the other interfaces.
- **No announce jitter.** Go randomises its tick by up to about a second
  (`multicast.go:373`) so nodes on a segment do not beacon in lockstep; ours is a
  flat `TICK = 1s` (`client/src/multicast.rs:34`).
- **The interface pre-filter is weaker.** Go drops interfaces that are down, not
  running, not multicast-capable or point-to-point before the regex
  (`multicast.go:194-204`); we cannot read those flags without a netlink
  dependency, so our filter is the one that matters here — an interface with no
  link-local IPv6 address cannot carry a link-local beacon.
- **One link-local address per interface** (the most usable one), where Go keeps
  every address on the adapter and walks them until one binds
  (`multicast.go:306-371`). Our state is keyed by interface name, so two rows for
  one name would make each look stale to the other and rebind for ever; on an
  ordinary interface the two agree.
- **An uncompilable `Regex` is ignored, not fatal.** Go's `regexp.MustCompile`
  (`cmd/yggdrasil/main.go:259`) panics at startup, so `multicast.go` has no regex
  error path at all; ours logs and treats the row as matching nothing
  (`client/src/multicast.rs:581-589`).
- **A password needing escaping does not survive our own `link::parse_link_uri`**,
  which takes the value raw while Go percent-decodes with `u.Query().Get`
  (`src/multicast.rs:482-489`). The escape stays: the URI is the wire form and Go
  is the reader to match.
- **`getMulticastInterfaces` is built once a tick** rather than per request, and
  sorted in the handler (`client/src/multicast.rs:255-284`,
  `multicast/admin.go:43-45`). The rows are Go's struct exactly, including
  `Password` as a **bool** (`multicast/admin.go:33`) and `-` for "nothing
  listening" (`:38`).

## Provenance

| what | from |
|------|------|
| the 104-byte layout, field order, offsets, the version gate | Go source read field by field against `advertisement.go:9-43` and `multicast.go:413-420`. `advertisement_roundtrips_and_rejects` (`src/multicast.rs:570-638`) asserts each offset of the 104 bytes above, the `uint16` truncation, the short-buffer refusal and the trailing-byte tolerance — but it **mirrors Go's own test *shape*** (`advertisement_test.go`: `TestMulticastAdvertisementRoundTrip`, `TestMulticastAdvertisementRejectsTruncatedHash`), which is a weaker oracle than a running node |
| **there is no captured Go beacon** | an open gap, and the one `04-slices.md` promised as `GO_MULTICAST_BEACON` and never delivered. Nothing about multicast appears in `tests/go_vectors.rs`, and no Go node has ever sent one into this harness |
| the blake2b known answers | `multicast_hash_over_peer_key` (`src/multicast.rs:641-698`) pins the keyed, unkeyed, wrong-password and over-limit-password digests, and its comment says where they were checked: **CPython's `hashlib.blake2b`**, which has nothing to do with Go, cross-checked against the BLAKE2 reference vectors. A correct BLAKE2b implementation is the only thing it proves |
| the membership-hash call sites, `bytes.Equal` semantics, and the three compare failure shapes | Go source (`multicast.go:214-222`, `:431-442`) against our side, where `multicast_never_dials_itself` feeds a wrong-password beacon, a 32-byte hash and a 68-byte hash and expects all three refused — **our own bytes either way** |
| the endpoint, the ramp, the not-self and the exact-version rules | Go source, plus `the_group_is_the_hardcoded_default`, `multicast_beacon_ramps_to_cap`, `multicast_ignores_minor_version_mismatch`, `multicast_never_dials_itself`. The ramp is asserted as a gap sequence; **no test sends a datagram on a socket** |
| the two URI forms, the escaping and the key order | Go source (`multicast.go:323-330`, `:425`, `:443-451`) against `listen_uri`/`dial_uri`, pinned by `multicast_dial_uri_params`. Not a capture: ours and Go's formatter are compared by reading both |
| the config row and the first-match rule | Go source (`config.go:60-67`, `multicast.go:205-233`), pinned by `interface_patterns_behave_like_go_regexp_matchstring`, `a_disabled_row_does_not_shadow_a_later_match` and `an_oversize_password_skips_the_interface` — all **against our list**, and Go's map iteration makes the overlap case unobservable from its source at all |
| bind-before-beacon ordering | Go source read (`multicast.go:334` takes the port from a listener it already holds, `:350-355` reads it back) against our two-phase version; `multicast_skips_a_beacon_when_its_listener_is_not_up` and `multicast_stops_a_vanished_interfaces_listener` cover our half, and `proof/9-multicast.sh` measures the whole thing end to end — two nodes in a namespace with **no configured peers**, the only proof on this page that uses real sockets |
| the interface scan | Go's filter (`multicast.go:159-165`) against our `/proc/net/if_inet6` reader. `if_inet6_columns_are_read_in_the_right_places` parses a **captured host file** — real bytes, but the kernel's, not Go's — and `a_malformed_if_inet6_yields_no_interfaces` guards the parser against garbage |
| everything about the socket itself: `SO_REUSEADDR`, `JoinGroup`, the zone on send, the `IPV6_PKTINFO` read | Go source (`multicast_unix.go:15-33`, `multicast.go:314`, `:362`, `:443-447`) and ours. `rescan` and `send_beacon` have **no test at all**; they need a real interface, which is what `proof/9-multicast.sh` provides and `cargo test` deliberately does not |
