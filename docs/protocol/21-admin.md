# Admin socket

The local control socket: `yggdrasil`'s `AdminListen`, spoken to by
`yggdrasilctl` and by the `getInfo`-style tooling that grew up around it. It is
**not** a mesh wire format — nothing here crosses a link, and none of the
envelope rules in `10-envelope.md` apply. It gets a page anyway because it is
the one part of the protocol that an operator's fingers touch, and because
interoperability with stock `yggdrasilctl` is a product claim.

Source of truth: `reference/yggdrasil-go/src/admin/` — `admin.go` (envelope,
bind, loop), `getself.go`, `getpeers.go`, `gettree.go`, `getpaths.go`,
`getsessions.go`, `addpeer.go`, `removepeer.go` — plus the peer bookkeeping it
reads through `src/core/api.go:71-109`. Every shape below was captured from the
installed Go 0.5.14 binary and diffed against ours; see *Proof*.

Our implementation: `client/src/admin.rs` (transport, bind, framing, the eight
commands) and the reply contents from `client/src/node.rs` (`Node::snapshot`).

## Transport

`AdminListen` is a URL. Go parses it and switches on the lowercased scheme
(`admin.go:89-129`):

| `AdminListen` | what binds |
|---|---|
| `""` or `none` | nothing; `New` returns `(nil, nil)` and the node runs without a socket (`admin.go:84-87`) |
| `unix:///path/yggdrasil-admin.sock` | `net.Listen("unix", path)` (`:114`) |
| `tcp://127.0.0.1:9001` | `net.Listen("tcp", u.Host)` — note: **host**, not path (`:124`) |
| anything else, unparseable included | `net.Listen("tcp", <the whole string>)` (`:125-129`) |

The `unix://` case is the only one with ceremony (`admin.go:91-122`), and it is
worth reproducing exactly because a stale socket file is a routine operator
condition:

1. `os.Stat(path)` — if the file exists, `net.DialTimeout("unix", path, 2s)`.
2. A **successful** dial means something is serving it: fatal, `os.Exit(1)`
   (`:102-105`). A **timeout** counts as in use too (`:96-101`), so a wedged
   previous node is also fatal. Only a refused dial proceeds.
3. `os.Remove(path)`; if that fails, fatal (`:106-112`).
4. Bind, then `os.Chmod(path, 0660)` — skipped for an abstract socket, whose
   path starts with `@` and has no inode to permission (`:116-121`).

On success Go logs `"%s admin socket listening on %s"` with the network name
uppercased (`admin.go:134-136`), so `TCP admin socket listening on 127.0.0.1:9001`.

## Requests and responses are JSON values on a stream

There is no length prefix, no delimiter and no newline requirement. Go runs
`json.NewDecoder(conn)` over the socket and calls `Decode` once per request
(`admin.go:308`, `:322`); the decoder reads exactly one JSON value and stops
with the next byte still in its buffer. Replies are written the same way —
`json.NewEncoder(conn)` with `SetIndent("", "  ")` (`:311-312`), whose `Encode`
appends a `\n`. So consecutive replies are two indented objects separated by
one newline, and a client that wants to read them must parse a JSON stream, not
lines.

That single fact explains the strangest-looking behaviour of the real tool:
`yggdrasilctl` never sets `keepalive`, so `handleRequest` breaks after one
reply (`admin.go:354`) and closes the connection (`defer conn.Close()`, `:313`).
Every `yggdrasilctl` command is a fresh connection. Two requests written in one
`write()` are still two requests — the second is answered only if the first set
`keepalive`.

### Request envelope

```go
type AdminSocketRequest struct {
    Name      string          `json:"request"`
    Arguments json.RawMessage `json:"arguments,omitempty"`
    KeepAlive bool            `json:"keepalive,omitempty"`
}
```
(`admin.go:31-35`)

Go decodes in two steps: `Decode(&buf)` into a `json.RawMessage`, then
`json.Unmarshal(buf, &req)` (`:322-327`). The consequences are load-bearing and
all three were captured:

- `DisallowUnknownFields` (`:309`) **cannot reject an extra key**, because the
  first decode target is raw bytes and the struct decode that checks unknown
  fields is aimed at the envelope — whose three fields are all it needs. The
  handler then unmarshals `arguments` into its own struct **without** the
  disallow flag, so an unknown *argument* key is ignored too.
  `{"request":"list","bogus":1}` succeeds.
- `Arguments` is raw JSON and is echoed back **verbatim**:
  `{"request":"list","arguments":"notanobject"}` replies with
  `"arguments": "notanobject"` and still runs `list`, because `list` discards
  its input (`admin.go:139`, `func(_ json.RawMessage)`). A handler that does
  unmarshal answers with the Go JSON error instead — each one decodes
  `arguments` into its own request struct and returns that failure verbatim
  (`admin.go:162-169`).
- `req.Arguments` is preset to `{}` before decoding (`:321`), so a request that
  omits `arguments` is echoed with `"arguments": {}`.

### Response envelope

```go
type AdminSocketResponse struct {
    Status   string             `json:"status"`
    Error    string             `json:"error,omitempty"`
    Request  AdminSocketRequest `json:"request"`
    Response json.RawMessage    `json:"response"`
}
```
(`admin.go:37-42`)

`status` is `"success"` or `"error"`; `error` only on the failure path; `request`
is the decoded request struct; `response` has **no** `omitempty`, so a failed
request carries `"response": null`. The handler's return value is
`json.Marshal`ed into `Response` (`:341`) and the encoder re-indents it.

`resp.Request = req` happens *after* the struct decode (`:329`), which is why
the echo has three shapes rather than one:

| how the request failed | echoed `request` |
|---|---|
| no JSON value at all (`not json at all`) | `{"request": ""}` — `arguments` absent, because `req` was never touched and its zero `RawMessage` is `nil` |
| value not an object (`[]`, `"just a string"`) | `{"request": ""}` — same reason, via `failed to unmarshal request` |
| object with an empty/absent name (`{"request":""}`) | `{"request": "", "arguments": {}}` — `:321` preset survived |

## The protocol errors

Four messages belong to the framing layer, and a client may match on them
verbatim (`admin.go:324-336`):

| input | `error` |
|---|---|
| `not json at all` | `failed to find request` |
| `[]`, `"just a string"` | `failed to unmarshal request` |
| `{"request":""}`, `{"keepalive":true}` | `no request specified` |
| `{"request":"NoSuchThing"}` | `unknown action 'nosuchthing', try 'list' for help` |

The unknown-action message carries the **lowercased** name (`reqname`, `:335`)
while the echo keeps the operator's case (`"request": "NoSuchThing"`). Names are
looked up lowercased (`:334`), so `LIST`, `list` and `List` are the same
command. Anything a handler itself returns is passed through unchanged, which is
how Go's link-layer wording reaches the socket: `link schema unknown`,
`invalid password supplied`, `priority value is invalid`,
`peer is already configured`, `peer is not configured`.

An error does **not** end the connection. The break test is `if !req.KeepAlive`
(`:354`) and it is reached on both paths, so a `keepalive: true` request that
fails is followed by a second answer on the same socket.

### Arguments are decoded before the command runs

Each handler unmarshals `arguments` into its own request struct and returns that
failure verbatim if it does not fit (`admin.go:162-169`), so a wrongly-typed
argument is refused *before* the command touches anything — an
`addPeer {"uri":123}` never reaches the link layer. Two message shapes, both
from Go's `json.UnmarshalTypeError`:

| sent | `error` |
|---|---|
| `"arguments": "notanobject"` on `getSelf` | `json: cannot unmarshal string into Go value of type admin.GetSelfRequest` |
| `"arguments": 5` on `getTree` | `json: cannot unmarshal number into Go value of type admin.GetTreeRequest` |
| `{"sort":123}` on `getPeers` | `json: cannot unmarshal number into Go struct field GetPeersRequest.sort of type string` |
| `{"uri":123}` on `addPeer` | `json: cannot unmarshal number into Go struct field AddPeerRequest.uri of type string` |
| `{"uri":"tcp://…","interface":5}` on `addPeer` | `json: cannot unmarshal number into Go struct field AddPeerRequest.interface of type string` |

Note the package prefix on the first form and its absence on the second, and
that the field is named by its **JSON tag**. The kinds are Go's words: `string`,
`number` (int and float alike), `bool`, `array`, `object`.

Three things Go accepts:

- `"arguments": null` — unmarshalling `null` into a struct is a no-op, and the
  echo keeps `null` rather than the `{}` preset.
- an unknown key, with any value: the handler structs are plain
  `json.Unmarshal`ed, without `DisallowUnknownFields`.
- `list` with a non-object, because its handler discards its input
  (`admin.go:139`).

## Commands

`list` is registered by `New` itself (`admin.go:139-152`) and reports every
other handler with its description and argument names, sorted by command name
(`:148-150`). The entries are `{"command","description"}` plus `"fields"` when
the handler takes arguments (`admin.go:50-57`, `fields,omitempty`). Command
names in the output are **lowercase** because they are the map keys, and the map
keys are lowercased at registration (`:61-72`).

The eight commands we answer — Go answers fourteen, and `list` is where that gap
is visible — with the struct that shapes each reply (field order is Go's
declaration order — see below):

| command | response |
|---|---|
| `list` | `{"list": [{"command","description","fields"}]}` |
| `getSelf` | `{"build_name","build_version","key","address","routing_entries","subnet"}` |
| `getPeers` | `{"peers": [{…16 fields…}]}` |
| `getTree` | `{"tree": [{"address","key","parent","sequence"}]}` |
| `getPaths` | `{"paths": [{"address","key","path","sequence"}]}` |
| `getSessions` | `{"sessions": [{"address","key","bytes_recvd","bytes_sent","uptime"}]}` |
| `addPeer` | `{}` (takes `uri`, optional `interface`) |
| `removePeer` | `{}` (takes `uri`, optional `interface`) |

`getPeers` is the one with real content (`getpeers.go:21-38`):

```go
type PeerEntry struct {
    URI           string        `json:"remote,omitempty"`
    Up            bool          `json:"up"`
    Inbound       bool          `json:"inbound"`
    IPAddress     string        `json:"address,omitempty"`
    PublicKey     string        `json:"key"`
    Port          uint64        `json:"port"`
    Priority      uint64        `json:"priority"`
    Cost          uint64        `json:"cost"`
    RXBytes       DataUnit      `json:"bytes_recvd,omitempty"`
    TXBytes       DataUnit      `json:"bytes_sent,omitempty"`
    RXRate        DataUnit      `json:"rate_recvd,omitempty"`
    TXRate        DataUnit      `json:"rate_sent,omitempty"`
    Uptime        float64       `json:"uptime,omitempty"`
    Latency       time.Duration `json:"latency,omitempty"`
    LastErrorTime time.Duration `json:"last_error_time,omitempty"`
    LastError     string        `json:"last_error,omitempty"`
}
```

- `DataUnit` is a `uint64` count of **bytes** (`admin.go:362`); its `String()`
  method only exists for table mode, so `-json` shows raw bytes.
- `Latency` and `LastErrorTime` are `time.Duration`, which marshals as an
  integer **number of nanoseconds**.
- `Uptime` is `Seconds()` — a float, and `encoding/json` writes a whole float
  without a decimal point (`"uptime": 4`), which `serde_json` never does.
- Every row comes from one map iteration in `core.GetPeers`
  (`api.go:79-106`), so a link the router has not adopted yet has no
  `port`/`priority`/`cost`/`latency` to report: Go's `conns[conn]` lookup simply
  misses (`api.go:96-103`).
- `remote` is the **link** URI, not the operator's: `peerinfo.URI = info.uri`
  (`api.go:83`) and `info.uri` came from `urlForLinkInfo`, which blanks the query
  (`link.go:766-769`). A `?password=` therefore never comes back out over the
  admin socket. For a link the node *accepted*, Go rewrites the host to the
  peer's socket address first, so inbound rows read
  `tcp://127.0.0.1:34392` (`link.go:519-525`).
- The list is always sorted, and the `sort` argument picks the comparator: see
  *Which rows, and in what order*.

`getTree`, `getPaths` and `getSessions` each sort their rows by hex public key
(`gettree.go:41-43`, `getpaths.go:41-43`, `getsessions.go:41-43`), which is why
their output is diffable.

## Which rows, and in what order

### Rows

`Core.GetPeers` walks `links._links` (`api.go:79-105`), and that map is keyed by
`linkInfo{uri, sintf}` (`link.go:43-44`) — by the **peering**, not by the node.
So a row exists for every peering the node has an opinion about:

- A configured dial puts its row in the map **before it connects**
  (`link.go:249-257`), with `_conn == nil`, and the row stays there while the
  dial goroutine backs off and retries. That is why a peering to a port with
  nothing behind it is listed with `up: false`, a `last_error` and a
  `last_error_time` — and why the only way to make that row leave is
  `removePeer`, which cancels the context so the goroutine returns and the
  `defer` at `link.go:307-311` deletes it. `remove` does not stop there: it also
  calls `conn.Close()` on the live connection (`link.go:433-438`), whatever the
  "The peer is not disconnected immediately" comment at `api.go:203` says. Two Go
  nodes measure it — after `removePeer uri=<the dial that is up>`, both sides
  answer `{"peers": []}` and the dialling node logs `Disconnected outbound …
  use of closed network connection`. Passing the URI of a live **inbound** row
  instead makes Go panic: that row's `link` is built without a context
  (`link.go:536-543`), so `state.cancel()` at `:434` dereferences nil and the
  node dies.
- An accepted link gets a row at accept time (`link.go:534-565`), named by the
  socket it came from, and the `defer` at `link.go:567-571` deletes it as soon
  as the link dies. So **a dead inbound row vanishes and a dead dial row stays**:
  the asymmetry is in the two `defer`s, not in the admin layer.
- Two directions to one node are two rows, because the two URIs differ.

Then one join: `conns` maps `net.Conn` → ironwood's `DebugPeerInfo`
(`api.go:73-77`) and the lookup is made with the row's own connection
(`api.go:96-103`). A row with no connection looks up `nil`, misses, and reports
no key, no port, no priority, no cost, no latency and no byte counters. The
counters themselves come from the same `if` (`api.go:86-95`).

Ours is `Node::snapshot` (`client/src/node.rs:171-224`), and it has one more
indirection to make the same statement: a row is identified by
`(uri, sintf)` and a live link by its node key, and neither determines the
other — so each row carries the `LinkId` of the link it last saw, and
**everything the link set and the router have to say about the row is gated on
one `links.stats(id)` lookup** (`node.rs:190-198`), which is our `conns[conn]`.
The gate matters most for a peering that has been replaced: the row survives,
and reads `up: false` with its counters cleared rather than reporting the live
link's key in the second time.

### Order

`getpeers.go:70-133` selects a comparator on `strings.ToLower(req.SortBy)` —
`"uptime"`, `"cost"`, or `sortByDefault` for anything else, including a
garbage value — and runs `slices.SortStableFunc`. Stable, so rows a comparator
calls equal keep the order the map gave them... except that map iteration is
randomised, so in Go that tiebreak is not reproducible; ours comes from the
configured peer list and is.

The comparators are worth reading, because two of their keys are **floats run
through `int()`**:

```go
if d := a.Uptime - b.Uptime; d != 0 {
    return int(d)
}
```

`d != 0` is a float test, so a 0.4-second gap is "different", and `int(0.4)` is
then **0** — the comparator reports equality and short-circuits, never reaching
the priority and cost keys below it. Two uptimes within a second of each other
are therefore "equal" for that pair of keys but not transitively so: 1.0 ties
1.4, 1.4 ties 2.5, and 1.0 loses to 2.5.

The consequence is why `client/src/admin.rs` has its own `sort_stable` insertion
sort rather than `slice::sort_by`: Rust's sort **verifies** the comparator and
panics with `user-provided comparison function does not correctly implement a
total order`. Measured 2026-09-25 with uptimes spread evenly over one second
(the realistic case for a node whose peers all came up in the same restart):
never a panic at 200 peers, always one at 300, data-dependent at 400. Go cannot
panic there — `slices.SortStableFunc` does block-swapping merges and never asks
whether its comparator is consistent — so matching Go's order means sorting
without the assumption. An insertion sort is stable, calls the comparator only
on adjacent pairs, and is at worst a few hundred rows squared, which is a node
with more peerings than anyone runs.

Three tests pin the resulting order: `getpeers_sort_modes_match_go_three_for_three`
(one assertion per mode, against orders worked out of the Go source by hand),
`getpeers_priority_ranks_after_the_key_and_before_the_cost` and
`getpeers_uptime_is_the_last_tiebreak_in_the_other_two_modes` for the key
sequence, and `getpeers_sorts_where_go_s_truncation_breaks_a_total_order` for
the non-transitive case itself. Note that a fixture for these has to keep any
group of sub-second-apart uptimes at least a second away from every other row,
or the test data is inconsistent with itself.


## Field order is part of the bytes

`encoding/json` writes struct fields in **declaration order**. The admin socket
is human-facing and tool-facing, and the order is visible in every diff, so
matching it is part of interoperability rather than polish.

`serde_json`'s `Map` is a `BTreeMap` (`preserve_order` off), so anything that
round-trips through a `Value` comes out alphabetically. Our responses are
therefore `#[derive(Serialize)]` structs in Go's order, and the envelope's
`response` field holds `enum Body` with a hand-written delegating `Serialize`
(`client/src/admin.rs:119`). `Box<dyn Serialize>` is not available for this:
`dyn Serialize` is not object-safe (`Serialize::collect_seq` takes `Self` by
value → E0038). `serde_json::RawValue` is rejected too — pre-indented bytes
would either double-indent or leave a body unindented, since
`Formatter::write_raw_fragment` is a no-op default that assumes an
already-formatted payload.

## Captured bytes

From the live diff run on 2026-09-25 (`proof/8-getpeers.sh`, phase A). Our node
dials Go's listener and both nodes also carry a peering to a port nothing
listens on, so each answer has one live row and one dead one — ours first, in
the order the two rows sort, Go's in the same shape:

```
$ yggdrasilctl -endpoint=tcp://127.0.0.1:19101 -json getPeers   # our node
{
  "peers": [
    {
      "remote": "tcp://127.0.0.1:12499",
      "up": false,
      "inbound": false,
      "key": "",
      "port": 0,
      "priority": 0,
      "cost": 0,
      "last_error_time": 6927829840,
      "last_error": "io: Connection refused (os error 111)"
    },
    {
      "remote": "tcp://127.0.0.1:12401",
      "up": true,
      "inbound": false,
      "address": "202:5f8:4834:1b24:e633:d0b4:78d6:b8ff",
      "key": "3f40f6f97c9b633985e970e528e0119ddb1394b619306e8b900bd66c39c732e9",
      "port": 1,
      "priority": 0,
      "cost": 106,
      "bytes_recvd": 521,
      "bytes_sent": 478,
      "rate_sent": 2,
      "uptime": 13.089762657,
      "latency": 53070000
    }
  ]
}
```

```
$ yggdrasilctl -endpoint=tcp://127.0.0.1:19001 -json getPeers   # Go node
{
  "peers": [
    {
      "remote": "tcp://127.0.0.1:12499",
      "up": false,
      "inbound": false,
      "key": "",
      "port": 0,
      "priority": 0,
      "cost": 0,
      "last_error_time": 1012060618,
      "last_error": "dial tcp 127.0.0.1:12499: connect: connection refused"
    },
    {
      "remote": "tcp://127.0.0.1:54622",
      "up": true,
      "inbound": true,
      "address": "202:eadc:bac1:72ae:6d26:7b22:e70b:f133",
      "key": "22a468a7d1aa325b309ba31e81d98b6f03e6856d4ae01cf36c703c8d723fa2de",
      "port": 1,
      "priority": 0,
      "cost": 160,
      "bytes_recvd": 652,
      "bytes_sent": 644,
      "rate_recvd": 2,
      "uptime": 7.069074106,
      "latency": 520000
    }
  ]
}
```

Read them as the same peering from both ends — taken in sequence though they were
(Go's six samples, then ours, a second apart), so uptimes and byte totals are
different instants and only the *shape* is a pair. Go's second row is the link
our node dialled: same key, `inbound: true` there and `false` here, and named by
Go's accepted socket (`127.0.0.1:54622`) rather than by the URI anyone
configured. Four field-level facts survive the diff:

- The dead row is identical in shape on both sides — `key`, `port`, `priority`,
  `cost` printed as zeroes, no `address`, no counters, no `uptime`, and the
  error pair present. That is the `conns[conn]` miss, not a guess.
- `rate_sent: 2` here and `rate_recvd: 2` there are the same two bytes a second
  (our keepalive), seen from the sending end and the receiving end. Each side
  reports the *other* rate as absent, because it is zero. See *Deviations*.
- `uptime` is a float both ways; Go happens to print `7.069074106` with a
  fraction, and writes a whole number without one (`"uptime": 4`), which
  `serde_json` never does.
- `cost` and `latency` are the two fields no single sample proves anything
  about. Both come from the router's own `SigReq` timing: `cost` is the lag EWMA
  in whole milliseconds (`_getCost`, `router.go:221-228`), seeded at `rtt * 2`
  by the first reply and then eased `7/8` towards each new one
  (`router.go:431-441`), and `latency` is the gap between two *stored*
  timestamps (`debug.go:84-86`), so it keeps ageing between requests. Go read
  160 and 0.52 ms, we read 106 and 53 ms, on a loopback where the socket
  round trip is a fraction of a millisecond. The formulas are the same and the
  magnitudes are the same order; why our sample sits two orders above Go's is a
  driver-timing question, recorded on the slice list rather than answered here.

`getSelf` for the same pair, to show the six fields in order:

```
$ yggdrasilctl -endpoint=tcp://127.0.0.1:19001 -json getSelf
{
  "build_name": "yggdrasil",
  "build_version": "0.5.14",
  "key": "80be7a1f…",
  "address": "200:fe83:bc0:6339:5392:7499:a43:eb76",
  "routing_entries": 2,
  "subnet": "300:fe83:bc0:6339::/64"
}
```

## Proof

- `client/tests/admin_loopback.rs` — seven tests, TCP and `unix://` both
  exercised for real:
  `admin_unix_socket_matches_tcp`, `admin_body_field_order_matches_go`,
  `admin_keepalive_honours_second_request`, `admin_error_strings_match_go`,
  `admin_getpeers_reports_the_link_uri_not_the_operators`,
  `admin_argument_types_match_go`, and
  `admin_getpeers_reports_every_field_go_does` — the last one polls a live
  peering until every one of the sixteen keys has appeared and then bounds each
  measured field against its own total, so a field that is *present but never
  filled* fails rather than being skipped.
- `client/tests/peer_rows.rs` — three tests over two in-process nodes, for the
  row *set* rather than the bytes: `an_accepted_link_gets_its_own_row` (the
  listener direction is a row, named by its socket, carrying the operator's
  `?priority=`), `a_dead_dial_row_stays_and_reports_down`, and
  `two_directions_to_one_peer_get_two_rows`.
- `client/src/admin.rs` — six unit tests for the order, because a live pair has
  two rows and two rows sort without exercising a tiebreak. See *Order* for what
  each one pins.
- `docs/plans/go-client-parity/proof/7-admin.sh` — two Go nodes and two of ours
  in one network namespace, `list getSelf getPeers getTree getPaths getSessions`
  diffed Go-vs-ours and tcp-vs-unix, then the same commands through stock
  `yggdrasilctl` in **table** mode (the harder test: it decodes into Go's own
  structs, so a wrong field name prints an empty cell).
  `unshare -Un --map-root-user sh docs/plans/go-client-parity/proof/7-admin.sh`
- `docs/plans/go-client-parity/proof/7-admin-raw.sh` — the 22 framing edge cases
  (`{"request":""}`, `not json at all`, `[]`, `"just a string"`,
  `{"request":"list","bogus":1}`, `{"request":"list","arguments":"notanobject"}`,
  the five argument-decode messages, `"arguments": null`, two values in one
  write, the five link error strings, the `?password=` round trip) diffed byte
  for byte. This is the script that found the password leak in `getPeers`, and
  the one that found the argument-decode gap.
- `docs/plans/go-client-parity/proof/7-admin-inbound.sh` — one dial each way, so
  the row sets and the `inbound` flag could be compared. It is the shape
  `8-getpeers.sh` grew from, and it is superseded by it: read that one instead.
- `docs/plans/go-client-parity/proof/8-getpeers.sh` — the Slice 8 proof, in five
  phases: our dial seen from both ends with its rates, uptime and latency; Go's
  dial seen from our side, which is the row we used not to have; a dead dial
  kept on both sides with its error pair; `sort=cost`/`sort=uptime` on our node
  and Go's, checked for the same row set and for an order the mode's own key
  explains; and a second pair of nodes whose configs dial each other, which is
  where the flapping deviation above was measured rather than reasoned about.
  `unshare -Un --map-root-user sh docs/plans/go-client-parity/proof/8-getpeers.sh`

There is deliberately **no** `tests/go_admin_vectors.rs`. A hex vector of our own
socket proves nothing, and the live Go node is the only honest oracle for text
like `link schema unknown` and `peer is already configured`, which come from Go's
error strings rather than from any byte layout.

Re-run requirements: the installed `yggdrasil`/`yggdrasilctl` 0.5.14, and a
network namespace — a Go node `panic`s at startup if it may not create a TUN
(`cmd/yggdrasil/main.go:282`), and `lo` starts down in a fresh netns. Never a Go
compiler, and never in CI. `-endpoint` is the flag that selects the socket;
there is no `-admin_socket`, and with no `-endpoint` `yggdrasilctl` reads the
platform default **config file** instead.

## Deviations from Go

- `build_name` is `"roots"` and `build_version` is our crate version. Claiming
  `yggdrasil` would be a lie about which implementation answered.
- `last_error` carries our own error text (`io: Connection refused (os error
  111)`) rather than Go's `dial tcp 127.0.0.1:1234: connect: connection
  refused`. `getPeers` is the only place Go's link errors are quoted, and the
  only ones we word differently are the ones the OS hands us; the link-layer
  refusals (`link schema unknown`, `invalid password supplied`,
  `peer is already configured`, `peer is not configured`,
  `priority value is invalid`) are Go's verbatim.
- **A peering dialled both ways: two rows, one per direction, and no flap.**
  This was a deviation and is not any more, so it is worth recording what the
  answer looks like rather than deleting the note. Go keys its link map by URI
  (`link.go:43-44`) and ironwood keeps several links per node key
  (`peers.go:47-62`), so both directions are up at once and each gets a row.
  Ours now does too: `LinkSet` is **one entry per link** with `LinkId` as the
  addressing unit, so a second link to a key we already hold is a second entry
  rather than a displacement. Measured 2026-09-30 with two nodes whose configs
  dial each other, against a live Go 0.5.14 node on the other end
  (`proof/8-getpeers.sh` phase C): both sides answer with **exactly two live
  rows**, one per direction, the same two rows in every one-second sample, and
  Go's log carries two `Connected` lines and no `Disconnected` churn.
  `client/tests/peer_rows.rs`'s `two_directions_to_one_peer_get_two_rows` pins
  our side and parks the redial with `?maxbackoff=600s` long enough to read the
  rows.
  The old measurement, for contrast: on 2026-09-25 exactly one direction was up
  at any instant, which direction flipped between samples, the accepted row left
  the list when its link died and came back with a new socket address, and Go's
  log alternated `Connected inbound` / `Disconnected outbound` every two seconds.
  So the row *set* had matched Go's while the row *liveness* had not.
  **A proof script that encoded the bug as the expected answer** is what kept
  this looking like a deviation for two days: phase C asserted "no answer may
  report two live rows" and "Go must log the pair going up and down", and both
  passed. It now asserts the Go behaviour instead.
- **A quiet link reports `rate_recvd: 0` here and nothing at all in Go.** Both
  answers are true: Go's peer monitor only arms its keepalive in reply to a
  *non*-keepalive frame (ironwood `peers.go:161-175`), so a converged idle
  peering has Go send nothing while we send two bytes a second, and each side's
  receive rate is therefore the other's send rate. Measured 2026-09-25 over
  twenty one-second samples: our `bytes_sent` +2/s and `bytes_recvd` frozen,
  Go's row the exact mirror. The counters and the one-second window agree
  (`_updateAverages`, `link.go:106-129`); the traffic behind them does not.
- `getSessions` answers `{address,key}` per session and omits `bytes_recvd`,
  `bytes_sent` and `uptime`: `SessionState` counts no per-session bytes and
  records no start time, so a zero would read as a measurement.
- `getTree` lists what our router has learned. Go seeds its tree with its own
  key (`parent` = self, `sequence` 1), so a Go node with no peers at all answers
  one row where ours answers none, and `getSelf`'s `routing_entries` is 1 against
  our 0. Both count the same map — `len(router.infos)`
  (`reference/ironwood/network/debug.go:64`, ours `views.rs:29-31`) — so the gap
  is one entry, not a different measure. With a link up the two agree, row for
  row and in the same key order.
- `list` offers fourteen commands and so does Go. Slice 9 added `getNodeInfo` and
  the three `debug_remote*` (`core/api.go:239-259`), Slice 11 added
  `getMulticastInterfaces` (`multicast/admin.go:56`) and Slice 14 added `getTun`
  (`tun/admin.go:31`).
- `getTun`'s two optional fields are not decoration. Go's handler returns as soon
  as `!t.isEnabled` (`tun/admin.go:30-32`) having set only `Enabled`, so `Name`
  and `MTU` keep their `omitempty` (`tun/admin.go:11-15`) and a node with no TUN
  answers `{"enabled": false}` — **not** `{"enabled": false, "name": "", "mtu":
  0}`. Printing the zeroes would make it indistinguishable from an interface
  called the empty string with an MTU of zero, and a `serde_json::Value` cannot
  tell an absent key from a zero, so the test asserts on the response *text*.
  Go reads `isEnabled`, `Name()` and `MTU()` off the adapter and never asks the
  kernel (`tun/admin.go:27-33`), so neither do we: a device that exists and a
  device that carries traffic are different questions, and only the first is
  what this command claims.
- Our `arguments` echo is a parsed `serde_json` map rather than raw bytes, so its
  keys come out sorted, while Go's `json.RawMessage` echo preserves the
  operator's order: `"arguments": {"uri":"x","interface":"y"}` echoes as
  `{"interface":"y","uri":"x"}`. Values and keys are identical; only the order
  inside that one object differs — and stock `yggdrasilctl` builds its arguments
  as a `map[string]string` and marshals it (`cmd/yggdrasilctl/main.go:102,121`),
  which Go already sorts, so the tool never sees the difference.
