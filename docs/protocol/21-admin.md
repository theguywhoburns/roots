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

The eight commands `yggdrasil-go` 0.5.14 answers, and the struct that shapes
each reply (field order is Go's declaration order — see below):

| command | response |
|---|---|
| `list` | `{"list": [{"command","description","fields"}]}` |
| `getSelf` | `{"build_name","build_version","key","address","routing_entries","subnet"}` |
| `getPeers` | `{"peers": [{…17 fields…}]}` |
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
- The list is always sorted — `""`/`uptime`/`cost`, default first
  (`getpeers.go:68-101`): outbound before inbound, then by key, priority, cost,
  uptime.

`getTree`, `getPaths` and `getSessions` each sort their rows by hex public key
(`gettree.go:41-43`, `getpaths.go:41-43`, `getsessions.go:41-43`), which is why
their output is diffable.

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

From the live diff run on 2026-09-24. A Go node and ours, each with one dial it
made and one it accepted, `-json` so nothing is re-encoded by the client:

```
$ yggdrasilctl -endpoint=tcp://127.0.0.1:19001 -json getPeers   # Go node
{
  "peers": [
    {
      "remote": "tcp://127.0.0.1:34392",
      "up": true,
      "inbound": true,
      "address": "202:e649:a9b6:b13d:ada6:1dfa:efe:5420",
      "key": "2336cac929d84a4b3c40be20357bf243890adfbc2a2cb1354d56d6834a09887b",
      "port": 1,
      "priority": 0,
      "cost": 160,
      "bytes_recvd": 665,
      "bytes_sent": 644,
      "rate_recvd": 2,
      "uptime": 5.007847654,
      "latency": 700000
    }
  ]
}
```

```
$ yggdrasilctl -endpoint=tcp://127.0.0.1:19101 -json getPeers   # our node
{
  "peers": [
    {
      "remote": "tcp://127.0.0.1:12401",
      "up": true,
      "inbound": false,
      "address": "200:29b6:e4ea:895b:bf9:fe82:920a:939d",
      "key": "eb248d8abb527a0300beb6fab6311f2b261835bbaa91b074d347058ee329dce7",
      "port": 1,
      "priority": 0,
      "cost": 82,
      "bytes_recvd": 521,
      "bytes_sent": 479,
      "uptime": 4.973837903
    }
  ]
}
```

Same command, same shape, same order, same absence of `omitempty` fields. Two
differences are real: we do not fill `rate_recvd`/`rate_sent`/`latency`/
`last_error_time`, and we produce **no row at all** for the link Go dialled into
us (see *Deviations*).

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

- `client/tests/admin_loopback.rs` — six tests, TCP and `unix://` both
  exercised for real:
  `admin_unix_socket_matches_tcp`, `admin_body_field_order_matches_go`,
  `admin_keepalive_honours_second_request`, `admin_error_strings_match_go`,
  `admin_getpeers_reports_the_link_uri_not_the_operators`,
  `admin_argument_types_match_go`.
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
  the row sets and the `inbound` flag can be compared. This is the script that
  pins the deviation below.

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
- We emit seven `PeerEntry` fields, not sixteen: no `rate_recvd`, `rate_sent`,
  `latency`, `last_error_time`. The library measures no throughput and
  timestamps no link error, so there is nothing true to put in them; a zero
  would read as a measurement.
- `last_error` carries our own error text (`io: Connection refused (os error
  111)`) rather than Go's `dial tcp 127.0.0.1:1234: connect: connection
  refused`. `getPeers` is the only place Go's link errors are quoted.
- **A link we accept gets no `getPeers` row.** Our rows come from the
  configured peer list (`Links::entries`), and an accepted link is not in it.
  Go's rows come from `_links`, which an accepted link *is* inserted into
  (`link.go:536-565`) with its host rewritten to the peer's address
  (`link.go:519-525`). Pinned by `proof/7-admin-inbound.sh`.
- **`inbound` on a configured row can describe a different link.** Our
  `LinkSet` keys by node public key, so when a node we also dialled reaches us
  first, the accepted link replaces our dial's entry and its direction is
  reported against the dial's URI. Go keeps them as separate rows. Also pinned
  by that script, and Slice 8 owns the row set.
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
- `uptime` is written with a decimal point (`4.973837903`, `serde_json` always
  keeps one); Go writes `4` for a whole float.
- `list` offers eight commands while Go offers fourteen: `getTun` is Slice 14's,
  `getMulticastInterfaces` Slice 11's, `getNodeInfo` and the three
  `debug_remote*` Slice 9's. Everything those six would have answered is not yet
  answerable, so listing them would be a promise we break.
- Our `arguments` echo is a parsed `serde_json` map rather than raw bytes, so its
  keys come out sorted, while Go's `json.RawMessage` echo preserves the
  operator's order: `"arguments": {"uri":"x","interface":"y"}` echoes as
  `{"interface":"y","uri":"x"}`. Values and keys are identical; only the order
  inside that one object differs — and stock `yggdrasilctl` builds its arguments
  as a `map[string]string` and marshals it (`cmd/yggdrasilctl/main.go:102,121`),
  which Go already sorts, so the tool never sees the difference.
- Go reads one argument `getPeers` accepts and we ignore: `sort`. Its **type** is
  checked like any other (`GetPeersRequest.sort` above), its value is not: the
  default order is what we emit whatever it says. Slice 8 owns the other two.
