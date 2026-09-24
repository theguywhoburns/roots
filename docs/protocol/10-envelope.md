# Link frame envelope

Every byte that crosses a Yggdrasil link after the handshake (`20-handshake.md`)
uses this envelope. It is the same over `tcp://`, `tls://`, `ws://`, `wss://`
and `quic://`: the transports carry a byte stream, the envelope gives it
message boundaries.

Source of truth: `reference/ironwood/network/peers.go` (write path
`sendPacket` :200-226, read path `handler` :243-266, dispatch
`_handlePacket` :268-300) and `reference/ironwood/network/wire.go:5-19`.
Every claim below was checked against bytes captured from the installed Go
0.5.14 binary — see *Proof*.

## Layout

```
uvarint(size) || type (1 byte) || payload (size - 1 bytes)
```

- `size` is an unsigned LEB128 integer (`binary.AppendUvarint` /
  `binary.ReadUvarint`), little-endian, 7 bits per byte, high bit set on every
  byte but the last.
- **`size` includes the type byte.** Go computes it as
  `bufSize := uint64(data.size() + 1)` and comments "The +1 is from 1 byte for
  the pType" (`peers.go:202-209`). A `size` of 1 means a type byte and no
  payload.
- The type byte selects the payload codec. Payload bytes are handed to that
  codec unchanged; the envelope does not escape or pad them.

## Limits

`size` above `peerMaxMessageSize` aborts the link with
`types.ErrOversizedMessage` (`peers.go:250-252`). yggdrasil-go sets that
option to `65535*2` = 131070 (`src/core/core.go:102`), which is our
`frame::MAX_MESSAGE_SIZE`. The check is on the *declared* size, before the
payload is read.

## Type table

Discriminants are the `iota` order in `wire.go:8-19`. Our `FrameType`
(`src/frame.rs:18-29`) mirrors it exactly.

| byte | Go constant            | our variant      | payload codec |
|-----:|------------------------|------------------|---------------|
| 0x00 | `wireDummy`            | `Dummy`          | none — ignored on read |
| 0x01 | `wireKeepAlive`        | `KeepAlive`      | none — ignored on read |
| 0x02 | `wireProtoSigReq`      | `SigReq`         | `tree.rs::SigReq` |
| 0x03 | `wireProtoSigRes`      | `SigRes`         | `tree.rs::SigRes` |
| 0x04 | `wireProtoAnnounce`    | `Announce`       | `tree.rs::Announce` |
| 0x05 | `wireProtoBloomFilter` | `BloomFilter`    | `bloom.rs` |
| 0x06 | `wireProtoPathLookup`  | `PathLookup`     | `pathfind.rs` |
| 0x07 | `wireProtoPathNotify`  | `PathNotify`     | `pathfind.rs` |
| 0x08 | `wireProtoPathBroken`  | `PathBroken`     | `pathfind.rs` |
| 0x09 | `wireTraffic`          | `Traffic`        | `traffic.rs` |

Any other byte is `types.ErrUnrecognizedMessage` in Go (the `default` arm of
`_handlePacket`), which drops the link. We do the same
(`FrameType::from_byte` → `Error::InvalidLength`).

A keepalive is therefore exactly two bytes on the wire: `01 01`. We write that
literal pair (`frame::keepalive_bytes`, `src/frame.rs:59-61`) and Go writes the
same, because a `KeepAlive` frame carries an empty payload.

## Captured bytes

Three frames Go pushed at us immediately after the handshake, as raw bytes off
the socket, with the envelope decoded.

### `SigReq` — `0c 02 02989088dbb5989884a701`

| offset | bytes | meaning |
|-------:|-------|---------|
| 0 | `0c` | uvarint size = 12 |
| 1 | `02` | type = `SigReq` |
| 2 | `02` | payload: `seq` uvarint = 2 |
| 3 | `989088dbb5989884a701` | payload: `nonce` uvarint (10 bytes, random) |

12 = 1 (type) + 11 (payload). Total frame 13 bytes.

### `BloomFilter` — `21 05 ffffffffffffffffffffffffffffffff00000000000000000000000000000000`

| offset | bytes | meaning |
|-------:|-------|---------|
| 0 | `21` | uvarint size = 33 |
| 1 | `05` | type = `BloomFilter` |
| 2 | 32 bytes | payload: the filter bitmap |

33 = 1 + 32. The bitmap is the first filter Go sends before any bloom
exchange has happened; see `bloom_vector_matches_go` for the codec that
explains it.

### `Announce` — `cd01 04 …` (207 bytes total)

| offset | bytes | meaning |
|-------:|-------|---------|
| 0 | `cd01` | uvarint size = 205 (two bytes: 0xcd, 0x01) |
| 2 | `04` | type = `Announce` |
| 3 | 32 bytes | payload: `key` |
| 35 | 32 bytes | payload: `parent` (equal to `key` — a root self-announce) |
| 67 | `01` | payload: `res.req.seq` uvarint = 1 |
| 68 | 10 bytes | payload: `res.req.nonce` uvarint |
| 78 | `00` | payload: `res.port` uvarint = 0 |
| 79 | 64 bytes | payload: `res.psig` |
| 143 | 64 bytes | payload: `sig` |

205 = 1 + 204, and 204 = 32 + 32 + (1 + 10 + 1 + 64) + 64; the two-byte size
prefix makes the frame 207 bytes on the wire. Because `key ==
parent` here, `res.psig` and `sig` are the same 64 bytes: one key signed the
same bytes both times. That is what a root's announce looks like, not a bug.

## Proof

- `tests/go_vectors.rs::go_link_frame_envelope_matches_captured` reads each
  captured frame with our decoder, asserts the declared size equals
  `type + payload`, then re-encodes with `frame::encode_frame` and requires
  byte equality with what Go sent. A size that excluded the type byte, or a
  uvarint written big-endian, fails it.
- The three frames came from a listener we dialed, so the write path is
  covered from both directions: Go wrote them, and `frame::encode_frame` — the
  same function the node's real send path calls (`src/link.rs:528`) —
  reproduces them.

## Deviations from Go

None known. Two behaviours worth stating because they are easy to get wrong:

- Go reads the length with `binary.ReadUvarint` from a `bufio.Reader`, so a
  frame is *one* `ReadUvarint` plus one `io.ReadFull` — it never inspects
  boundaries the transport happens to provide. A WS transport that frames one
  message per `flush` must still let a frame span messages.
- Go's `handler` returns on any error, dropping the link, rather than skipping
  a bad frame. So a malformed payload is a disconnect, not a log line.
