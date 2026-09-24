# Product: go-client-parity

## Problem

Three people, three complaints, all about the same gap.

**The builder.** "I want to ship something that reaches nodes already on the
mesh — a sync tool, a chat relay, a sensor collector. Today the only working
implementation is a Go program, so I either run that as a sidecar and write
pipes to it, or I port the protocol myself out of someone else's source.
Neither is what I signed up for."

**The reader.** "I need to know what the protocol *actually* is. Which bytes
go out first, what a node is agreeing to when it accepts a session, why mine
gets dropped four seconds later. The spec is folklore, so I keep reading Go."

**The operator.** "I already run the node I trust. If a second implementation
shows up, I want to put it next to the first, point the same questions at both,
and get the same answers — or find out exactly where they diverge."

What is missing is not a demo that connects to one peer. It is a library whose
job is finished, plus a description of the protocol accurate enough to
reconstruct a node from, plus a client ordinary enough to be compared against
the one people already run.

## Success metric

**Go-guarded wire formats: 12 of 22 today, 22 of 22 by the end.**

A message kind counts as guarded when a checked-in byte string came from the Go
implementation and a test fails if our bytes differ. The enumeration and the
per-kind status are in `02-architecture.md` ("Wire-format coverage"); the 22 are
every message this library encodes or decodes, plus the two multicast formats
once they exist. Documentation is the other half of the same number: one
`docs/protocol/` page per family, and a page whose byte layout is not asserted by
a test does not count as written.

The earlier draft of this gate said "8 kinds", which undercounted: it counted
only the `*_matches_go` test names and missed the Go-captured session `init`,
the `e2c` map, the frame envelope and the keepalive bytes. Corrected at Gate 2.

Two supporting counts, same rule — verified automatically, not attested in a
doc:

- Mesh shapes proven end to end without a Go process anywhere in the path: 1
  today (two nodes, loopback), 3 required.
- Operator questions the client answers the way the trusted node answers them:
  **12 of 15 named commands** today, from the Go admin inventory in
  `02-architecture.md`. Missing: `getMulticastInterfaces`, `getTun`, `lookups`.
  Several of the 12 pass by name while diverging in content (`getPeers` ignores
  Go's three sort modes and hardcodes `up`/`inbound`), so that number needs a
  content check before it can be trusted — Gate 3 work.

## Announcement — the blog post before the feature

Today we're releasing roots-rs, a Rust implementation of the Yggdrasil mesh that
you can read as well as run. Every message the protocol uses is written out with
a worked example, and each example is checked against the original
implementation, so the documentation cannot quietly rot when the wire format
moves under you. If you build something that needs to reach a node on the mesh,
you can do it from inside your own program now instead of supervising a separate
process. There is also a plain client that answers the same questions the node
you already run answers, which means the two can be pointed at the same mesh and
compared rather than argued about. Start with the protocol guide and skip the
source archaeology.

## Screens

No UI. The client is a command-line program plus a local admin socket, and its
whole purpose is to be interchangeable with the tool operators already use.

## Out of scope for this feature

- Anything requiring a Go toolchain on the verification machine (arrives later,
  as a scheduled job rather than a per-push gate).
- Publishing a crate or a release channel.
- Being a better network stack than the one people run today. Parity first.
