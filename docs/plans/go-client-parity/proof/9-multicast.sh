#!/bin/sh
# Multicast discovery, end to end over real sockets: two nodes, neither
# configured with the other, each finding the other by beacon.
#
# The claim is the one a config-driven node makes on a bare LAN. Nothing in
# either config names the other, and within a few seconds each `getPeers` shows a
# peer that could only have arrived over multicast. That exercises the whole path
# at once: the `ff02::114` group socket with SO_REUSEADDR, the beacon with its
# zone set, the blake2b membership check, the `tls://` listener the beacon's own
# port forced us to bind *first*, and the one-shot `CallPeer` dial.
#
# WHY A NETNS AND A VETH PAIR
#
# Link-local multicast needs a link that actually carries it. This host does not:
# `enp3s0` and `wlp0s20f3` are both on 192.168.0.0/24, and a datagram sent to
# `ff02::114` on one of them never reaches a socket joined on the other — measured
# with two plain UDP sockets and no Yggdrasil code in the path, so it is the
# network, not the client. A veth pair inside a namespace is a link we control,
# and multicast crosses it (measured the same way). So the proof builds its own
# segment rather than hoping for the host's.
#
# `unshare -Urn` supplies CAP_NET_ADMIN for the two `ip link add` calls. The
# nodes themselves need no privilege: the group socket, the `tls://` listeners,
# the links and the admin sockets are all unprivileged, and this script never
# asks the host for anything.
#
# `yggdrasilctl -endpoint` reads our admin socket because the admin protocol is
# Go's, so the Go client talks to us. No Go compiler is involved anywhere.

set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../../../.." && pwd)
BIN=$ROOT/target/debug/roots

A_IFACE=${A_IFACE:-mca0}
B_IFACE=${B_IFACE:-mcb0}
# Go's beacon ramp starts at a few seconds, so a peer is normally found on the
# first or second beacon. 60 s is generous for a slow first bind.
BUDGET=${BUDGET:-60}

if [ "$(id -u)" = 0 ] && [ -n "${IN_NETNS:-}" ]; then
  :
else
  # Re-exec inside a network namespace, unless already in one. `-r` maps us to
  # root inside it, which is what makes `ip link add` possible; nothing outside
  # the namespace is touched.
  if [ "$(ip link show "$A_IFACE" >/dev/null 2>&1; echo $?)" = 0 ]; then
    echo "FAIL: $A_IFACE already exists on the host; run this under unshare or pick" >&2
    echo "      other names with A_IFACE=/B_IFACE=" >&2
    exit 1
  fi
  echo "== re-running inside a network namespace"
  exec unshare -Urn --map-root-user env IN_NETNS=1 "$0" "$@"
fi

WORK=$(mktemp -d)
A_PID=
B_PID=
cleanup() {
  kill "$A_PID" "$B_PID" 2>/dev/null || true
  ip link del "$A_IFACE" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

echo "== building"
cargo build -q -p roots-client --manifest-path "$ROOT/Cargo.toml"

echo "== a two-ended segment: $A_IFACE <-> $B_IFACE"
ip link add "$A_IFACE" type veth peer name "$B_IFACE"
ip link set "$A_IFACE" up
ip link set "$B_IFACE" up
# A link-local address on each end. `nodad` because there is no router to
# advertise one; multicast does not need one.
ip -6 addr add fe80::a/64 dev "$A_IFACE" nodad
ip -6 addr add fe80::b/64 dev "$B_IFACE" nodad

# The generated default, narrowed four ways: one multicast interface, no
# configured peers, no configured interface peers, and an admin socket so the
# result is observable. Everything else is left exactly as `-genconf` prints it,
# so this keeps working when Go's config gains a key.
#
# Note the multicast row asks for port 0 by default, which is the point: the
# beacon has to advertise the port the kernel gave us, not one we picked.
write_conf() {
  _path=$1
  _iface=$2
  _admin=$3
  "$BIN" -genconf >"$WORK/gen.json"
  # Anchored on both ends, because Go's `MatchString` is a substring search
  # unless the pattern is anchored (`multicast.go:196-217`), so an unanchored
  # `mca0` would also match an interface called `mca01`.
  IFACE=$_iface perl -0pi -e 's/"Regex": "[^"]*"/"Regex": "^$ENV{IFACE}\$"/' "$WORK/gen.json"
  perl -0pi -e 's/"Peers": \[[^\]]*\]/"Peers": []/' "$WORK/gen.json"
  perl -0pi -e 's/"InterfacePeers": \{[^}]*\}/"InterfacePeers": {}/' "$WORK/gen.json"
  ADMIN=$_admin perl -0pi -e 's/"Listen": \[/"AdminListen": "$ENV{ADMIN}", "Listen": [/' "$WORK/gen.json"
  mv "$WORK/gen.json" "$_path"
}

A_ADMIN="unix://$WORK/a.sock"
B_ADMIN="unix://$WORK/b.sock"
write_conf "$WORK/a.conf" "$A_IFACE" "$A_ADMIN"
write_conf "$WORK/b.conf" "$B_IFACE" "$B_ADMIN"

# Nothing in either config names the other. Assert it on the file rather than
# trusting the perl above, because the whole claim rests on it.
for conf in a b; do
  if ! grep -q '"Peers": \[\]' "$WORK/$conf.conf"; then
    echo "FAIL: $conf.conf still has a configured peer" >&2
    cat "$WORK/$conf.conf" >&2
    exit 1
  fi
done

echo "== A on $A_IFACE, B on $B_IFACE, neither configured with the other"
"$BIN" -useconffile "$WORK/a.conf" >"$WORK/a.log" 2>&1 &
A_PID=$!
"$BIN" -useconffile "$WORK/b.conf" >"$WORK/b.log" 2>&1 &
B_PID=$!

wait_for() { # file, pattern, description
  _waited=0
  while [ "$_waited" -lt 30 ]; do
    if grep -q "$2" "$1" 2>/dev/null; then
      return 0
    fi
    sleep 1
    _waited=$((_waited + 1))
  done
  echo "FAIL: $3 (waited ${_waited}s)" >&2
  cat "$1" >&2
  exit 1
}

wait_for "$WORK/a.log" "admin socket listening" "A's admin socket never came up"
wait_for "$WORK/b.log" "admin socket listening" "B's admin socket never came up"
# Both must have a multicast listener bound before discovery can happen: the
# beacon advertises the port the listener got, so a node that dialled another
# before binding would prove nothing about the beacon.
wait_for "$WORK/a.log" "multicast: listening on $A_IFACE" \
  "A never bound a multicast listener on $A_IFACE"
wait_for "$WORK/b.log" "multicast: listening on $B_IFACE" \
  "B never bound a multicast listener on $B_IFACE"
echo "== both bound a multicast listener"

# What we are after: a row in `getPeers` that neither config could produce. Both
# nodes must see one — a beacon is symmetric, whoever finds a peer dials it once
# and the far end gets an inbound link.
wait_for_peer() { # admin socket, log file, node name
  _waited=0
  while [ "$_waited" -lt "$BUDGET" ]; do
    if yggdrasilctl -endpoint="$1" -json getPeers 2>/dev/null | grep -q '"up": true'; then
      echo "== $3 found a peer after ${_waited}s"
      return 0
    fi
    sleep 1
    _waited=$((_waited + 1))
  done
  echo "FAIL: $3 has no peer after ${BUDGET}s" >&2
  echo "-- $3 getPeers:" >&2
  yggdrasilctl -endpoint="$1" -json getPeers >&2 2>&1 || true
  cat "$2" >&2
  exit 1
}

wait_for_peer "$A_ADMIN" "$WORK/a.log" A
wait_for_peer "$B_ADMIN" "$WORK/b.log" B

echo "== A getPeers"
yggdrasilctl -endpoint="$A_ADMIN" -json getPeers
echo "== B getPeers"
yggdrasilctl -endpoint="$B_ADMIN" -json getPeers
echo "== A getMulticastInterfaces"
yggdrasilctl -endpoint="$A_ADMIN" -json getMulticastInterfaces
echo "== B getMulticastInterfaces"
yggdrasilctl -endpoint="$B_ADMIN" -json getMulticastInterfaces

# The peer must be at a **link-local** address. Nothing in either config names an
# address, and the only path that produces a `fe80::` peering is the beacon: the
# dial URI is built from the beacon's source address
# (`tls://[fe80::…%iface]:port`, `multicast.go:443-451`). So a `fe80::` remote is
# the claim, and it is checkable without depending on which link won.
#
# `inbound: true` is expected and is not a defect: both nodes dial each other at
# once, one link is refused as `already_configured` and dropped
# (`link.go:366-373`), and the survivor is the accepted one. Go behaves the same.
for pair in "A:$A_ADMIN" "B:$B_ADMIN"; do
  node=${pair%%:*}
  admin=${pair#*:}
  rows=$(yggdrasilctl -endpoint="$admin" -json getPeers)
  if ! echo "$rows" | grep -q '"remote": "tls://\[fe80::'; then
    echo "FAIL: $node's peer is not at a link-local address, so no beacon found it" >&2
    echo "$rows" >&2
    exit 1
  fi
  # The far end's address must be the one it holds on its own interface, which is
  # what proves the two veth ends really are talking to each other.
  case $node in
    A) want=fe80::b ;;
    B) want=fe80::a ;;
  esac
  if ! echo "$rows" | grep -q "$want"; then
    echo "FAIL: $node's peer is not $want, which is the other end's address" >&2
    echo "$rows" >&2
    exit 1
  fi
done

echo "PASS: two nodes with no configured peers found each other over multicast"
