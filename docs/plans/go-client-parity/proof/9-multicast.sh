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

# ---------------------------------------------------------------------------
# The beacon's own bytes, from Go.
#
# Everything above proves the two directions *work* — our beacon reached a Go
# node and our listener acted on a Go beacon — but neither side of that shows a
# single Go byte, so the advertisement codec has never been checked against Go's.
# It was round-tripped through our own encoder instead, which cannot catch a
# layout that is self-consistent and wrong.
#
# The arrangement is deliberate. A Go node beacons on the veth with
# `Listen: false`, and one of our nodes is the only listener: Go binds
# `[::]:9001` whenever *either* flag is set (`multicast.go:96-101`), so a Go
# listener would compete for the same datagrams and which socket got one would be
# a kernel decision. With `Listen: false` there is exactly one socket on the
# group, and `ROOTS_DBG_MULTICAST` prints what arrived.
# ---------------------------------------------------------------------------
echo
echo "== Go's beacon bytes: a Go node beaconing, our node the only listener"
GOA_IFACE=${GOA_IFACE:-mcg0}
GOB_IFACE=${GOB_IFACE:-mcb1}
GOB_ADMIN="unix://$WORK/gob.sock"

# A third veth pair, so this does not disturb the pair under test: the beacon
# has to arrive on an interface this node's own multicast row does not match, or
# a peer that happens to match would be a coincidence rather than the beacon.
ip link add "$GOA_IFACE" type veth peer name "$GOB_IFACE"
ip link set "$GOA_IFACE" up
ip link set "$GOB_IFACE" up
ip -6 addr add fe80::c/64 dev "$GOA_IFACE" nodad
ip -6 addr add fe80::d/64 dev "$GOB_IFACE" nodad

GOB_KEY=$("$BIN" -genconf | grep -o '"PrivateKey": *"[0-9a-f]*"' | grep -o '[0-9a-f]\{128\}')
GOB_PUB=$(printf '%s' "$GOB_KEY" | cut -c65-128)
# Beacon on, listen off. `Beacon: true` alone is what keeps Go from binding the
# group port, and it is also the configuration an operator writes on the machine
# that should advertise but not dial.
cat >"$WORK/gob.conf" <<EOF
{
  "PrivateKey": "$GOB_KEY",
  "AdminListen": "$GOB_ADMIN",
  "Listen": [], "Peers": [], "InterfacePeers": {},
  "MulticastInterfaces": [
    { "Regex": "^$GOA_IFACE\$", "Beacon": true, "Listen": false, "Password": "" }
  ],
  "AllowedPublicKeys": [], "GroupPassword": "",
  "IfName": "auto", "IfMTU": 65535,
  "NodeInfoPrivacy": false, "NodeInfo": null
}
EOF

# Our node, on the other end, beaconing on the veth too so it has a reason to open
# its group socket. Discovery is 104 bytes (Slice 10's constant) and the beacon
# has to clear Go's own ramp, which starts in seconds.
cat >"$WORK/oursb.conf" <<EOF
{
  "PrivateKey": "$("$BIN" -genconf | grep -o '"PrivateKey": *"[0-9a-f]*"' | grep -o '[0-9a-f]\{128\}')",
  "AdminListen": "unix://$WORK/oursb.sock",
  "Listen": [], "Peers": [], "InterfacePeers": {},
  "MulticastInterfaces": [
    { "Regex": "^$GOB_IFACE\$", "Beacon": true, "Listen": true, "Password": "" }
  ],
  "AllowedPublicKeys": [], "GroupPassword": "",
  "IfName": "auto", "IfMTU": 65535,
  "NodeInfoPrivacy": false, "NodeInfo": null
}
EOF

grep -q '"Listen": \[\]' "$WORK/gob.conf" || { echo "FAIL: the Go node has no configured peer" >&2; exit 1; }
grep -q '"Listen": \[\]' "$WORK/oursb.conf" || { echo "FAIL: our node has no configured peer" >&2; exit 1; }

ROOTS_DBG_MULTICAST=1 "$BIN" -useconffile "$WORK/oursb.conf" >"$WORK/oursb.log" 2>&1 &
B_PID=$!
yggdrasil -useconffile "$WORK/gob.conf" >"$WORK/gob.log" 2>&1 &
GOB_PID=$!
cleanup2() { kill "$B_PID" "$GOB_PID" 2>/dev/null || true; }

# Go's beacon ramp starts in seconds, so give it room and stop as soon as one
# arrives. Sixty is generous; the point is not to wait, it is not to miss it.
beacon=""
_waited=0
while [ "$_waited" -lt 60 ]; do
    # The trace line is `multicast: N bytes in on <zone> from <addr>: <hex> [...]`,
    # and the zone is a link-local address, so it contains colons and no field can
    # be split on them. Match only as far as the length and take the hex off the
    # end.
    beacon=$(grep -o 'multicast: [0-9]* bytes in on .*' "$WORK/oursb.log" | tail -1 || true)
    [ -n "$beacon" ] && break
    sleep 1
    _waited=$((_waited + 1))
done
cleanup2

if [ -z "$beacon" ]; then
    echo "FAIL: no beacon from the Go node arrived in 60s" >&2
    cat "$WORK/gob.log" >&2
    cat "$WORK/oursb.log" >&2
    exit 1
fi
echo "   $beacon"

# The length is the first thing worth checking and the cheapest: our codec's
# advertisement is a fixed 104 bytes (`src/multicast.rs`, and its
# `advertisement_roundtrips_and_rejects` test), so anything else is a field count
# or a width we have wrong, and no amount of reading the rest would help.
beacon_len=$(echo "$beacon" | sed 's/^multicast: \([0-9]*\) bytes.*/\1/')
if [ "$beacon_len" != "104" ]; then
    echo "FAIL: Go's beacon is $beacon_len bytes and ours is 104" >&2
    echo "   $beacon" >&2
    exit 1
fi
echo "   104 bytes, as our codec says"

# And the parts that have to agree for a beacon to be *accepted*: the key it
# advertises is the node's own, and the magic and version are what our decoder
# checks before anything else. `ACTED ON` versus `ignored` is the real assertion —
# a beacon of the right length that our decoder refuses is a layout mismatch, and
# the length alone would have passed.
if ! grep -q 'ACTED ON' "$WORK/oursb.log"; then
    echo "FAIL: a 104-byte beacon arrived and our decoder ignored it" >&2
    grep 'bytes in on' "$WORK/oursb.log" | tail -3 >&2
    exit 1
fi
echo "   and our decoder acted on it"

# The hex is the last 104 characters of the line, because the address before it
# is a link-local one and therefore also full of colons.
beacon_hex=$(echo "$beacon" | grep -o '[0-9a-f]\{104\}')
# The advertised key and the node's own key are printed **together, from this
# run**, because each run generates a fresh key: pasting the hex from one run and
# the pubkey from another produces a vector that fails on the key assertion for a
# reason that has nothing to do with the codec.
#
# Everything below slices by *offset in bytes* through one `awk`, rather than
# `cut`-ing a hex string by character and hoping. The layout is fixed
# (`src/multicast.rs`): 4 bytes of version, 32 of key, 2 of port, 2 of hash
# length, then the hash.
gob_pub=$(grep -o 'Your public key is [0-9a-f]*' "$WORK/gob.log" | head -1 | awk '{print $NF}')
gob_port=$(grep -o 'TLS listener started on .*' "$WORK/gob.log" | head -1 | sed 's/.*://')
if [ -z "$gob_pub" ] || [ -z "$gob_port" ]; then
    echo "FAIL: could not read the Go node's key and port from its log" >&2
    cat "$WORK/gob.log" >&2
    exit 1
fi
read -r beacon_key beacon_port_hex <<EOF
$(printf '%s' "$beacon_hex" | awk '{
    # awk substr is 1-based and this is hex, so byte n starts at char 2n-1. The
    # layout is 4 bytes of version, 32 of key, 2 of port, 2 of hash length.
    printf "%s %s\n", substr($0, 9, 64), substr($0, 73, 4)
}')
EOF
if [ "$beacon_key" != "$gob_pub" ]; then
    echo "FAIL: the beacon advertises $beacon_key but the node is $gob_pub" >&2
    exit 1
fi
beacon_port=$(printf '%d' "0x$beacon_port_hex" 2>/dev/null || echo "")
if [ "$beacon_port" != "$gob_port" ]; then
    echo "FAIL: the beacon carries port '$beacon_port' but the listener bound '$gob_port'" >&2
    exit 1
fi
echo "   it advertises that node's own key, and the port it actually bound ($gob_port)"

echo
echo "== paste into tests/go_vectors.rs"
echo "GO_BEACON: $beacon_hex"
echo "GO_BEACON_PUBKEY: $gob_pub"
echo "GO_BEACON_PORT: $gob_port"
echo
echo "PASS: Go's beacon is 104 bytes and our decoder accepts it"
