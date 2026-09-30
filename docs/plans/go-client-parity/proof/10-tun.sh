#!/bin/sh
# TUN bridging, end to end over a real kernel interface: two nodes, each with a
# TUN and a mesh address, and an ICMP echo that crosses the mesh twice.
#
# The claim is the one an operator makes when they set `IfName` in a config: a
# packet the kernel routed to the interface came out of the other node's
# interface, and the reply came back. It exercises the whole path at once — the
# `0200::/7` filter in `Device::wants`, the session inbox the node loop drains,
# `Router::send_or_resolve` finding or holding a path, the TUN write, and
# `getTun` reporting the device the kernel actually gave us.
#
# WHY TWO NESTED NAMESPACES
#
# The nodes need `/dev/net/tun` and `TUNSETIFF`, which need `CAP_NET_ADMIN`. They
# also need to be *separate*: two TUNs in one namespace can be routed to each
# other by the kernel, so a ping could succeed without the mesh carrying a single
# byte of it. A false green. So each node gets its own network namespace, joined
# by a veth pair, and each namespace's TUN has exactly one way out.
#
# `ip netns add` needs a writable `/run/netns` and a mount namespace this host
# will not give a `unshare -Urn` (measured: "Cannot create namespace file
# /var/run/netns/...: Permission denied"). Moving a veth end into a *child's*
# netns by pid works and needs neither, so that is what this uses: a child
# `unshare -n`'s into its own netns, the parent hands it a veth end, and
# `nsenter -t <pid> -n` is the window into it. No capability outside the
# namespaces is asked for, and no Go compiler is involved.
#
# The nodes peer over a plain TCP link across the veth, named in each config, so
# the mesh path being proved is the link and the session — not multicast
# discovery, which Slice 11's own proof already covers.

set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../../../.." && pwd)
BIN=$ROOT/target/debug/roots

A_IFACE=${A_IFACE:-tuna0}
B_IFACE=${B_IFACE:-tunb0}
# The veth pair between the two namespaces. Distinct from the TUN names: this is
# a carrier, the other two are the devices under test.
A_VETH=${A_VETH:-va0}
B_VETH=${B_VETH:-vb0}
BUDGET=${BUDGET:-60}

if [ "$(id -u)" = 0 ] && [ -n "${IN_NETNS:-}" ]; then
  :
else
  if ip link show "$A_IFACE" >/dev/null 2>&1 || ip link show "$B_IFACE" >/dev/null 2>&1; then
    echo "FAIL: $A_IFACE or $B_IFACE already exists on the host; run this under unshare or" >&2
    echo "      pick other names with A_IFACE=/B_IFACE=" >&2
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
  ip link del "$A_VETH" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

echo "== building"
cargo build -q -p roots-client --manifest-path "$ROOT/Cargo.toml"

# Each node is a child in its own netns, waiting for the veth end the parent is
# about to hand it and then running the real binary. `nsenter` needs the pid of
# the process *in* the new netns, which is the `unshare` process: it does not fork.
#
# `lo` comes up first because both admin sockets and the TCP link's loopback
# fallback need it, and a fresh netns has it down (the third of AGENTS.md's traps).
#
# The child brings the veth up but does not address it: the parent has to know both
# ends to give them *different* addresses, and giving both ends the same one means
# each node dials itself and gets "connection refused" from its own listener. That
# is a silent false negative, and the multicast proof never caught it because a
# multicast group is addressed to a group, not to a host.
start_node() { # tag, veth name, config
  unshare -n sh -c '
    ip link set lo up
    while ! ip link show dev "$1" >/dev/null 2>&1; do sleep 0.1; done
    ip link set "$1" up
    exec "$2" -useconffile "$3"
  ' sh "$2" "$BIN" "$3" >"$WORK/$1.log" 2>&1 &
  echo $!
}

A_ADMIN="unix://$WORK/a.sock"
B_ADMIN="unix://$WORK/b.sock"

# The generated default, narrowed five ways: a named TUN, a TCP listener, one
# TCP peer, no multicast, and an admin socket. Everything else is left exactly as
# `-genconf` prints it, so this keeps working when Go's config gains a key.
#
# The listener is explicit because `-genconf` leaves `Listen` empty and we spawn
# no listener for an empty list — the only thing that made the multicast proof
# work is that discovery advertises a port and the node binds it. A configured
# peer has no such help, so the port goes in the config.
write_conf() { # path, ifname, admin, own listen port, peer uri
  _path=$1
  _ifname=$2
  _admin=$3
  _port=$4
  _peer=$5
  "$BIN" -genconf >"$_path"
  IFNAME=$_ifname perl -0pi -e 's/"IfName": "[^"]*"/"IfName": "$ENV{IFNAME}"/' "$_path"
  PORT=$_port perl -0pi -e 's/"Listen": \[\]/"Listen": ["tcp:\/\/[::]:$ENV{PORT}"]/' "$_path"
  PEER=$_peer perl -0pi -e 's/"Peers": \[\]/"Peers": ["$ENV{PEER}"]/' "$_path"
  # No multicast: this proof is about the TUN, and a discovery path between the
  # two nodes would make it impossible to say which link carried the packet.
  perl -0pi -e 's/"MulticastInterfaces": \[[^\]]*\]/"MulticastInterfaces": []/' "$_path"
  ADMIN=$_admin perl -0pi -e 's/"Listen": \[/"AdminListen": "$ENV{ADMIN}", "Listen": [/' "$_path"
}

# A peering over a link-local address, which is what a real config on a LAN uses.
# The port is fixed because the peer URI has to be in the config before the other
# node starts.
#
# Two things about the URI, both of which cost a run to find out:
#
# - The zone names the **local** interface the packet leaves from, not the far
#   end's. `fe80::b%va0` means "reach fe80::b out of va0", so A names A's own veth
#   and B names B's. Crossing them fails with `getaddrinfo: Name or service not
#   known`, because the interface named does not exist in the namespace doing the
#   lookup.
# - The address is the **far** end's, and the two ends have different addresses.
#   A URI naming our own address on our own interface is a self-dial, which fails
#   with `connection refused` from our own listener and looks exactly like a mesh
#   that does not work.
A_PORT=${A_PORT:-42071}
B_PORT=${B_PORT:-42072}
A_LL=${A_LL:-fe80::a}
B_LL=${B_LL:-fe80::b}
write_conf "$WORK/a.conf" "$A_IFACE" "$A_ADMIN" "$A_PORT" "tcp://[$B_LL%${A_VETH}]:$B_PORT"
write_conf "$WORK/b.conf" "$B_IFACE" "$B_ADMIN" "$B_PORT" "tcp://[$A_LL%${B_VETH}]:$A_PORT"

# Assert the three things the claim rests on, on the files rather than on the
# perl above having worked.
for conf in a b; do
  grep -q '"MulticastInterfaces": \[\]' "$WORK/$conf.conf" \
    || { echo "FAIL: $conf.conf still has a multicast interface" >&2; exit 1; }
  grep -q "\"IfName\": \"$A_IFACE\"\|\"IfName\": \"$B_IFACE\"" "$WORK/$conf.conf" \
    || { echo "FAIL: $conf.conf has no IfName" >&2; exit 1; }
  grep -q '"AdminListen": "unix://' "$WORK/$conf.conf" \
    || { echo "FAIL: $conf.conf has no admin socket" >&2; exit 1; }
done

echo "== A in its own netns with a $A_IFACE, B in another with a $B_IFACE"
A_PID=$(start_node a "$A_VETH" "$WORK/a.conf")
B_PID=$(start_node b "$B_VETH" "$WORK/b.conf")

# The veth pair is created here and one end moved into each child. Both ends are
# visible in this namespace, so the pair is made here even though neither end
# stays. The link-local addresses are set by the parent because it is the only
# process that can see both ends, and it has to keep them different.
ip link add "$A_VETH" type veth peer name "$B_VETH"
ip link set "$A_VETH" netns "$A_PID"
ip link set "$B_VETH" netns "$B_PID"
nsenter -t "$A_PID" -n ip -6 addr add "$A_LL/64" dev "$A_VETH" nodad
nsenter -t "$B_PID" -n ip -6 addr add "$B_LL/64" dev "$B_VETH" nodad

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

# A node that could not open its device must say so and stop: `main.rs` exits on
# a TUN failure, so a log with the line is also proof the device really is up.
wait_for "$WORK/a.log" "TUN $A_IFACE up with" "A never brought its TUN up"
wait_for "$WORK/b.log" "TUN $B_IFACE up with" "B never brought its TUN up"
echo "== both devices are up"

A_ADDR=$("$BIN" -useconffile "$WORK/a.conf" -address)
B_ADDR=$("$BIN" -useconffile "$WORK/b.conf" -address)
echo "== A is $A_ADDR, B is $B_ADDR"

# `getTun` has to report the device the *kernel* gave us, not the one we asked
# for, and an MTU inside the range `getSupportedMTU` clamps to.
for node in A B; do
  if [ "$node" = A ]; then
    admin=$A_ADMIN
  else
    admin=$B_ADMIN
  fi
  tun=$(yggdrasilctl -endpoint="$admin" -json getTun 2>/dev/null) || {
    echo "FAIL: $node's getTun did not answer" >&2
    exit 1
  }
  echo "$tun" | grep -q '"enabled": true' || {
    echo "FAIL: $node reports no TUN: $tun" >&2
    exit 1
  }
  echo "== $node getTun: $tun"
done

# The link must be up before a ping means anything: a session needs a peer.
#
# No `cut -d:` on a `unix://` URL — the scheme's own colons are what gets split
# on, and it fails quietly as "the admin socket did not answer".
wait_for_peer() { # label, admin socket, log file
  _label=$1
  _admin=$2
  _log=$3
  _waited=0
  while [ "$_waited" -lt "$BUDGET" ]; do
    if yggdrasilctl -endpoint="$_admin" -json getPeers 2>/dev/null | grep -q '"up": true'; then
      echo "== $_label has a peer after ${_waited}s"
      return 0
    fi
    sleep 1
    _waited=$((_waited + 1))
  done
  echo "FAIL: $_label has no peer after ${BUDGET}s" >&2
  yggdrasilctl -endpoint="$_admin" -json getPeers >&2 2>&1 || true
  # Both logs, always. A node that never started has nothing in *its own* peer
  # table to explain, so dumping only `$_log` hid the node that was missing.
  for other in "$WORK/a.log" "$WORK/b.log"; do
    echo "-- $other:" >&2
    cat "$other" >&2 || true
  done
  exit 1
}

wait_for_peer A "$A_ADMIN" "$WORK/a.log"
wait_for_peer B "$B_ADMIN" "$WORK/b.log"

# The claim. The kernel in A's namespace pings B's mesh address; the packet can
# only leave through A's TUN, and it can only arrive through B's TUN.
#
# BOTH routes are installed before the first ping, and that is not tidiness. The
# device is addressed `/128`, so a mesh address has no route at all until somebody
# adds one: a mesh address is derived from a key, not advertised, so there is no
# prefix to install a route from. Without the reverse route the far end's kernel
# receives the echo request, **cannot route its own reply**, and drops it — so
# the sender sees 100% loss while the receiver's log shows the request arriving
# and being written to the device perfectly. That is the shape of a broken mesh
# and it is indistinguishable from one until you check the other namespace.
#
# Go installs routes for a *subnet* over its own netlink code (`tun/tun.go:148-190`);
# for a node address the operator adds the route, and doing it here is what makes
# "the kernel routed it at us" part of the claim rather than an assumption.
echo "== routes: each kernel needs to be able to reach the other's mesh address"
nsenter -t "$A_PID" -n ip -6 route add "$B_ADDR" dev "$A_IFACE"
nsenter -t "$B_PID" -n ip -6 route add "$A_ADDR" dev "$B_IFACE"

echo "== A's kernel pings B's mesh address over the TUN"
if ! nsenter -t "$A_PID" -n ping -6 -c 3 -W 5 -I "$A_IFACE" "$B_ADDR"; then
  echo "FAIL: the ping did not come back" >&2
  echo "-- A:" >&2
  cat "$WORK/a.log" >&2
  echo "-- B:" >&2
  cat "$WORK/b.log" >&2
  exit 1
fi

# And the reverse, because a bridge that only works one way is half a bridge and
# the session bookkeeping is not symmetric until it is exercised both ways.
echo "== B's kernel pings A's mesh address over the TUN"
if ! nsenter -t "$B_PID" -n ping -6 -c 3 -W 5 -I "$B_IFACE" "$A_ADDR"; then
  echo "FAIL: the reverse ping did not come back" >&2
  echo "-- A:" >&2
  cat "$WORK/a.log" >&2
  echo "-- B:" >&2
  cat "$WORK/b.log" >&2
  exit 1
fi

echo "== A getPeers"
yggdrasilctl -endpoint="$A_ADMIN" -json getPeers
echo "== B getPeers"
yggdrasilctl -endpoint="$B_ADMIN" -json getPeers

echo "PASS: an ICMP echo crossed two real TUN interfaces in both directions"
