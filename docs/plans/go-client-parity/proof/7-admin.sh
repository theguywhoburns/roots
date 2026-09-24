#!/bin/sh
# Slice 7 proof: does the real, installed `yggdrasilctl` talk to our node the
# same way it talks to a Go node?
#
#   unshare -Un --map-root-user sh docs/plans/go-client-parity/proof/7-admin.sh
#
# The namespace is not decoration: a Go node panics at startup unless it may
# create a TUN (`cmd/yggdrasil/main.go:282`), and `lo` starts *down* in a fresh
# netns, so both are handled here. Nothing on the host is touched, and the host's
# own service node is not the thing being asked about — `-endpoint` is what
# selects the socket (there is no `-admin_socket`, and with no `-endpoint`
# yggdrasilctl reads the platform default config file instead).
#
# All four nodes hold the same private key, the throwaway fixture already
# committed in client/src/config.rs, so their getSelf answers are comparable byte
# for byte. Needs the installed yggdrasil/yggdrasilctl 0.5.14; never a Go
# compiler, and never in CI.
set -e

ROOT=$(cd "$(dirname "$0")/../../../.." && pwd)
cd "$ROOT"
cargo build -q -p roots-client
ip link set lo up

KEY=$(grep -o '"PrivateKey": "[0-9a-f]*"' client/src/config.rs | head -1 | grep -o '[0-9a-f]\{128\}')
if [ -z "$KEY" ]; then
    echo "no 128-hex fixture key in client/src/config.rs" >&2
    exit 1
fi

CONF=$(mktemp -d)
PIDS=""
trap 'kill $PIDS 2>/dev/null; rm -rf "$CONF"' EXIT INT TERM

# $1 = AdminListen, $2 = IfName (only a Go node reads it), $3 = file
conf() {
    cat >"$3" <<EOF
{
  "PrivateKey": "$KEY",
  "AdminListen": "$1",
  "Listen": [],
  "Peers": [],
  "InterfacePeers": {},
  "MulticastInterfaces": [],
  "AllowedPublicKeys": [],
  "GroupPassword": "",
  "IfName": "$2",
  "IfMTU": 65535,
  "NodeInfoPrivacy": false,
  "NodeInfo": null
}
EOF
}

conf "tcp://127.0.0.1:19001" rootsgo-t "$CONF/go-tcp.conf"
conf "unix://$CONF/go.sock" rootsgo-u "$CONF/go-unix.conf"
conf "tcp://127.0.0.1:19101" roots-t "$CONF/ours-tcp.conf"
conf "unix://$CONF/ours.sock" roots-u "$CONF/ours-unix.conf"

yggdrasil -useconffile "$CONF/go-tcp.conf" >"$CONF/go-tcp.log" 2>&1 &
PIDS="$PIDS $!"
yggdrasil -useconffile "$CONF/go-unix.conf" >"$CONF/go-unix.log" 2>&1 &
PIDS="$PIDS $!"
target/debug/roots -useconffile "$CONF/ours-tcp.conf" >"$CONF/ours-tcp.log" 2>&1 &
PIDS="$PIDS $!"
target/debug/roots -useconffile "$CONF/ours-unix.conf" >"$CONF/ours-unix.log" 2>&1 &
PIDS="$PIDS $!"
sleep 5

# One peer that cannot connect, on every endpoint, so getPeers has a row to
# render and a last_error to compare.
for ep in tcp://127.0.0.1:19001 tcp://127.0.0.1:19101 \
    "unix://$CONF/go.sock" "unix://$CONF/ours.sock"; do
    yggdrasilctl -endpoint="$ep" -json addPeer uri=tcp://127.0.0.1:1234 \
        >"$CONF/addpeer.out" 2>&1 || true
done
sleep 3

for cmd in list getSelf getPeers getTree getPaths getSessions; do
    yggdrasilctl -endpoint=tcp://127.0.0.1:19001 -json $cmd >"$CONF/go-$cmd" 2>&1 || true
    yggdrasilctl -endpoint=tcp://127.0.0.1:19101 -json $cmd >"$CONF/ours-$cmd" 2>&1 || true
    yggdrasilctl -endpoint="unix://$CONF/go.sock" -json $cmd >"$CONF/gou-$cmd" 2>&1 || true
    yggdrasilctl -endpoint="unix://$CONF/ours.sock" -json $cmd >"$CONF/oursu-$cmd" 2>&1 || true
    echo "##### $cmd"
    echo "-- go tcp | ours tcp"
    diff "$CONF/go-$cmd" "$CONF/ours-$cmd" && echo "   IDENTICAL"
    echo "-- ours tcp | ours unix"
    diff "$CONF/ours-$cmd" "$CONF/oursu-$cmd" && echo "   IDENTICAL"
done

echo "##### table mode against our node (yggdrasilctl decodes into its own structs)"
for cmd in list getSelf getPeers; do
    echo "-- $cmd"
    yggdrasilctl -endpoint=tcp://127.0.0.1:19101 $cmd 2>&1 || true
done

echo "##### our node's startup log"
cat "$CONF/ours-tcp.log"
