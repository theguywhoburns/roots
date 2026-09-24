#!/bin/sh
# Slice 7 proof, second half: does our getPeers produce the same ROW SET as Go's,
# and the same `inbound` flag, for a link we dialled and a link we accepted?
#   unshare -Un --map-root-user sh docs/plans/go-client-parity/proof/7-admin-inbound.sh
#
# 7-admin.sh proves the framing and the field order; it holds only a peer that
# cannot connect, so no row is ever `up`. This script makes one link in each
# direction, separately, and shows what each side reports.
#
# What it showed when it was written (2026-09-24) — the two deviations
# docs/protocol/21-admin.md recorded and Slice 8 then fixed:
#   A: our dial's row matched Go's inbound row apart from the rate/latency
#      fields we did not fill (and Go named the row by the rewritten socket
#      address, `link.go:519-525`).
#   B: Go listed the link it dialled; we listed nothing for a link we accepted,
#      because our rows came from the configured peer list. With both directions
#      up at once our row additionally reported the *accepted* link's direction
#      against the dial's URI, because `LinkSet` keys by node public key and the
#      second link replaces the first.
# Run it again and A is a field-by-field match; B is a row of our own, named by
# its socket, with the direction that belongs to it. The one-live-row half of B
# is still true and still churns — that part now has a check, in
# 8-getpeers.sh phase C, which supersedes this script.
# Needs the installed yggdrasil/yggdrasilctl 0.5.14; never a Go compiler, and
# never in CI.
set -e
ip link set lo up
cd "$(dirname "$0")/../../../.."
cargo build -q -p roots-client

GK=$(yggdrasil -genconf -json | grep -o '"PrivateKey": *"[0-9a-f]*"' | grep -o '[0-9a-f]\{128\}')
OK=$(yggdrasil -genconf -json | grep -o '"PrivateKey": *"[0-9a-f]*"' | grep -o '[0-9a-f]\{128\}')
CONF=$(mktemp -d)
trap 'kill $GO $OURS 2>/dev/null; rm -rf "$CONF"' EXIT INT TERM

conf() { # key, admin, ifname, listen, file
    cat >"$5" <<EOF
{
  "PrivateKey": "$1",
  "AdminListen": "$2",
  "Listen": ["$4"],
  "Peers": [], "InterfacePeers": {}, "MulticastInterfaces": [],
  "AllowedPublicKeys": [], "GroupPassword": "",
  "IfName": "$3", "IfMTU": 65535,
  "NodeInfoPrivacy": false, "NodeInfo": null
}
EOF
}
conf "$GK" "tcp://127.0.0.1:19001" rootsin-g "tcp://127.0.0.1:12401" "$CONF/go.conf"
conf "$OK" "tcp://127.0.0.1:19101" rootsin-o "tcp://127.0.0.1:12402" "$CONF/ours.conf"

yggdrasil -useconffile "$CONF/go.conf" >"$CONF/go.log" 2>&1 &
GO=$!
target/debug/roots -useconffile "$CONF/ours.conf" >"$CONF/ours.log" 2>&1 &
OURS=$!
sleep 4

ctl() { yggdrasilctl -endpoint="$1" -json "$2" ${3+"$3"} 2>&1 || true; }

echo "== A: OURS dials Go's listener =="
ctl tcp://127.0.0.1:19101 addPeer uri=tcp://127.0.0.1:12401
sleep 5
echo "-- go getPeers";  ctl tcp://127.0.0.1:19001 getPeers
echo "-- ours getPeers"; ctl tcp://127.0.0.1:19101 getPeers
ctl tcp://127.0.0.1:19101 removePeer uri=tcp://127.0.0.1:12401 >/dev/null
sleep 2

echo "== B: Go dials OUR listener =="
ctl tcp://127.0.0.1:19001 addPeer uri=tcp://127.0.0.1:12402
sleep 5
echo "-- go getPeers";  ctl tcp://127.0.0.1:19001 getPeers
echo "-- ours getPeers"; ctl tcp://127.0.0.1:19101 getPeers
