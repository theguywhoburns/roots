#!/bin/sh
# Slice 8 proof: does our `getPeers` answer the same rows, with the same fields
# and in the same order, as a Go 0.5.14 node's?
#   unshare -Un --map-root-user sh docs/plans/go-client-parity/proof/8-getpeers.sh
#
# `7-admin-inbound.sh` ended with two deviations on purpose: we listed nothing
# for a link we accepted, and no row ever carried a rate, a latency or an error
# age. Both are fixed, and this script checks each in the direction that owns it:
#
#   1. phase A — we dial Go: our row is the outbound one, Go's row for the same
#      link is the inbound one, and both carry bytes, rates, uptime, latency;
#   2. phase B — Go dials us: we now list the accepted link at all, under the
#      socket address it came from, with `inbound: true`;
#   3. a dial with nothing behind it stays listed on both sides, `up: false`,
#      with `last_error` and `last_error_time`;
#   4. `sort=cost` / `sort=uptime` answer with the same rows as no sort, in an
#      order the mode's own key actually explains;
#   5. phase C — a peering dialled both ways at once, on a second pair of nodes
#      so nothing is torn down first: neither side ever answers with two live
#      rows, and which one is live moves between samples. That is the flapping
#      deviation `docs/protocol/21-admin.md` records.
# Needs the installed yggdrasil/yggdrasilctl 0.5.14 — never a Go compiler, and
# never in CI.
set -e
ip link set lo up
cd "$(dirname "$0")/../../../.."
cargo build -q -p roots-client

GK=$(yggdrasil -genconf -json | grep -o '"PrivateKey": *"[0-9a-f]*"' | grep -o '[0-9a-f]\{128\}')
OK=$(yggdrasil -genconf -json | grep -o '"PrivateKey": *"[0-9a-f]*"' | grep -o '[0-9a-f]\{128\}')
D=$(mktemp -d)
trap 'kill $GO $OURS $GO2 $OURS2 2>/dev/null; rm -rf "$D"' EXIT INT TERM

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
conf "$GK" "tcp://127.0.0.1:19001" rootsgp8 "tcp://127.0.0.1:12401" "$D/go.conf"
conf "$OK" "tcp://127.0.0.1:19101" rootsop8 "tcp://127.0.0.1:12402" "$D/ours.conf"

yggdrasil -useconffile "$D/go.conf" >"$D/go.log" 2>&1 &
GO=$!
target/debug/roots -useconffile "$D/ours.conf" >"$D/ours.log" 2>&1 &
OURS=$!
sleep 4

GOEP=tcp://127.0.0.1:19001
OUEP=tcp://127.0.0.1:19101
ctl() { # endpoint, then the command and its key=value arguments
    ep=$1
    shift
    yggdrasilctl -endpoint="$ep" -json "$@" 2>&1 || true
}
# Rates are per-measurement and `omitempty`, so one answer can legitimately miss
# them. Ask several times and keep everything seen.
poll() { # endpoint, file, times
    i=0
    while [ "$i" -lt "$3" ]; do
        ctl "$1" getPeers >>"$2"
        i=$((i + 1))
        sleep 1
    done
}

fails=0
need() { # label, file, pattern, min
    n=$(grep -c "$3" "$2" || true)
    if [ "$n" -ge "$4" ]; then
        echo "ok    $1 ($n)"
    else
        echo "FAIL  $1 ($n, want at least $4)"
        fails=$((fails + 1))
    fi
}
# Per answer: the `remote` of the row that is up, or `nothing`.
liverow() {
    awk '/"peers": \[/ { if (seen) printf "  %s\n", (live ? live : "nothing"); live = ""; seen = 0 }
        /"remote"/ { r = $0; gsub(/.*: "|",$/, "", r); cur = r }
        /"up": true/ { seen = 1; live = (live == "" ? cur : live " + " cur) }
        END { printf "  %s\n", (live ? live : "nothing") }' "$1"
}
onelive() { # label, file — no answer may report two live rows
    if awk 'BEGIN { bad = 0; n = 0; seen = 0 }
        /"peers": \[/ { if (n > 1) bad = 1; n = 0 }
        /"up": true/ { n++; seen = 1 }
        END { exit bad || (seen == 0) }' "$2"; then
        echo "ok    $1"
    else
        echo "FAIL  $1 (an answer listed two live rows, or none at all)"
        fails=$((fails + 1))
    fi
}
liveclean() { # label, file — the row that is `up` must carry no error field
    if awk '/"up"/ { live = ($0 ~ /true/) }
        live && /"last_error"/ { bad = 1 }
        END { exit bad }' "$2"; then
        echo "ok    $1"
    else
        echo "FAIL  $1 (a row that is up also printed an error)"
        fails=$((fails + 1))
    fi
}
# The `remote` of every row, in the order the answer printed them.
remotes() { grep '"remote"' "$1" | sed 's/.*: "//; s/".*//' | sort; }
order() { grep '"remote"' "$1" | sed 's/.*: "//; s/".*//'; }
# The first inbound row's `remote`, which `PeerEntry` always prints before it.
inbound_uri() {
    awk '/"remote"/{r=$0} /"inbound": true/{gsub(/.*: "|",?$/,"",r); print r; exit}' "$1"
}
# An inbound row is named by the accepted socket, so its port is neither of the
# two URIs in this run.
checksocketnamed() { # label, uri
    case "$2" in
    tcp://127.0.0.1:12401 | tcp://127.0.0.1:12402 | tcp://127.0.0.1:12499 | "")
        echo "FAIL  $1 (named '$2', which is a configured URI or nothing at all)"
        fails=$((fails + 1))
        ;;
    tcp://127.0.0.1:*)
        echo "ok    $1 ($2)"
        ;;
    *)
        echo "FAIL  $1 (unrecognised remote '$2')"
        fails=$((fails + 1))
        ;;
    esac
}
costs() { grep '"cost"' "$1" | sed 's/[^0-9]//g'; }
checkorder() { # label, file  — the printed costs must not go backwards
    if awk '/"cost"/ { gsub(/[^0-9]/, ""); if ($0 == "") next; if ($0 + 0 < prev) bad = 1; prev = $0 + 0 }
        END { exit bad }' "$2"; then
        echo "ok    $1"
    else
        echo "FAIL  $1 (the rows are not in the order the mode claims)"
        fails=$((fails + 1))
    fi
}

echo "== phase A: we dial Go =="
ctl $OUEP addPeer uri=tcp://127.0.0.1:12401 >/dev/null
ctl $OUEP addPeer uri=tcp://127.0.0.1:12499 >/dev/null
ctl $GOEP addPeer uri=tcp://127.0.0.1:12499 >/dev/null
sleep 6
poll $GOEP "$D/a-go" 6
poll $OUEP "$D/a-ours" 6

need "we list the link we dialled" "$D/a-ours" '"remote": "tcp://127.0.0.1:12401"' 6
need "and call it outbound" "$D/a-ours" '"inbound": false' 12
need "Go lists the same link as inbound" "$D/a-go" '"inbound": true' 6
checksocketnamed "Go names that row by the accepted socket" "$(inbound_uri "$D/a-go")"
for side in a-ours a-go; do
    need "$side counts bytes both ways" "$D/$side" '"bytes_recvd"' 6
    need "$side has an uptime" "$D/$side" '"uptime"' 6
    need "$side has measured a round trip" "$D/$side" '"latency"' 6
    need "$side keeps the dead dial" "$D/$side" '"remote": "tcp://127.0.0.1:12499"' 6
    need "$side ages the dead dial's error" "$D/$side" '"last_error_time"' 6
done
# A rate is the traffic in the last second and `omitempty`, so it can only be
# asked for of the side that actually has traffic: we keep a quiet link up with a
# two-byte keepalive every second, and Go answers a keepalive with nothing at all
# (ironwood `peers.go:161-175` arms its timer for non-keepalive receives only).
# Measured 2026-09-25: our `bytes_sent` grew 2 a second while `bytes_recvd` sat
# still, and Go's row was the mirror image. See docs/protocol/21-admin.md.
need "we report a send rate (we send keepalives)" "$D/a-ours" '"rate_sent"' 3
need "Go reports a receive rate (it receives them)" "$D/a-go" '"rate_recvd"' 3
liveclean "our live row prints no error field" "$D/a-ours"
liveclean "Go's live row prints no error field" "$D/a-go"

echo
echo "== phase B: Go dials us (the accepted link, on our side) =="
ctl $OUEP removePeer uri=tcp://127.0.0.1:12401 >/dev/null
sleep 2
ctl $GOEP addPeer uri=tcp://127.0.0.1:12402 >/dev/null
sleep 6
poll $OUEP "$D/b-ours" 6
poll $GOEP "$D/b-go" 6
need "we list the link we accepted" "$D/b-ours" '"inbound": true' 6
checksocketnamed "and name it by the accepted socket" "$(inbound_uri "$D/b-ours")"
need "and Go lists the dial it made" "$D/b-go" '"remote": "tcp://127.0.0.1:12402"' 6
need "the accepted row carries our peer's key" "$D/b-ours" '"key": "[0-9a-f]\{64\}"' 6
need "the accepted row counts bytes" "$D/b-ours" '"bytes_recvd"' 6

echo
echo "== sort modes, on our node and Go's =="
for mode in "" cost uptime; do
    ctl $GOEP getPeers ${mode:+sort=$mode} >"$D/sort-go-$mode"
    ctl $OUEP getPeers ${mode:+sort=$mode} >"$D/sort-ours-$mode"
done
for side in go ours; do
    same=$(diff <(remotes "$D/sort-$side-") <(remotes "$D/sort-$side-cost") >/dev/null && echo yes || true)
    [ "$same" = yes ] && echo "ok    $side: sort=cost answers with the same rows" || {
        echo "FAIL  $side: sort=cost changed the row set"; fails=$((fails + 1)); }
    same=$(diff <(remotes "$D/sort-$side-") <(remotes "$D/sort-$side-uptime") >/dev/null && echo yes || true)
    [ "$same" = yes ] && echo "ok    $side: sort=uptime answers with the same rows" || {
        echo "FAIL  $side: sort=uptime changed the row set"; fails=$((fails + 1)); }
    checkorder "$side: sort=cost is non-decreasing in cost" "$D/sort-$side-cost" '"cost"'
done

echo
echo "== error wording, the part of the field that still differs =="
echo "-- go"; grep -h '"last_error"' "$D/a-go" | sort -u
echo "-- ours"; grep -h '"last_error"' "$D/a-ours" | sort -u

echo
echo "== phase C: both directions to one peer, from a cold start =="
# The phases above tear a link down before the next one is built, which hides the
# crossed case. This uses a second pair whose *config* dials the other, so both
# directions are attempted at once and neither side is cleaning up after itself.
# What this measures is the deviation docs/protocol/21-admin.md records under
# "A peering dialled both ways flaps": Go keys its link map by URI and ironwood
# keeps several links per node key (`peers.go:47-62`), so Go *can* hold both
# directions at once — but our `LinkSet` keeps one slot per node key and taking
# it closes the link that held it, so the pair trades closures instead of
# settling. Neither side ever shows two live rows here, and which one is live
# changes between samples.
GK2=$(yggdrasil -genconf -json | grep -o '"PrivateKey": *"[0-9a-f]*"' | grep -o '[0-9a-f]\{128\}')
OK2=$(yggdrasil -genconf -json | grep -o '"PrivateKey": *"[0-9a-f]*"' | grep -o '[0-9a-f]\{128\}')
conf_x() { # key, admin, ifname, listen, peer, file
    cat >"$6" <<EOF
{
  "PrivateKey": "$1",
  "AdminListen": "$2",
  "Listen": ["$4"], "Peers": ["$5"],
  "InterfacePeers": {}, "MulticastInterfaces": [],
  "AllowedPublicKeys": [], "GroupPassword": "",
  "IfName": "$3", "IfMTU": 65535,
  "NodeInfoPrivacy": false, "NodeInfo": null
}
EOF
}
conf_x "$GK2" "tcp://127.0.0.1:19002" rootsgp8c "tcp://127.0.0.1:12403" tcp://127.0.0.1:12404 "$D/go2.conf"
conf_x "$OK2" "tcp://127.0.0.1:19102" rootsop8c "tcp://127.0.0.1:12404" tcp://127.0.0.1:12403 "$D/ours2.conf"
yggdrasil -useconffile "$D/go2.conf" >"$D/go2.log" 2>&1 &
GO2=$!
target/debug/roots -useconffile "$D/ours2.conf" >"$D/ours2.log" 2>&1 &
OURS2=$!
sleep 10
poll tcp://127.0.0.1:19002 "$D/c-go" 3
poll tcp://127.0.0.1:19102 "$D/c-ours" 3
echo "-- go, one line per answer: the row that is up"
liverow "$D/c-go"
echo "-- ours"
liverow "$D/c-ours"
onelive "Go never answers with both directions up" "$D/c-go"
onelive "nor do we" "$D/c-ours"
need "both sides keep their own dial listed throughout" "$D/c-go" '"remote": "tcp://127.0.0.1:12404"' 3
need "both sides keep their own dial listed throughout" "$D/c-ours" '"remote": "tcp://127.0.0.1:12403"' 3
need "the accepted direction does get a row" "$D/c-ours" '"inbound": true' 1
need "Go logs the pair going up and down" "$D/go2.log" "Connected \|Disconnected " 6
echo "-- our node's own words about it"
tail -2 "$D/ours2.log"

echo
if [ "$fails" -eq 0 ]; then
    echo "== all checks passed =="
else
    echo "== $fails check(s) failed =="
    exit 1
fi
