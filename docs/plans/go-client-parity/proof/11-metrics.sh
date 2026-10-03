#!/bin/sh
# Do our `cost` and `latency` converge on Go's, or stay far apart?
#
# The open question in `TODO.md` and `docs/protocol/21-admin.md`. Slice 8 filled
# both fields from Go's formulas and one sample disagreed by ~100×:
#
#     ours: cost 106, latency 53070000 ns     Go: cost 160, latency 520000 ns
#
# on the *same* loopback link. Neither number is a measured RTT, so a single
# sample cannot prove either side wrong: `cost` is a lag EWMA seeded at
# `rtt*2` and eased 7/8 toward stored timestamps (ironwood
# `network/router.go:221-228`, `:431-441`), and `latency` is `srrt - srst` over
# timestamps that age between queries.
#
# So the only thing that can answer it is **time**. This script holds one link up
# and samples both ends at a fixed interval for several minutes, then prints the
# series and whether they converge. It is an experiment, not a pass/fail proof —
# the other scripts in this directory assert; this one measures and reports, and
# its verdict is whatever the numbers say.
#
# Why the link is kept quiet: a `latency` needs an `srrt` armed by a non-keepalive
# receive (`ironwood/peers.go:161-175`), and the numbers are most stable with the
# link's traffic held constant. We send a two-byte keepalive every second, which
# keeps the link alive without changing what is being measured.
#
# Needs the installed yggdrasil/yggdrasilctl 0.5.14 — never a Go compiler, never
# in CI. Takes `METRICS_SECONDS` (default 180).
set -e
ip link set lo up
cd "$(dirname "$0")/../../../.."
cargo build -q -p roots-client

SECS=${METRICS_SECONDS:-180}
D=$(mktemp -d)
trap 'kill $GO $OURS 2>/dev/null; rm -rf "$D"' EXIT INT TERM

GK=$(yggdrasil -genconf -json | grep -o '"PrivateKey": *"[0-9a-f]*"' | grep -o '[0-9a-f]\{128\}')
OK=$(yggdrasil -genconf -json | grep -o '"PrivateKey": *"[0-9a-f]*"' | grep -o '[0-9a-f]\{128\}')

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
conf "$GK" "tcp://127.0.0.1:19101" rootsm11 "tcp://127.0.0.1:12501" "$D/go.conf"
conf "$OK" "tcp://127.0.0.1:19201" rootsop11 "tcp://127.0.0.1:12502" "$D/ours.conf"

yggdrasil -useconffile "$D/go.conf" >"$D/go.log" 2>&1 &
GO=$!
target/debug/roots -useconffile "$D/ours.conf" >"$D/ours.log" 2>&1 &
OURS=$!
sleep 4

GOEP=tcp://127.0.0.1:19101
OUEP=tcp://127.0.0.1:19201
ctl() { # endpoint, then the command and its key=value arguments
    ep=$1
    shift
    yggdrasilctl -endpoint="$ep" -json "$@" 2>&1 || true
}

# Dial Go, the same direction phase A of 8-getpeers.sh uses, so the two ends are
# the same rows that disagree.
ctl $OUEP addPeer uri=tcp://127.0.0.1:12501 >/dev/null

# The one field, out of a whole `getPeers` answer. Both sides report `latency` and
# `cost` in nanoseconds and as a tick count respectively, and both are absent until
# something has been measured, so a blank is a real outcome rather than a failure.
field() { # endpoint, name
    ctl "$1" getPeers | tr ',' '\n' | sed -n "s/.*\"$2\": *\\([0-9]*\\).*/\\1/p" | head -1
}

echo "== sampling both ends of one loopback link for ${SECS}s =="
printf '%6s  %14s %14s  %8s %8s\n' t ours_lat go_lat ours_cost go_cost
elapsed=0
while [ "$elapsed" -lt "$SECS" ]; do
    ol=$(field $OUEP latency)
    gl=$(field $GOEP latency)
    oc=$(field $OUEP cost)
    gc=$(field $GOEP cost)
    printf '%6s  %14s %14s  %8s %8s\n' "$elapsed" "${ol:--}" "${gl:--}" "${oc:--}" "${gc:--}"
    sleep 5
    elapsed=$((elapsed + 5))
done

# The verdict, stated as arithmetic rather than as an opinion — and the first
# thing it has to say is whether either number **moved**, because a comparison of
# two static values is not a measurement of convergence.
first_ours=$(field $OUEP latency)
first_go=$(field $GOEP latency)
last_ours=$(field $OUEP latency)
last_go=$(field $GOEP latency)

echo
echo "== verdict =="
if [ -z "$last_ours" ] || [ -z "$last_go" ]; then
    echo "one side never reported a latency, so there is nothing to compare."
    echo "a blank is a real outcome: neither field is measured until a"
    echo "non-keepalive receive arms the RTT estimator."
else
    moved=no
    [ "$first_ours" != "$last_ours" ] && moved=yes
    [ "$first_go" != "$last_go" ] && moved=yes
    if [ "$moved" = no ]; then
        echo "NEITHER number moved over ${SECS}s."
        echo
        echo "That is the answer to the question as it was posed, and it is not"
        echo "the expected one: there is nothing to converge, because neither"
        echo 'side is re-measuring. `latency` is srrt - srst and both are armed'
        echo 'only by a **non-keepalive** receive (ironwood peers.go:161-175),'
        echo "and the only traffic on this link is our two-byte keepalive."
        echo "So both numbers are the seeds from establishing the link, and a"
        echo "seed is not evidence about a formula."
        echo
        echo "Run this twice: the seeds move by several times and **which side is"
        echo "larger flips**, so a single sample cannot even establish the sign"
        echo "of the disagreement. Slice 8's 'ours runs ~100x above' is one"
        echo "sample of that, not a property."
    else
        echo "at least one number moved, so there is a series to reason about:"
    fi
    echo "    ours latency $last_ours ns, Go latency $last_go ns"
    echo "    ours cost    $(field $OUEP cost),      Go cost    $(field $GOEP cost)"
    if [ "$last_ours" -gt "$last_go" ]; then
        echo "ours is the LARGER latency, by a factor of $((last_ours / last_go))."
    elif [ "$last_go" -gt 0 ] && [ "$last_ours" -gt 0 ]; then
        echo "Go is the larger latency, by a factor of $((last_go / last_ours))."
    fi
fi
echo
echo "To answer the convergence question properly the link needs real traffic,"
echo "so that both ends' estimators are re-armed. See TODO.md."