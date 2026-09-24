#!/bin/sh
# Capture the admin framing edge cases that docs/protocol/21-admin.md documents,
# from a live Go 0.5.14 node and from ours, one raw JSON value per line, each
# request on a fresh connection (so `keepalive` is not what is being tested here).
#   unshare -Un --map-root-user sh docs/plans/go-client-parity/proof/7-admin-raw.sh
set -e
ip link set lo up
cd "$(dirname "$0")/../../../.."
# Always rebuild: a stale `target/debug/roots` answers with the bytes of a
# version that no longer exists, which reads exactly like a parity failure.
cargo build -q -p roots-client

CONF=$(mktemp -d)
KEY=$(grep -o '"PrivateKey": "[0-9a-f]*"' client/src/config.rs | head -1 | grep -o '[0-9a-f]\{128\}')
cat >"$CONF/go.conf" <<EOF
{"PrivateKey": "$KEY", "AdminListen": "tcp://127.0.0.1:19001", "Listen": [], "Peers": [],
 "InterfacePeers": {}, "MulticastInterfaces": [], "AllowedPublicKeys": [], "GroupPassword": "",
 "IfName": "rootsgo-r", "IfMTU": 65535, "NodeInfoPrivacy": false, "NodeInfo": null}
EOF
sed 's/19001/19101/; s/rootsgo-r/roots-r/' "$CONF/go.conf" >"$CONF/ours.conf"

yggdrasil -useconffile "$CONF/go.conf" >"$CONF/go.log" 2>&1 &
GO=$!
target/debug/roots -useconffile "$CONF/ours.conf" >"$CONF/ours.log" 2>&1 &
OURS=$!
trap 'kill $GO $OURS 2>/dev/null; rm -rf "$CONF"' EXIT INT TERM
sleep 5

cat >"$CONF/reqs" <<'EOF'
{"request":""}
not json at all
{"request":"NoSuchThing"}
{"request":"LIST"}
{"keepalive":true}
{"request":"list","bogus":1}
[]
"just a string"
{"request":"list","arguments":"notanobject"}
{"request":"getSelf","arguments":"notanobject"}
{"request":"getSelf","arguments":null}
{"request":"getTree","arguments":5}
{"request":"getPeers","arguments":{"sort":123}}
{"request":"addPeer","arguments":{"uri":123}}
{"request":"addPeer","arguments":{"uri":"tcp://127.0.0.1:1234","interface":5}}
{"request":"getPeers","arguments":{"sort":"uptime"}}
{"request":"addPeer","arguments":{"uri":"bogus://x"}}
{"request":"addPeer","arguments":{"uri":"tcp://127.0.0.1:1234?password=nothex"}}
{"request":"addPeer","arguments":{"uri":"tcp://127.0.0.1:1234?password=zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"}}
{"request":"addPeer","arguments":{"uri":"tcp://127.0.0.1:1234?priority=999"}}
{"request":"addPeer","arguments":{"uri":"tcp://127.0.0.1:1234"}}
{"request":"addPeer","arguments":{"uri":"tcp://127.0.0.1:1234"}}
{"request":"removePeer","arguments":{"uri":"tcp://127.0.0.1:9999"}}
{"request":"getPeers","arguments":{"sort":"nonsense"}}
{"request":"getSelf"}{"request":"getTree"}
EOF

for port in 19001 19101; do
  perl -e '
    use strict; use warnings; use IO::Socket::INET;
    my ($port, $file) = @ARGV;
    open my $fh, "<", $file or die $!;
    while (my $req = <$fh>) {
        chomp $req; next unless length $req;
        my $s = IO::Socket::INET->new(PeerAddr => "127.0.0.1:$port") or die "connect: $!";
        print $s $req; $s->shutdown(1);
        local $/; my $r = <$s>; $r = "(no reply)" unless defined $r;
        print "=== $req\n$r";
    }
  ' "$port" "$CONF/reqs" >"$CONF/raw-$port.txt" 2>&1
done

echo "##### Go 19001 vs ours 19101"
diff "$CONF/raw-19001.txt" "$CONF/raw-19101.txt" && echo "IDENTICAL"
cp "$CONF/raw-19001.txt" /tmp/7admin-go.txt
cp "$CONF/raw-19101.txt" /tmp/7admin-ours.txt
echo "(copies left in /tmp/7admin-go.txt and /tmp/7admin-ours.txt for the doc)"
