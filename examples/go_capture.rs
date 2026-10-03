//! Capture real Go `meta` handshake bytes from the installed yggdrasil binary,
//! and check our encoder reproduces them byte for byte for the same key.
//!
//! This is the oracle for `tests/go_vectors.rs`: the hex there was produced
//! here, from `/run/current-system/sw/bin/yggdrasil` 0.5.14 — never
//! transcribed from Go's own tests, which build their expectations
//! programmatically and so prove nothing about our bytes.
//!
//! The node always tries to create a TUN interface and `panic`s if it may not
//! (Go `cmd/yggdrasil/main.go:282`), so this must run inside a private user +
//! network namespace, which is unprivileged on this host:
//!
//! ```sh
//! unshare -Un --map-root-user cargo run -q --example go_capture -- --frames
//! ```
//!
//! A fresh netns has `lo` DOWN, so the harness brings it up itself (see
//! `ensure_loopback`).
//!
//! Add `-- --frames` to also exchange link frames with the node and dump the
//! raw envelope bytes (`SigReq` arrives unsolicited inside ~1 s: Go
//! `_sendReqs`, ironwood `network/router.go:188`).

use std::io::Write;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use ed25519_dalek::{Signer, SigningKey};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use roots::frame::{self, FrameType};
use roots::handshake::{HEADER_LEN, Meta};

/// The oracle: a Nix store binary, no Go toolchain involved.
const GO_BIN: &str = "/run/current-system/sw/bin/yggdrasil";
/// Both ports are only reachable inside our own namespace, so a fixed pair is
/// safer than a free-port hunt (the config has to name the port up front).
const PORTS: [u16; 2] = [17777, 17778];
/// Go's admin socket. It has to be named, and the reason is not cosmetic.
///
/// `yggdrasil -genconf -json` **omits** `AdminListen` entirely — Go's
/// `omitempty` — so a config that leaves it out gets Go's compiled-in default,
/// `unix:///var/run/yggdrasil/yggdrasil.sock`. Inside a user namespace that path
/// is not writable, and Go treats the failure as **fatal**:
///
/// ```text
/// Admin socket failed to listen: listen unix /var/run/yggdrasil/…: permission denied
/// ```
///
/// The node exits there — before the TUN, before the pathfinder, before
/// anything this harness could capture a session from. That is the whole reason
/// `GO_SESSION` never existed: the node was dying four lines into its startup
/// and the harness reported "no session" as if the node had been running the
/// whole time.
///
/// An **empty** `AdminListen` does not help: Go's core substitutes the default
/// for an empty value as well, so the field has to name something bindable.
/// Naming a TCP port inside the namespace is enough, and it doubles as the
/// lever `ask_go_about_us` pulls.
const ADMIN_PORT: u16 = 17779;
/// Fixed seed, so we can re-sign with it. Go's `PrivateKey` config field is
/// the 64-byte seed||pub, hence the pubkey is derived, never chosen.
const SEED: [u8; 32] = [0x5c; 32];
/// Our own identity for `--frames`. It must differ from `SEED`: a node closes
/// any link whose meta carries its own key (Go `ErrLinkToSelf`,
/// `src/core/link.go:158`, checked at :662; ours is `Error::SelfDial`), which
/// is exactly what reusing `SEED` produced.
const OUR_SEED: [u8; 32] = [0x2b; 32];
/// Non-empty password takes the keyed branch of the membership hash; empty
/// takes the unkeyed one. Both signatures must match Go's.
const PASSWORD: &str = "roots-capture";

fn go_config(priv_hex: &str, port: u16, password: &str) -> String {
    let listen = if password.is_empty() {
        format!("tcp://127.0.0.1:{port}")
    } else {
        format!("tcp://127.0.0.1:{port}?password={password}")
    };
    format!(
        r#"{{"PrivateKey":"{priv_hex}","Listen":["{listen}"],"Peers":[],"InterfacePeers":{{}},"AllowedPublicKeys":[],"MulticastInterfaces":[],"AdminListen":"tcp://127.0.0.1:{ADMIN_PORT}","IfName":"auto","IfMTU":65535,"NodeInfoPrivacy":false,"NodeInfo":{{"name":"gocap","software":"go0.5.14","build":"capture","protocol":7,"link":"tcp://127.0.0.1:1"}}}}"#
    )
}

/// Ask Go about us over its admin socket, and thereby make it open a session.
///
/// **This is the only way Go ever sends nodeinfo, and it took reading the source
/// to find out.** `nodeinfo._sendReq` has exactly one caller in the whole
/// module — the `getNodeInfo` admin handler (`core/nodeinfo.go:160`) — and it
/// does a plain `PacketConn.WriteTo` of a nodeinfo *request*. There is no
/// proactive send anywhere: a fresh Go node will not tell a peer anything,
/// however long the link is up and however much nodeinfo it holds.
///
/// That matters because a session rides **inside** a `Traffic` frame: there is
/// no session frame type, since the pathfinder sits below the session layer and
/// the traffic frame's payload *is* the session message. So no session bytes
/// means no `Traffic` frame, and asking the admin socket is the only lever that
/// produces one.
///
/// The payload is sealed to *our* box key, which we hold, so unlike a peer's
/// session message this one is readable — see the `FrameType::Traffic` arm.
async fn ask_go_about_us(our_pub: [u8; 32]) -> Result<String, String> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let mut s = dial(ADMIN_PORT).await;
    // Go's admin stream is newline-delimited JSON: one request object, then one
    // response object (`core/admin.go`). `key` is hex, per `nodeinfo.go:152`.
    let req = format!(
        r#"{{"request":"getNodeInfo","arguments":{{"key":"{}"}}}}
"#,
        hex::encode(our_pub)
    );
    s.write_all(req.as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    // Go pretty-prints its response, so the answer is **many lines**: counting
    // braces is the only way to know it has arrived, and stopping at the first
    // newline reads `{` and calls it a response. The deadline is Go's own plus a
    // margin — its handler waits 6 s (`nodeinfo.go:164`).
    let mut reader = BufReader::new(s);
    let mut body = String::new();
    let until = tokio::time::Instant::now() + Duration::from_secs(9);
    loop {
        let mut line = String::new();
        match tokio::time::timeout_at(until, reader.read_line(&mut line)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(_)) => {
                let opens = body.matches('{').count();
                let closes = body.matches('}').count();
                body.push_str(&line);
                // Balanced and non-empty means a whole object; Go's error
                // responses are balanced too, so there is no ambiguity here.
                if opens > 0 && opens == closes && !body.trim().is_empty() {
                    break;
                }
            }
            Ok(Err(e)) => return Err(e.to_string()),
            Err(_) => return Err("timed out reading the admin response".into()),
        }
    }
    let body = body.trim().to_string();
    if body.is_empty() {
        return Err("the admin socket closed without answering".into());
    }
    Ok(body)
}

/// Refuse to run anywhere the node could claim a real interface and reroute the
/// host's `200::/7`. What we need is `CAP_NET_ADMIN` over *our* network
/// namespace, which is exactly what `unshare -Un --map-root-user` produces;
/// `/proc/1/ns/net` is unreadable from a child userns, so the namespace is
/// inferred from the capability plus a non-host uid mapping.
fn assert_private_netns() {
    const CAP_NET_ADMIN: u64 = 1 << 12;
    let hint = "run inside a private namespace:\n  unshare -Un --map-root-user cargo run -q --example go_capture";
    let status = std::fs::read_to_string("/proc/self/status").expect("/proc/self/status");
    let cap_eff = status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:"))
        .and_then(|value| u64::from_str_radix(value.trim(), 16).ok())
        .unwrap_or(0);
    assert!(
        cap_eff & CAP_NET_ADMIN != 0,
        "no CAP_NET_ADMIN here, so the Go node cannot create its TUN and will panic.\n{hint}"
    );
    let uid_map = std::fs::read_to_string("/proc/self/uid_map").unwrap_or_default();
    assert!(
        uid_map.trim() != "0 0 4294967295",
        "uid 0 here is the host's root, so the node would join the host mesh.\n{hint}"
    );
    if let (Ok(mine), Ok(init)) = (
        std::fs::read_link("/proc/self/ns/net"),
        std::fs::read_link("/proc/1/ns/net"),
    ) {
        assert!(
            mine != init,
            "sharing the network namespace with PID 1.\n{hint}"
        );
    }
}

/// A fresh network namespace has `lo` administratively DOWN with no routes, so
/// every loopback connect fails `ENETUNREACH`. Bringing it up needs
/// `CAP_NET_ADMIN`, which `assert_private_netns` just proved we hold — over our
/// own namespace only.
fn ensure_loopback() {
    let up = Command::new("ip")
        .args(["link", "set", "lo", "up"])
        .status()
        .expect("run `ip link set lo up` (is `ip` on PATH?)");
    assert!(up.success(), "`ip link set lo up` failed: {up}");
}

/// The Go node, reaped even when the capture panics: an orphan keeps our
/// stdout open, so `go_capture | tail` would hang instead of reporting the
/// panic.
struct Go(Child);

impl Drop for Go {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn spawn_go(config: &str) -> Go {
    let mut child = Command::new(GO_BIN)
        .args(["-useconf"])
        .stdin(Stdio::piped())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn yggdrasil (is the binary installed?)");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(config.as_bytes())
        .expect("write config");
    Go(child)
}

/// Connect, retrying while the node's listener comes up. Any connection that
/// is not used is dropped, which costs the node a failed link and nothing
/// else: the `meta` we sign is deterministic, so every attempt yields the same
/// bytes.
async fn dial(port: u16) -> TcpStream {
    let addr = format!("127.0.0.1:{port}");
    let mut last = None;
    for _ in 0..100 {
        match TcpStream::connect(&addr).await {
            Ok(stream) => return stream,
            Err(e) => last = Some(e),
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!(
        "never reached {addr}: {} — a loopback failure usually means `lo` is \
         down in this namespace",
        last.expect("loop ran")
    );
}

async fn read_meta(stream: &mut TcpStream) -> Vec<u8> {
    let mut header = [0u8; HEADER_LEN];
    stream.read_exact(&mut header).await.expect("meta header");
    assert_eq!(&header[..4], b"meta", "Go preamble");
    let body = u16::from_be_bytes([header[4], header[5]]) as usize;
    let mut msg = header.to_vec();
    msg.resize(HEADER_LEN + body, 0);
    stream
        .read_exact(&mut msg[HEADER_LEN..])
        .await
        .expect("meta body");
    msg
}

/// Read one raw link frame, keeping the envelope intact for the dump. Failures
/// are reported rather than swallowed: a closed stream means Go hung up on us
/// (almost always a password or version mismatch), which is not the same
/// result as "Go sent nothing".
async fn read_frame_raw<S: AsyncRead + Unpin>(
    stream: &mut S,
) -> Option<(Vec<u8>, FrameType, Vec<u8>)> {
    let mut len = Vec::with_capacity(3);
    loop {
        let mut byte = [0u8; 1];
        match stream.read_exact(&mut byte).await {
            Ok(_) => {}
            Err(e) => {
                eprintln!("(stream closed while reading a frame length: {e})");
                return None;
            }
        }
        len.push(byte[0]);
        if byte[0] & 0x80 == 0 {
            break;
        }
    }
    let Some((n, _)) = frame::read_uvarint(&len) else {
        eprintln!("(undecodable frame length: {})", hex::encode(&len));
        return None;
    };
    let mut body = vec![0u8; n as usize];
    if let Err(e) = stream.read_exact(&mut body).await {
        eprintln!("(stream closed mid-frame: {e})");
        return None;
    }
    let Ok((ftype, payload)) = frame::decode_body(&body) else {
        eprintln!("(undecodable frame body: {})", hex::encode(&body));
        return None;
    };
    let payload = payload.to_vec();
    let mut raw = len;
    raw.extend_from_slice(&body);
    Some((raw, ftype, payload))
}

async fn capture(password: &str, port: u16, frames: bool) -> Vec<u8> {
    let sk = SigningKey::from_bytes(&SEED);
    let pk = sk.verifying_key().to_bytes();
    let priv_hex = hex::encode([SEED.as_slice(), pk.as_slice()].concat());
    let _node = spawn_go(&go_config(&priv_hex, port, password));
    let mut stream = dial(port).await;

    let theirs = read_meta(&mut stream).await;
    let label = if password.is_empty() {
        "unkeyed"
    } else {
        "keyed"
    };
    println!("=== {label} meta (port {port}, {} bytes) ===", theirs.len());
    println!("go   {}", hex::encode(&theirs));

    let decoded = Meta::decode(&theirs, password.as_bytes())
        .expect("our decoder must accept Go's meta with the same password");
    assert_eq!(decoded.public_key, pk, "meta carries the configured key");
    assert_eq!((decoded.major, decoded.minor), (0, 5), "Go 0.5.x");
    assert_eq!(decoded.vendor, None, "Go sends no vendor tag");
    println!(
        "dec  major={} minor={} prio={} pubkey={}",
        decoded.major,
        decoded.minor,
        decoded.priority,
        hex::encode(decoded.public_key)
    );

    // Ours, from the same seed: must be the same bytes, signature included.
    let ours = Meta::local_go(&pk, decoded.priority)
        .encode(&sk, password.as_bytes())
        .expect("encode");
    println!("ours {}", hex::encode(&ours));
    assert_eq!(
        ours, theirs,
        "our encoder diverged from Go's bytes ({label})"
    );
    println!("match: byte-identical");

    if frames {
        // A real link needs our own key, not the oracle's.
        let our_sk = SigningKey::from_bytes(&OUR_SEED);
        let our_pk = our_sk.verifying_key().to_bytes();
        let our_meta = Meta::local_go(&our_pk, 0)
            .encode(&our_sk, password.as_bytes())
            .expect("encode ours");
        println!("ours(meta) {}", hex::encode(&our_meta));
        stream
            .write_all(&our_meta)
            .await
            .expect("send our meta to open the link");
        stream.flush().await.expect("flush");

        // Go answers a `SigReq` with a `SigRes` and nothing else, and only for a
        // request it has not already answered. So the harness has to ask: the
        // unsolicited burst is `SigReq` + `BloomFilter` + `Announce`, and the
        // `SigRes` payload — the one with a real `psig` in it — is simply absent
        // from a passive capture. `SigReq::encode` is ours, which does not
        // matter: the vector under test is Go's answer.
        //
        // The request has to be one Go will accept, so it is the *oracle's* key
        // and the seq it already used. Go caches answered requests
        // (`peers.sigCache`, ironwood `network/peers.go`), so a repeated
        // (node, seq) nonce is silently dropped — which is the third of
        // AGENTS.md's traps in a new dress.
        let req = roots::tree::SigReq { seq: 1, nonce: 0 };
        let mut req_bytes = Vec::new();
        req.encode(&mut req_bytes);
        println!("ours(SigReq) {}", hex::encode(&req_bytes));
        roots::link::write_frame_to(&mut stream, FrameType::SigReq, &req_bytes)
            .await
            .expect("send a SigReq");

        // Read Go's answer to that request, and keep it. This is the `SigRes`
        // whose `psig` is signed by **Go** over (our key, Go's key) — and that
        // is exactly the preimage an announce naming Go as our parent needs, so
        // it is reusable rather than a second signature to forge. Go's key is
        // the one from its `meta`, which we already decoded above.
        let go_pk = decoded.public_key;
        let (sigres, _) = loop {
            let Some((_, ftype, payload)) = read_frame_raw(&mut stream).await else {
                panic!("Go hung up before answering our SigReq");
            };
            if ftype == FrameType::SigRes {
                break roots::tree::SigRes::decode(&payload).expect("decode Go's SigRes");
            }
        };
        assert!(
            sigres.check(&our_pk, &go_pk),
            "Go's SigRes must verify against (our key, Go's key) before we reuse it"
        );
        println!(
            "go(SigRes) {}",
            hex::encode(&{
                let mut b = Vec::new();
                sigres.encode(&mut b);
                b
            })
        );
        println!(
            "go(SigRes) req={} port={} — Go's idea of the port it can reach us on",
            sigres.req.seq, sigres.port
        );

        // Answer Go's `Announce` with one of our own, so Go accepts us as a tree
        // peer rather than dropping the link for want of an upstream. Built by
        // hand rather than by a router because this harness is the byte-level
        // oracle and a router in the loop would make the capture depend on the
        // thing under test.
        //
        // **Go is our parent, and that is load-bearing.** The obvious choice —
        // announce ourselves as our own parent, the shape Go used for its own
        // root announce — is accepted and is *not* enough, and the symptom is
        // entirely silent: Go never sends a `PathLookup`, so nothing it wants to
        // tell us ever arrives.
        //
        // The reason is `_fixOnTree` (`network/bloomfilter.go:145-174`), which
        // decides whether a peer sits on the routing tree:
        //
        // ```go
        // if selfInfo.parent == pk { pbi.onTree = true }
        // else if info, isIn := bs.router.infos[pk]; isIn {
        //     if info.parent == selfKey { pbi.onTree = true }
        // }
        // ```
        //
        // A self-parented peer satisfies neither arm: it is not Go's parent, and
        // its parent is not Go. And `_sendMulticast` skips every peer with
        // `!pbi.onTree` (`bloomfilter.go:306-308`) — so the `PathLookup` Go
        // generates for us when the admin socket asks it about us is multicast
        // into a room with nobody in it. `_sendLookup` does not send a unicast
        // lookup at all; the bloom filter is the *whole* decision
        // (`network/pathfinder.go:27-42`).
        //
        // So the announce has to name Go as the parent, which is also the
        // honest thing: Go genuinely is our upstream for the length of this
        // link. The cost is that `res` must be Go's own signature, which is why
        // the `SigRes` above is read and reused rather than made here.
        //
        // MEASURED: this does *not* produce a second, non-empty bloom. Go accepts
        // the announce, keeps the link open, and does not re-advertise its
        // filter inside the 30 s window — one bloom, still empty. So the bloom
        // bit order stays pinned by a generator vector rather than by the
        // installed binary (`src/bloom.rs`, `bloom_vector_matches_go`, and the
        // note on `the_flag_layout_is_flags_then_data`). The code is kept because
        // the announce is a real interop check: if our `Announce` were malformed
        // Go would close the link, and that is a cheap thing to assert by eye in
        // the log.
        //
        // The shapes are Go's: `Announce{key, parent, res{req, port, psig}, sig}`,
        // where `res.psig` is signed by the parent and `sig` by the announcer
        // (`router.go:409-416`).
        let our_sk = SigningKey::from_bytes(&OUR_SEED);
        let our_pk = our_sk.verifying_key().to_bytes();
        // The outer `sig` covers the same preimage as `psig` — node ‖ parent ‖
        // req ‖ port — signed by the announcer rather than by the parent
        // (`Announce::check` verifies both over `res.bytes_for_sig`).
        let preimage = sigres.bytes_for_sig(&our_pk, &go_pk);
        let ann = roots::tree::Announce {
            key: our_pk,
            parent: go_pk,
            res: sigres,
            sig: our_sk.sign(&preimage).to_bytes(),
        };
        assert!(
            ann.check(),
            "our own announce must satisfy our own checker before we send it"
        );
        let mut ann_bytes = Vec::new();
        ann.encode(&mut ann_bytes);
        println!("ours(Announce) {}", hex::encode(&ann_bytes));
        roots::link::write_frame_to(&mut stream, FrameType::Announce, &ann_bytes)
            .await
            .expect("send an Announce");

        // Hold the link open. Go gives every link read a **deadline** and closes it
        // when nothing arrives before it expires (`core/link.go:274-291`), and
        // measured here that is **about four seconds**:
        //
        // ```text
        // Disconnected inbound: …; error: read tcp …: i/o timeout
        // ```
        //
        // So a capture that sends its `SigReq` and `Announce` and then only
        // *listens* gets four seconds of link, which is why this harness
        // reported "no session" for every session capture ever attempted: the
        // node was healthy and the link was killed by our own silence. A live
        // node sends a `KeepAlive` when it has nothing else to say — the same
        // trick `keepalive_if_idle` plays on the dispatch path — and that is
        // what a tick here reproduces.
        // The stream is split rather than shared: the tick and the read loop both
        // need it, and a `TcpStream` cannot be both borrowed at once. Splitting
        // is also what a real link does — the read side and the write side are
        // separate halves with separate lifetimes.
        let (mut rhalf, whalf) = stream.into_split();
        // The write half is behind a mutex because two tasks write to it: the
        // keepalive tick and the `PathNotify` reply below. A frame is written
        // with one `write_all` of its whole length-prefixed body, so two
        // writers cannot interleave *within* a frame - but they can still
        // interleave *between* frames, and holding the lock across the write
        // is what stops that.
        let whalf = std::sync::Arc::new(tokio::sync::Mutex::new(whalf));
        let tick_half = whalf.clone();
        let keepalive = tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_millis(700));
            loop {
                tick.tick().await;
                let mut w = tick_half.lock().await;
                if roots::link::write_frame_to(&mut *w, FrameType::KeepAlive, &[])
                    .await
                    .is_err()
                {
                    return;
                }
            }
        });

        println!("=== frames from Go ===");
        // The admin request is fired **concurrently** with the read loop, not
        // before it, because it provokes the very frame the loop has to answer.
        //
        // The chain is: `getNodeInfo` → `PacketConn.WriteTo` → pathfinder has no
        // path to us → a `PathLookup` goes out → we answer with a `PathNotify`
        // → the nodeinfo request goes out again and this time it lands. Asking
        // before we start listening would mean not seeing the lookup, which is
        // exactly the failure this harness had before.
        // Spawned and **not** awaited: awaiting here would block the read loop
        // for the length of the admin call, which is exactly the race that
        // stopped the lookup from ever being answered. The answer is collected
        // after the loop.
        let ask = tokio::spawn(ask_go_about_us(our_pk));

        // Generous, and it stays in place because the report at the end says
        // what did *not* arrive: a second bloom, or a session. Both are open
        // gaps in the evidence (`src/bloom.rs`, and the session formats in
        // `docs/protocol/README.md`), and a capture that silently printed
        // nothing would hide them.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        let mut got = 0;
        let mut blooms = 0;
        let mut seen_session = false;
        let mut notified = 0u32;
        while let Ok(Some((raw, ftype, payload))) =
            tokio::time::timeout_at(deadline, read_frame_raw(&mut rhalf)).await
        {
            got += 1;
            if ftype == FrameType::BloomFilter {
                blooms += 1;
            }
            println!(
                "{:?} payload={} raw={}",
                ftype,
                hex::encode(&payload),
                hex::encode(&raw)
            );
            // Answer a `PathLookup` for us, which is what makes us reachable.
            //
            // This is Go's own `_handleLookup` reply, field for field
            // (`pathfinder.go:53-85`): the path we hand back is the one the
            // lookup arrived on, the watermark is the maximum so no cheaper
            // route can pre-empt it, and the signed `info` carries **our own**
            // path — which is empty, because we are our own root (our announce
            // sets `parent == key`, the shape `Announce::check` requires of a
            // node with no upstream).
            //
            // Without this the pathfinder has no `paths[us]` entry, so every
            // `WriteTo` for us is answered by `_rumorSendLookup` and nothing is
            // ever delivered — silently, since `_sendReq` discards its error
            // (`nodeinfo.go:113`).
            if ftype == FrameType::PathLookup {
                match roots::pathfind::PathLookup::decode_exact(&payload) {
                    Ok(lookup) => {
                        let mut info = roots::pathfind::NotifyInfo {
                            seq: std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .map(|d| d.as_secs())
                                .unwrap_or(0),
                            path: Vec::new(),
                            sig: [0u8; 64],
                        };
                        info.sign(&our_sk);
                        let notify = roots::pathfind::PathNotify {
                            path: lookup.from.clone(),
                            watermark: u64::MAX,
                            source: our_pk,
                            dest: lookup.source,
                            info,
                        };
                        assert!(
                            notify.check(),
                            "our own PathNotify must satisfy our own checker"
                        );
                        let mut bytes = Vec::new();
                        notify.encode(&mut bytes);
                        println!("ours(PathNotify) {}", hex::encode(&bytes));
                        let mut w = whalf.lock().await;
                        roots::link::write_frame_to(&mut *w, FrameType::PathNotify, &bytes)
                            .await
                            .expect("send a PathNotify");
                        notified += 1;
                    }
                    Err(e) => println!("(path lookup decode failed: {e})"),
                }
            }
            // A session rides inside a `Traffic` frame: there is no session
            // frame type, because the path-encrypted `Traffic` payload *is* the
            // session message (`encrypted/packetconn.go:66-84` →
            // `network/packetconn.go:72-93`). Its payload is sealed to *our* box
            // key, which we hold, so unlike a peer's we can read it.
            if ftype == FrameType::Traffic {
                seen_session = true;
                match roots::traffic::Traffic::decode(&payload) {
                    Ok(tr) => {
                        println!(
                            "GO_SESSION src={} n={}",
                            hex::encode(tr.source),
                            tr.payload.len()
                        );
                        println!("GO_SESSION_HEX {}", hex::encode(&tr.payload));
                    }
                    Err(e) => println!("(traffic decode failed: {e})"),
                }
            }
        }
        if got == 0 {
            println!("(no frame arrived within the window)");
        }
        if blooms < 2 {
            println!("(only {blooms} bloom(s): Go's filter is still empty, so the");
            println!(" flag bit order stays pinned by a generator vector — see");
            println!(" `the_flag_layout_is_flags_then_data` in src/bloom.rs)");
        }
        if !seen_session {
            println!("(no Traffic frame: no session was opened, so no session bytes)");
        }
        if notified == 0 {
            println!("(no PathLookup answered: Go had no path to us, so it never");
            println!(" asked for one — check that it learned our key at all)");
        }
        keepalive.abort();
        // The admin answer last: it is the *result* of the exchange above, so
        // printing it before the loop would claim an outcome that had not
        // happened yet.
        match ask.await {
            Ok(Ok(answer)) => println!("GO_ADMIN getNodeInfo {answer}"),
            Ok(Err(e)) => println!("(getNodeInfo did not answer: {e})"),
            Err(e) => println!("(getNodeInfo task failed: {e})"),
        }
    }

    theirs
}

#[tokio::main]
async fn main() {
    let frames = std::env::args().skip(1).any(|a| a == "--frames");
    assert_private_netns();
    ensure_loopback();
    let unkeyed = capture("", PORTS[0], false).await;
    let keyed = capture(PASSWORD, PORTS[1], frames).await;
    assert_ne!(unkeyed, keyed, "the password must change the signature");
    println!("=== paste into tests/go_vectors.rs ===");
    println!("GO_META_UNKEYED: {}", hex::encode(&unkeyed));
    println!("GO_META_KEYED:   {}", hex::encode(&keyed));
}
