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
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use roots::frame::{self, FrameType};
use roots::handshake::{HEADER_LEN, Meta};

/// The oracle: a Nix store binary, no Go toolchain involved.
const GO_BIN: &str = "/run/current-system/sw/bin/yggdrasil";
/// Both ports are only reachable inside our own namespace, so a fixed pair is
/// safer than a free-port hunt (the config has to name the port up front).
const PORTS: [u16; 2] = [17777, 17778];
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
        r#"{{"PrivateKey":"{priv_hex}","Listen":["{listen}"],"Peers":[],"InterfacePeers":{{}},"AllowedPublicKeys":[],"MulticastInterfaces":[],"AdminListen":"","IfName":"auto","IfMTU":65535,"NodeInfoPrivacy":true,"NodeInfo":{{}}}}"#
    )
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
        .args(["-useconf", "-loglevel", "error"])
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
async fn read_frame_raw(stream: &mut TcpStream) -> Option<(Vec<u8>, FrameType, Vec<u8>)> {
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

        // Answer Go's `Announce` with one of our own, so Go accepts us as a tree
        // peer rather than dropping the link for want of an upstream. Built by
        // hand rather than by a router because this harness is the byte-level
        // oracle and a router in the loop would make the capture depend on the
        // thing under test.
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
        // We are our own parent, since we have no upstream: the same shape as
        // the root announce Go sent us, and `Announce::check` requires exactly
        // this (`port == 0 && key == parent`).
        //
        // So `psig` is signed over *our* key as both `node` and `parent` — which
        // is not the preimage of the `SigRes` Go sent us above. That one is
        // signed over (our key, Go's key), because Go answers a request with a
        // preimage naming the *requester* (`network/router.go:412`). An announce
        // carries a `SigRes` about its own `key`, and a node with no upstream
        // answers its own request.
        let sigreq = roots::tree::SigReq { seq: 1, nonce: 0 };
        let sigres = roots::tree::SigRes::seal(sigreq, 0, &our_pk, &our_sk, &our_pk);
        // The outer `sig` covers the same preimage as `psig` — node ‖ parent ‖
        // req ‖ port — signed by the announcer rather than by the parent
        // (`Announce::check` verifies both over `res.bytes_for_sig`).
        let preimage = sigres.bytes_for_sig(&our_pk, &our_pk);
        let ann = roots::tree::Announce {
            key: our_pk,
            parent: our_pk,
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

        println!("=== frames from Go ===");
        // Generous, and it stays in place because the report at the end says
        // what did *not* arrive: a second bloom, or a session. Both are open
        // gaps in the evidence (`src/bloom.rs`, and the session formats in
        // `docs/protocol/README.md`), and a capture that silently printed
        // nothing would hide them.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        let mut got = 0;
        let mut blooms = 0;
        let mut seen_session = false;
        while let Ok(Some((raw, ftype, payload))) =
            tokio::time::timeout_at(deadline, read_frame_raw(&mut stream)).await
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
