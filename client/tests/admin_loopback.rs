//! The admin socket's framing, checked against bytes captured from a real Go
//! 0.5.14 node (`docs/protocol/21-admin.md`, Slice 7).
//!
//! Eight claims, all of them loopback:
//! 1. both transports Go's `AdminListen` understands answer identically, and the
//!    socket file gets Go's mode;
//! 2. a body keeps Go's struct field order, which a `serde_json::Value` would
//!    have silently sorted;
//! 3. `keepalive` is what keeps a connection open — and it is the only thing;
//! 4. the error strings are Go's verbatim, including the shape of the echoed
//!    request when decoding never got that far;
//! 5. a peer is reported by its link URI, so a `?password=` never comes back out;
//! 6. an argument of the wrong JSON type is refused in Go's own words, before
//!    the command runs;
//! 7. `getPeers` prints Go's `PeerEntry` fields — all sixteen of them, and only
//!    the ones its `omitempty` tags do not hide;
//! 8. `getMulticastInterfaces` reports the multicast task's table, with `-` for an
//!    interface nothing is listening on and a bool rather than a password.
//!
//! The three `sort` modes are proved in `admin.rs`'s own tests instead: they need
//! rows whose cost, uptime and direction are chosen, which no loopback mesh can
//! be asked to arrange.

use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use roots::LinkOptions;
use roots_client::admin::{Bound, bind_admin, serve_admin};
use roots_client::listen::spawn_listeners;
use roots_client::multicast::{InterfaceTable as MulticastTable, MulticastInterfaceState};
use roots_client::node::{Cmd, Node};
use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UnixStream};
use tokio::sync::mpsc;

/// A node with nothing to do but answer the socket, which is all the socket is
/// allowed to talk to: every answer arrives as a `Cmd`.
async fn spawn_node() -> mpsc::UnboundedSender<Cmd> {
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let (mut node, tx) = Node::new(key);
    tokio::spawn(async move {
        let _ = node.run().await;
    });
    tx
}

/// A socket bound for one test, with its serving task already running. `addr`
/// is the connect target: `127.0.0.1:PORT` for TCP, the path for a Unix socket.
struct Server {
    addr: String,
}

impl Server {
    async fn tcp() -> Self {
        Self::on(spawn_node().await).await
    }

    /// A socket on top of a node the caller drives, for the tests that need a
    /// peer to report on rather than an empty table.
    async fn on(tx: mpsc::UnboundedSender<Cmd>) -> Self {
        Self::with_table(tx, roots_client::multicast::empty_table()).await
    }

    /// A socket whose multicast table the caller can fill, for
    /// `getMulticastInterfaces`.
    async fn with_table(tx: mpsc::UnboundedSender<Cmd>, ifaces: MulticastTable) -> Self {
        let bound = bind_admin("tcp://127.0.0.1:0")
            .await
            .expect("bind_admin")
            .expect("a real address was asked for");
        let addr = bound.addr();
        tokio::spawn(serve_admin(bound, tx, ifaces));
        Self { addr }
    }

    async fn unix(tag: &str) -> Self {
        let path = format!("/tmp/roots-admin-{tag}-{}.sock", std::process::id());
        let _ = std::fs::remove_file(&path);
        let tx = spawn_node().await;
        let bound = bind_admin(&format!("unix://{path}"))
            .await
            .expect("bind_admin")
            .expect("a path was asked for");
        assert!(
            matches!(bound, Bound::Unix(_)),
            "unix:// must bind a unix socket"
        );
        tokio::spawn(serve_admin(
            bound,
            tx,
            roots_client::multicast::empty_table(),
        ));
        Self { addr: path }
    }

    fn host(&self) -> String {
        self.addr.clone()
    }

    async fn connect(&self) -> TcpStream {
        TcpStream::connect(self.host()).await.expect("connect")
    }

    async fn connect_unix(&self) -> UnixStream {
        UnixStream::connect(self.host())
            .await
            .expect("connect unix")
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        if self.addr.ends_with(".sock") {
            let _ = std::fs::remove_file(&self.addr);
        }
    }
}

/// Accumulator for a stream we intend to read several values from. Generic over
/// the transport on purpose: the point of one of these tests is that the two
/// transports Go serves are interchangeable.
struct Reader<S> {
    sock: S,
    buf: Vec<u8>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Reader<S> {
    fn new(sock: S) -> Self {
        Self {
            sock,
            buf: Vec::new(),
        }
    }

    async fn send(&mut self, req: &str) {
        self.sock.write_all(req.as_bytes()).await.expect("write");
        self.sock.flush().await.expect("flush");
    }

    /// One request in, one value back, on a connection that stays open.
    async fn ask(&mut self, req: &str) -> Vec<u8> {
        self.send(req).await;
        self.frame(req).await
    }

    /// One value off the wire, however the bytes were split — the same framing
    /// the server itself uses.
    async fn frame(&mut self, asked: &str) -> Vec<u8> {
        loop {
            if let Some(end) = complete_value(&self.buf) {
                let frame = self.buf[..end].to_vec();
                self.buf.drain(..end);
                return frame;
            }
            let mut scratch = [0u8; 4096];
            let n = tokio::time::timeout(Duration::from_secs(5), self.sock.read(&mut scratch))
                .await
                .unwrap_or_else(|_| panic!("the socket never answered {asked:?}"))
                .expect("read");
            assert_ne!(n, 0, "the socket closed before answering {asked:?}");
            self.buf.extend_from_slice(&scratch[..n]);
        }
    }

    /// The answer after the last answer: Go closes, so there is nothing to read.
    async fn expect_closed(&mut self) {
        let mut scratch = [0u8; 64];
        let n = tokio::time::timeout(Duration::from_secs(5), self.sock.read(&mut scratch))
            .await
            .expect("the socket stayed open past a request with no keepalive")
            .expect("read");
        assert_eq!(n, 0, "the server sent a second value nobody asked for");
    }
}

fn complete_value(buf: &[u8]) -> Option<usize> {
    let mut de = serde_json::Deserializer::from_slice(buf).into_iter::<Value>();
    match de.next() {
        Some(Ok(_)) => Some(de.byte_offset()),
        Some(Err(e)) if e.is_eof() || e.is_io() => None,
        Some(Err(e)) => panic!("the socket wrote junk: {e}"),
        None => None,
    }
}

/// Go's `json.Encoder` output is UTF-8; say so once instead of at every use.
fn pretty(frame: &[u8]) -> String {
    String::from_utf8(frame.to_vec()).expect("utf-8")
}

/// Do these keys appear in this order in the raw bytes? Checking the text
/// rather than a parsed `Value` is the point — a parse is what loses the order.
fn in_order(text: &str, keys: &[&str]) -> bool {
    let mut at = 0usize;
    keys.iter()
        .all(|k| match text[at..].find(&format!("\"{k}\"")) {
            Some(i) => {
                at += i + k.len() + 2;
                true
            }
            None => false,
        })
}

#[tokio::test]
async fn admin_unix_socket_matches_tcp() {
    let tcp = Server::tcp().await;
    let unix = Server::unix("same").await;

    let mut over_tcp = Reader::new(tcp.connect().await);
    let mut over_unix = Reader::new(unix.connect_unix().await);
    let one = over_tcp.ask(r#"{"request":"list"}"#).await;
    let two = over_unix.ask(r#"{"request":"list"}"#).await;
    assert_eq!(
        pretty(&one),
        pretty(&two),
        "the transport must not change what the socket says"
    );
    let body: Value = serde_json::from_slice(&one).expect("one value");
    assert_eq!(body["status"], "success");
    // Thirteen: Slice 9 added `getNodeInfo` and the three `debug_remoteGet*`
    // (`core/api.go:239-259`) and Slice 11 added `getMulticastInterfaces`
    // (`multicast/admin.go:56`). Go's own fourteen are those plus `getTun`
    // (`tun/admin.go:31`), which needs a kernel interface and arrives with
    // Slice 14.
    assert_eq!(body["response"]["list"].as_array().map(Vec::len), Some(13));

    // Go's `os.Chmod(path, 0660)` (`admin.go:118`).
    let mode = std::fs::metadata(unix.host())
        .expect("socket file")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o660, "socket file mode");

    // Go's two spellings for "no admin socket at all".
    assert!(bind_admin("none").await.expect("none").is_none());
    assert!(bind_admin("").await.expect("empty").is_none());
}

#[tokio::test]
async fn admin_body_field_order_matches_go() {
    let server = Server::tcp().await;
    let mut reader = Reader::new(server.connect().await);
    reader.send(r#"{"request":"getSelf"}"#).await;
    let text = pretty(&reader.frame("getSelf").await);
    // Go's `AdminSocketResponse` then `GetSelfResponse` (`admin.go:37-42`,
    // `getself.go:12-19`): the envelope first, then build → key → address →
    // routing entries → subnet. Alphabetical would put `address` on top.
    assert!(
        in_order(
            &text,
            &[
                "status",
                "request",
                "response",
                "build_name",
                "build_version",
                "key",
                "address",
                "routing_entries",
                "subnet",
            ]
        ),
        "the response body is not in Go's field order:\n{text}"
    );
}

#[tokio::test]
async fn admin_keepalive_honours_second_request() {
    let server = Server::tcp().await;
    let mut reader = Reader::new(server.connect().await);
    // Two values in one write, the first asking to be kept alive.
    reader
        .send(r#"{"request":"list","keepalive":true}{"request":"getSelf","arguments":{}}"#)
        .await;

    let one: Value = serde_json::from_slice(&reader.frame("list").await).expect("first value");
    assert_eq!(one["status"], "success");
    assert_eq!(one["request"]["request"], "list");
    assert_eq!(
        one["request"]["keepalive"], true,
        "the echo keeps keepalive"
    );

    // The second answer only arrives because the first asked for it.
    let two: Value = serde_json::from_slice(&reader.frame("getSelf").await).expect("second value");
    assert_eq!(two["status"], "success");
    assert_eq!(two["request"]["request"], "getSelf");
    assert!(
        two["request"].get("arguments").is_some(),
        "a decoded request echoes its arguments, even an empty one: {}",
        serde_json::to_string_pretty(&two["request"]).unwrap()
    );
    // The second request had no keepalive, so the loop ends there.
    reader.expect_closed().await;

    // The control: the very first request, sent alone, closes the connection.
    let mut alone = Reader::new(server.connect().await);
    alone.send(r#"{"request":"list"}"#).await;
    let frame = alone.frame("list").await;
    assert_eq!(
        serde_json::from_slice::<Value>(&frame).expect("value")["request"]["request"],
        "list"
    );
    alone.expect_closed().await;
}

/// Each row is a request, the `error` Go answers with, and whether Go's echo
/// carries an `arguments` key. Every string and shape here was read off a real
/// node's socket, not written from the docs.
#[tokio::test]
async fn admin_error_strings_match_go() {
    let server = Server::tcp().await;
    let cases: &[(&str, &str, bool)] = &[
        (r#"{"request":""}"#, "no request specified", true),
        ("not json at all", "failed to find request", false),
        (r#"{"request":[1,2]}"#, "failed to unmarshal request", false),
        (
            r#"{"request":"NoSuchThing"}"#,
            "unknown action 'nosuchthing', try 'list' for help",
            true,
        ),
        (
            r#"{"request":"addPeer","arguments":{"uri":"bogus://x"}}"#,
            "link schema unknown",
            true,
        ),
        (
            r#"{"request":"removePeer","arguments":{"uri":"tcp://127.0.0.1:43999"}}"#,
            "peer is not configured",
            true,
        ),
    ];
    for (req, want, echo_args) in cases {
        let mut reader = Reader::new(server.connect().await);
        reader.send(req).await;
        let frame = reader.frame(req).await;
        let text = pretty(&frame);
        let body: Value = serde_json::from_slice(&frame).expect("one value");
        assert_eq!(body["status"], "error", "for {req}");
        assert_eq!(body["error"], *want, "for {req}");
        assert_eq!(
            body["response"],
            Value::Null,
            "a failed request answers `response: null`, for {req}"
        );
        assert_eq!(
            body["request"].get("arguments").is_some(),
            *echo_args,
            "arguments echo for {req}: {text}"
        );
        // `response` has no `omitempty` in Go, so the key is on the wire even
        // when it is null — which is what the raw bytes show.
        assert!(text.contains("\"response\": null"), "for {req}");
        reader.expect_closed().await;
    }

    // One connection for the rest, kept alive by every request on it.
    let mut reader = Reader::new(server.connect().await);

    // The unknown action keeps the operator's case in the echo and lowercases
    // only inside the message (`admin.go:334-336`).
    reader
        .send(r#"{"request":"NoSuchThing","keepalive":true}"#)
        .await;
    let text = pretty(&reader.frame("NoSuchThing").await);
    assert!(
        text.contains(r#""request": "NoSuchThing""#),
        "echo lost the operator's case: {text}"
    );

    // An oversize password is refused by the URI parser, before any connection
    // is attempted — Go's gate is `len(p) > blake2b.Size` (`link.go:200-206`),
    // and `links.add` returns it to the caller rather than logging it.
    let too_long = "p".repeat(roots::handshake::MAX_PASSWORD_LEN + 1);
    reader
        .send(&format!(
            r#"{{"request":"addPeer","arguments":{{"uri":"tcp://127.0.0.1:43100?password={too_long}"}},"keepalive":true}}"#
        ))
        .await;
    let frame = reader.frame("bad password").await;
    assert_eq!(
        serde_json::from_slice::<Value>(&frame).expect("value")["error"],
        "invalid password supplied",
        "a refused URI option must come back as an error, not a success: {}",
        pretty(&frame)
    );
    // A bad priority is the same story, and a `0` priority is not.
    reader
        .send(r#"{"request":"addPeer","arguments":{"uri":"tcp://127.0.0.1:43100?priority=999"},"keepalive":true}"#)
        .await;
    let frame = reader.frame("bad priority").await;
    assert_eq!(
        serde_json::from_slice::<Value>(&frame).expect("value")["error"],
        "priority value is invalid"
    );

    // Two identical dials: the second is a kick, not a second link
    // (`link.go:766-769`).
    reader
        .send(
            r#"{"request":"addPeer","arguments":{"uri":"tcp://127.0.0.1:43101"},"keepalive":true}"#,
        )
        .await;
    let first = reader.frame("addPeer").await;
    assert_eq!(
        serde_json::from_slice::<Value>(&first).expect("value")["status"],
        "success",
        "{}",
        pretty(&first)
    );
    reader
        .send(r#"{"request":"addPeer","arguments":{"uri":"tcp://127.0.0.1:43101"}}"#)
        .await;
    let again = reader.frame("addPeer again").await;
    let body: Value = serde_json::from_slice(&again).expect("value");
    assert_eq!(body["error"], "peer is already configured");
    assert_eq!(body["status"], "error");
    // An error does not end a kept-alive connection, so all of that arrived on
    // one socket — and the last request, with no keepalive, closed it.
    reader.expect_closed().await;
}

/// `getPeers` reports the *link* URI, which is the operator's URI with its query
/// blanked. Found by the live Go byte diff, and worth a test of its own because
/// the field that leaks is a secret: `?password=` is in the configured URI, and
/// Go's `PeerInfo.URI` comes from the map key, which went through
/// `urlForLinkInfo` (`core/api.go:83`, `link.go:766-769`).
#[tokio::test]
async fn admin_getpeers_reports_the_link_uri_not_the_operators() {
    let server = Server::tcp().await;
    let mut reader = Reader::new(server.connect().await);

    reader
        .send(
            r#"{"request":"addPeer","arguments":{"uri":"tcp://127.0.0.1:43102?password=s3cr3t"},"keepalive":true}"#,
        )
        .await;
    assert_eq!(
        serde_json::from_slice::<Value>(&reader.frame("addPeer").await).expect("value")["status"],
        "success"
    );

    reader
        .send(r#"{"request":"getPeers","keepalive":true}"#)
        .await;
    let frame = reader.frame("getPeers").await;
    let text = pretty(&frame);
    let body: Value = serde_json::from_slice(&frame).expect("value");
    let peers = &body["response"]["peers"];
    assert_eq!(peers[0]["remote"], "tcp://127.0.0.1:43102", "{text}");
    assert!(
        !text.contains("s3cr3t"),
        "the peering password came back over the socket: {text}"
    );
    assert_eq!(
        peers[0]["up"], false,
        "nothing listens on 43102, so the link is configured and down: {text}"
    );
    assert_eq!(
        peers[0]["key"], "",
        "a peer the router never adopted has no node key, as in Go: {text}"
    );

    // Removing it takes it out of the answer, and `peers` stays an array rather
    // than becoming null (`getPeersHandler` makes a zero-length slice). Note the
    // URI has no query here: the entry was configured with one, and `remove`
    // matches on `link_id` the way `add` does (`link.go:236-245`, `419-445`).
    reader
        .send(r#"{"request":"removePeer","arguments":{"uri":"tcp://127.0.0.1:43102"},"keepalive":true}"#)
        .await;
    assert_eq!(
        serde_json::from_slice::<Value>(&reader.frame("removePeer").await).expect("value")["status"],
        "success"
    );
    reader.send(r#"{"request":"getPeers"}"#).await;
    let text = pretty(&reader.frame("getPeers after remove").await);
    assert!(
        text.contains(r#""peers": []"#),
        "an empty peer list is not a null one: {text}"
    );
    reader.expect_closed().await;
}

/// Every handler unmarshals `arguments` into its own request struct before the
/// command runs (`admin.go:162-169`), so a wrongly-typed argument is refused in
/// Go's `json.UnmarshalTypeError` words — and refused *before* the link layer
/// sees the URI. Found by the byte diff in `proof/7-admin-raw.sh`: we used to
/// hand arguments to the commands and let each one ignore what it did not read.
#[tokio::test]
async fn admin_argument_types_match_go() {
    let server = Server::tcp().await;
    let cases: &[(&str, &str)] = &[
        (
            r#"{"request":"getSelf","arguments":"notanobject"}"#,
            "json: cannot unmarshal string into Go value of type admin.GetSelfRequest",
        ),
        (
            r#"{"request":"getTree","arguments":5}"#,
            "json: cannot unmarshal number into Go value of type admin.GetTreeRequest",
        ),
        (
            r#"{"request":"getSessions","arguments":false}"#,
            "json: cannot unmarshal bool into Go value of type admin.GetSessionsRequest",
        ),
        (
            r#"{"request":"getPeers","arguments":{"sort":123}}"#,
            "json: cannot unmarshal number into Go struct field GetPeersRequest.sort of type string",
        ),
        (
            r#"{"request":"addPeer","arguments":{"uri":123}}"#,
            "json: cannot unmarshal number into Go struct field AddPeerRequest.uri of type string",
        ),
    ];
    for (req, want) in cases {
        let mut reader = Reader::new(server.connect().await);
        reader.send(req).await;
        let frame = reader.frame(req).await;
        let body: Value = serde_json::from_slice(&frame).expect("one value");
        assert_eq!(body["status"], "error", "for {req}: {}", pretty(&frame));
        assert_eq!(body["error"], *want, "for {req}");
        // The arguments are echoed as they arrived, and the command ran nowhere.
        assert_eq!(
            body["request"]["arguments"],
            serde_json::from_str::<Value>(req)
                .expect("object")
                .get("arguments")
                .cloned()
                .expect("arguments"),
            "the echo must be the operator's own bytes for {req}"
        );
        reader.expect_closed().await;
    }

    // A bad `interface` is refused with the URI still unread: the peer must not
    // exist afterwards, so the error really did come before the link layer.
    let mut reader = Reader::new(server.connect().await);
    reader
        .send(r#"{"request":"addPeer","arguments":{"uri":"tcp://127.0.0.1:43103","interface":5},"keepalive":true}"#)
        .await;
    let frame = reader.frame("bad interface").await;
    assert_eq!(
        serde_json::from_slice::<Value>(&frame).expect("value")["error"],
        "json: cannot unmarshal number into Go struct field AddPeerRequest.interface of type string",
        "{}",
        pretty(&frame)
    );
    reader
        .send(r#"{"request":"getPeers","keepalive":true}"#)
        .await;
    let frame = reader.frame("getPeers after a refused addPeer").await;
    assert_eq!(
        serde_json::from_slice::<Value>(&frame).expect("value")["response"]["peers"],
        Value::Array(Vec::new()),
        "a request refused for its argument types still added a peer: {}",
        pretty(&frame)
    );

    // The three shapes Go *accepts*, on the same socket.
    reader
        .send(r#"{"request":"getSelf","arguments":null,"keepalive":true}"#)
        .await;
    let frame = reader.frame("null arguments").await;
    let body: Value = serde_json::from_slice(&frame).expect("value");
    assert_eq!(
        body["status"],
        "success",
        "`null` unmarshals into a struct as a no-op: {}",
        pretty(&frame)
    );
    assert_eq!(
        body["request"]["arguments"],
        Value::Null,
        "an explicit null arguments echoes null, not the empty-object preset"
    );

    reader
        .send(r#"{"request":"list","arguments":"notanobject","keepalive":true}"#)
        .await;
    let body: Value =
        serde_json::from_slice(&reader.frame("list with junk arguments").await).expect("value");
    assert_eq!(
        body["status"], "success",
        "`list` discards its arguments (`admin.go:139`), so it cannot be given a bad one"
    );

    reader
        .send(r#"{"request":"addPeer","arguments":{"uri":"tcp://127.0.0.1:43103","bogus":[1],"interface":null}}"#)
        .await;
    let frame = reader.frame("unknown argument key").await;
    let body: Value = serde_json::from_slice(&frame).expect("value");
    assert_eq!(
        body["status"],
        "success",
        "an unknown key is not refused, and a null field is a no-op: {}",
        pretty(&frame)
    );
    // The peer really did get added, so this socket can end the conversation by
    // removing it — and a request with no `keepalive` closes it either way.
    reader.expect_closed().await;
    let mut reader = Reader::new(server.connect().await);
    reader
        .send(r#"{"request":"removePeer","arguments":{"uri":"tcp://127.0.0.1:43103"}}"#)
        .await;
    assert_eq!(
        serde_json::from_slice::<Value>(&reader.frame("removePeer").await).expect("value")["status"],
        "success"
    );
    reader.expect_closed().await;
}

/// Go's `PeerEntry` declaration order (`getpeers.go:22-37`). The order *is* the
/// protocol: `encoding/json` writes struct fields in the order they are declared,
/// so a body with the same keys in another order is a different answer.
const PEER_FIELDS: &[&str] = &[
    "remote",
    "up",
    "inbound",
    "address",
    "key",
    "port",
    "priority",
    "cost",
    "bytes_recvd",
    "bytes_sent",
    "rate_recvd",
    "rate_sent",
    "uptime",
    "latency",
    "last_error_time",
    "last_error",
];

/// Which of Go's fields a row printed, checked in order against the raw bytes.
/// A parsed `Value` has already lost the order — `preserve_order` is off — so the
/// text is the only witness. `omitempty` makes the *set* different per row, which
/// is why each row is checked against its own list rather than against all 16.
fn printed_fields(row: &Value, text: &str) -> Vec<&'static str> {
    for key in row.as_object().expect("a row is an object").keys() {
        assert!(
            PEER_FIELDS.contains(&key.as_str()),
            "getPeers invented a field {key} that Go does not have: {text}"
        );
    }
    let present: Vec<&'static str> = PEER_FIELDS
        .iter()
        .copied()
        .filter(|k| row.get(*k).is_some())
        .collect();
    assert!(
        in_order(text, &present),
        "getPeers fields are not in Go's order, which wants {present:?}: {text}"
    );
    present
}

/// Ask for `getPeers` until the answer holds exactly one row that `want` accepts,
/// and return it with the bytes it arrived in. One row on purpose: the order check
/// reads the whole frame, and a second row would put its keys in the way.
async fn ask_one_row<S>(reader: &mut Reader<S>, want: impl Fn(&Value) -> bool) -> (Value, String)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let end = Instant::now() + Duration::from_secs(10);
    loop {
        let frame = reader
            .ask(r#"{"request":"getPeers","keepalive":true}"#)
            .await;
        let text = pretty(&frame);
        let body: Value = serde_json::from_slice(&frame).expect("one value");
        assert_eq!(body["status"], "success", "{text}");
        let peers = body["response"]["peers"].as_array().expect("peers");
        if peers.len() == 1 && want(&peers[0]) {
            return (peers[0].clone(), text);
        }
        assert!(
            Instant::now() < end,
            "timed out waiting for the row I asked about: {text}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// The whole `PeerEntry` field set, on two rows that between them cover every
/// field: a dial that cannot succeed (error, age, nothing else) and a live link
/// (bytes, rates, uptime, latency, address). `rate_recvd`, `rate_sent` and
/// `latency` were the gap Slice 7 left: the library measured no throughput,
/// stamped no error moment and kept no round trip, so there was nothing true to
/// print.
#[tokio::test]
async fn admin_getpeers_reports_every_field_go_does() {
    // B has no socket and nothing to do but be dialled.
    let b_sk = SigningKey::from_bytes(&[0xB0; 32]);
    let b_key = b_sk.verifying_key().to_bytes();
    let (mut b, b_tx) = Node::new(b_sk.clone());
    let served = spawn_listeners(
        &b_sk,
        &LinkOptions::default(),
        &["tcp://127.0.0.1:0".to_string()],
        &b_tx,
    )
    .await
    .expect("B binds a listener")[0]
        .clone();
    tokio::spawn(async move {
        let _ = b.run().await;
    });

    let (mut a, tx) = Node::new(SigningKey::from_bytes(&[0xA0; 32]));
    let server = Server::on(tx.clone()).await;
    tokio::spawn(async move {
        let _ = a.run().await;
    });
    let mut reader = Reader::new(server.connect().await);

    // Phase one: nothing listens on port 1, so this row is all failure.
    reader
        .send(r#"{"request":"addPeer","arguments":{"uri":"tcp://127.0.0.1:1"},"keepalive":true}"#)
        .await;
    reader.frame("addPeer").await;
    let (row, text) = ask_one_row(&mut reader, |r| r["last_error"].is_string()).await;
    assert_eq!(row["up"], false, "{text}");
    assert_eq!(row["inbound"], false, "{text}");
    assert_eq!(
        row["key"], "",
        "`key` has no `omitempty` in Go, so a row with no node key prints an empty one"
    );
    assert_eq!(
        row["address"],
        Value::Null,
        "and `address` does, so the same row omits it: {text}"
    );
    assert!(
        row["last_error_time"].as_u64().is_some_and(|n| n > 0),
        "Go prints the error's age as a `time.Duration` in exact nanoseconds: {text}"
    );
    assert_eq!(
        printed_fields(&row, &text),
        [
            "remote",
            "up",
            "inbound",
            "key",
            "port",
            "priority",
            "cost",
            "last_error_time",
            "last_error",
        ],
        "a failed row prints exactly Go's non-zero fields, no more"
    );

    // Phase two: the dead row out of the way, and a live link in its place.
    reader
        .send(
            r#"{"request":"removePeer","arguments":{"uri":"tcp://127.0.0.1:1"},"keepalive":true}"#,
        )
        .await;
    reader.frame("removePeer").await;
    reader
        .send(&format!(
            r#"{{"request":"addPeer","arguments":{{"uri":"{served}"}},"keepalive":true}}"#
        ))
        .await;
    reader.frame("addPeer to B").await;
    let (row, text) = ask_one_row(&mut reader, |r| r["up"] == true).await;
    assert_eq!(row["remote"], served, "{text}");
    assert_eq!(row["inbound"], false, "we dialled this one: {text}");
    assert_eq!(row["key"], hex::encode(b_key), "{text}");
    assert_eq!(
        row["address"],
        roots::addr_for_key(&b_key).to_string(),
        "Go derives the address from the key in the same breath"
    );
    assert!(
        row["port"].as_u64().is_some_and(|p| p >= 1),
        "a registered peer has a port: {text}"
    );
    assert!(
        row["cost"].as_u64().is_some_and(|c| c >= 1),
        "Go floors the cost at one millisecond: {text}"
    );
    assert!(
        row["bytes_recvd"].as_u64().is_some_and(|b| b > 0)
            && row["bytes_sent"].as_u64().is_some_and(|b| b > 0),
        "the handshake and the tree chatter are counted both ways: {text}"
    );
    assert!(
        row["uptime"].as_f64().is_some_and(|u| u > 0.0 && u < 60.0),
        "`uptime` is Go's float64 seconds since the link came up: {text}"
    );
    let present = printed_fields(&row, &text);
    for must in [
        "remote",
        "up",
        "inbound",
        "address",
        "key",
        "port",
        "priority",
        "cost",
        "bytes_recvd",
        "bytes_sent",
        "uptime",
    ] {
        assert!(
            present.contains(&must),
            "a live row must print {must}: {text}"
        );
    }
    assert!(
        row.get("last_error").is_none(),
        "a healthy link has nothing to report, and must not print a stale one: {text}"
    );

    // The rates are Go's bytes-per-second counters, which the node fills as the
    // chatter arrives: asking again is how a row that never reports one is caught
    // rather than talked around. Each must be positive — the link is being served
    // — and cannot exceed the total it is a slice of.
    let (row, text) = ask_one_row(&mut reader, |r| {
        r.get("rate_recvd").is_some() && r.get("rate_sent").is_some()
    })
    .await;
    for (rate, total) in [("rate_recvd", "bytes_recvd"), ("rate_sent", "bytes_sent")] {
        let value = row[rate].as_u64().expect(rate);
        assert!(
            value > 0 && value <= row[total].as_u64().expect(total),
            "{rate} is the traffic since the last measure, so it is positive and no \
             larger than {total}: {text}"
        );
    }

    // `latency` is the last `SigReq` round trip, re-read at query time
    // (`debug.go:84-86`), so it is absent while a fresh request is in flight —
    // but it has to appear, or nobody ever measured one.
    let (row, text) = ask_one_row(&mut reader, |r| r.get("latency").is_some()).await;
    let latency = row["latency"].as_u64().expect("latency");
    assert!(
        latency > 0 && latency % 10_000 == 0,
        "Go rounds the round trip to hundredths of a millisecond: {text}"
    );
}

/// `getMulticastInterfaces` reads the multicast task's table and nothing else
/// (`multicast/admin.go:30-48`), so the claims here are about what it does and
/// does not do with a row.
///
/// Three of Go's details are easy to get wrong and each is asserted:
///   - the five fields are always present, because `MulticastInterfaceState` has
///     no `omitempty` (`multicast/admin.go:21-27`);
///   - an interface nothing is listening on reports `-`, not an empty string
///     (`multicast/admin.go:41`);
///   - `password` is a **bool**. Go answers `len(intf.password) > 0` and never
///     the password itself (`multicast/admin.go:44`), because the reader already
///     has the config file.
#[tokio::test]
async fn admin_getmulticastinterfaces_reports_the_table_and_no_passwords() {
    let ifaces: MulticastTable = roots_client::multicast::empty_table();
    *ifaces.lock().unwrap() = vec![
        // Two interfaces, given to the socket **out of name order**, because Go
        // sorts by name before answering (`multicast/admin.go:46-48`) and a map
        // is where an unsorted table would otherwise hide.
        MulticastInterfaceState {
            name: "wlan0".into(),
            address: "-".into(),
            beacon: true,
            listen: true,
            password: true,
        },
        MulticastInterfaceState {
            name: "eth0".into(),
            address: "[fe80::1%eth0]:9000".into(),
            beacon: true,
            listen: false,
            password: false,
        },
    ];
    let server = Server::with_table(spawn_node().await, ifaces).await;
    let mut reader = Reader::new(server.connect().await);

    let one = reader.ask(r#"{"request":"getMulticastInterfaces"}"#).await;
    let body: Value = serde_json::from_slice(&one).expect("one value");
    assert_eq!(body["status"], "success");
    let rows = body["response"]["multicast_interfaces"]
        .as_array()
        .expect("a list");
    assert_eq!(rows.len(), 2, "{one:?}");

    assert_eq!(rows[0]["name"], "eth0", "sorted by name: {one:?}");
    assert_eq!(
        rows[0]["address"], "[fe80::1%eth0]:9000",
        "the bound listener's own address"
    );
    assert_eq!(rows[0]["beacon"], true);
    assert_eq!(rows[0]["listen"], false);
    assert_eq!(
        rows[0]["password"], false,
        "`password` is a bool, never the password"
    );

    // Every field, every time, **in Go's declaration order**. The order has to
    // be checked on the raw bytes: reading the answer into a `serde_json::Value`
    // sorts the keys, because `serde_json::Map` is a `BTreeMap`. An assertion
    // made through a parsed value would pass on a body built from a map, which
    // is the mistake `docs/protocol/21-admin.md` warns about.
    let text = String::from_utf8(one.clone()).expect("utf-8");
    let at = |needle: &str| {
        text.find(needle)
            .unwrap_or_else(|| panic!("{needle:?} missing from {text}"))
    };
    let mut order: Vec<(&str, usize)> = [
        "\"name\"",
        "\"address\"",
        "\"beacon\"",
        "\"listen\"",
        "\"password\"",
    ]
    .into_iter()
    .map(|k| (k, at(k)))
    .collect();
    order.sort_by_key(|(_, at)| *at);
    assert_eq!(
        order.iter().map(|(k, _)| *k).collect::<Vec<_>>(),
        [
            "\"name\"",
            "\"address\"",
            "\"beacon\"",
            "\"listen\"",
            "\"password\""
        ],
        "Go's declaration order, all five, with nothing omitted: {text}"
    );

    assert_eq!(
        rows[1]["address"], "-",
        "Go's placeholder for an interface with no listener, not an empty \
         string: {one:?}"
    );
    assert_eq!(
        rows[1]["password"], true,
        "a set password is reported as true"
    );
}

/// A node whose multicast module never started — a host where the group bind
/// failed — still has the handler, because Go registers it unconditionally
/// (`multicast/admin.go:55-64`). The answer is an empty list, not an error.
#[tokio::test]
async fn admin_getmulticastinterfaces_on_a_node_with_no_module_is_empty() {
    let server = Server::tcp().await;
    let mut reader = Reader::new(server.connect().await);
    let one = reader.ask(r#"{"request":"getMulticastInterfaces"}"#).await;
    let body: Value = serde_json::from_slice(&one).expect("one value");
    assert_eq!(body["status"], "success", "{one:?}");
    assert_eq!(
        body["response"]["multicast_interfaces"],
        json!([]),
        "an empty list, not a null and not an error: {one:?}"
    );
}
