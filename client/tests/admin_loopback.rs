//! The admin socket's framing, checked against bytes captured from a real Go
//! 0.5.14 node (`docs/protocol/21-admin.md`, Slice 7).
//!
//! Six claims, all of them loopback:
//! 1. both transports Go's `AdminListen` understands answer identically, and the
//!    socket file gets Go's mode;
//! 2. a body keeps Go's struct field order, which a `serde_json::Value` would
//!    have silently sorted;
//! 3. `keepalive` is what keeps a connection open — and it is the only thing;
//! 4. the error strings are Go's verbatim, including the shape of the echoed
//!    request when decoding never got that far;
//! 5. a peer is reported by its link URI, so a `?password=` never comes back out;
//! 6. an argument of the wrong JSON type is refused in Go's own words, before
//!    the command runs.

use std::os::unix::fs::PermissionsExt;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use roots_client::admin::{Bound, bind_admin, serve_admin};
use roots_client::node::{Cmd, Node};
use serde_json::Value;
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
        let tx = spawn_node().await;
        let bound = bind_admin("tcp://127.0.0.1:0")
            .await
            .expect("bind_admin")
            .expect("a real address was asked for");
        let addr = bound.addr();
        tokio::spawn(serve_admin(bound, tx));
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
        tokio::spawn(serve_admin(bound, tx));
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
    assert_eq!(body["response"]["list"].as_array().map(Vec::len), Some(8));

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
