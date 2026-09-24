//! The admin socket: Go's `src/admin` framing, byte for byte.
//!
//! A connection is a stream of JSON values answered one-for-one
//! (`admin.go:307-360`), `keepalive` decides whether the loop runs again, and
//! the reply carries the request struct back in its `request` field.
//! Everything the socket says about the node arrives as a [`Cmd`], because only
//! the node task may read the router.
//!
//! Field order is part of the protocol: `encoding/json` writes struct order,
//! so every body here is a `struct` and never a `json!` map — a map would
//! serialise alphabetically, and `serde_json`'s `preserve_order` feature is off
//! deliberately ([`crate::config`] sorts its maps for the same reason).

use std::io;
use std::os::unix::fs::PermissionsExt;
use std::time::Duration;

use serde::Serialize;
use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, UnixListener, UnixStream};
use tokio::sync::{mpsc, oneshot};

use crate::node::{Cmd, Snapshot};

/// Go's four protocol-level strings (`admin.go:324-336`). Verbatim, including
/// the fact that the first one throws away whatever the decoder actually
/// complained about.
const FAILED_TO_FIND: &str = "failed to find request";
const FAILED_TO_UNMARSHAL: &str = "failed to unmarshal request";
const NO_REQUEST: &str = "no request specified";
fn unknown_action(name: &str) -> String {
    format!("unknown action '{name}', try 'list' for help")
}

/// A command name, its `list` description and its argument names — the exact
/// `AddHandler` triples from `admin.go:139-257`, lowercased because Go
/// registers and looks up with `strings.ToLower`. Sorted, because `list` sorts.
///
/// `getNodeInfo`, the three `debug_remote*` commands (`core/api.go:240-259`),
/// `getTun` (`tun/admin.go:31`) and `getMulticastInterfaces`
/// (`multicast/admin.go:50`) are missing from this table: their answers need
/// mesh round trips, a TUN and multicast state, so they arrive with Slices 9,
/// 14 and 11. `list` says what the node can do, so it says eight commands
/// rather than Go's fourteen.
const COMMANDS: &[(&str, &str, &[&str])] = &[
    (
        "addpeer",
        "Add a peer to the peer list",
        &["uri", "interface"],
    ),
    ("getpaths", "Show established paths through this node", &[]),
    ("getpeers", "Show directly connected peers", &["sort"]),
    (
        "getsessions",
        "Show established traffic sessions with remote nodes",
        &[],
    ),
    ("getself", "Show details about this node", &[]),
    ("gettree", "Show known Tree entries", &[]),
    ("list", "List available commands", &[]),
    (
        "removepeer",
        "Remove a peer from the peer list",
        &["uri", "interface"],
    ),
];

fn known(name: &str) -> bool {
    COMMANDS.iter().any(|(n, _, _)| *n == name)
}

/// The word Go's `json` package uses for a value's kind in an error message.
/// A float and an int are both `number`; only these five words appear.
fn go_kind(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// Check `arguments` the way Go's handler wrapper does, by unmarshalling it into
/// the command's own request struct before the command runs
/// (`admin.go:162-169`, `getself.go:13`, `getpeers.go:14-16`, `addpeer.go:8-11`).
/// A value that is not an object, or a known field that is not a string, is an
/// error whose text is Go's `json.UnmarshalTypeError` — reproduced verbatim,
/// including the package prefix on one form and its absence on the other,
/// because this is the text an operator's tool sees.
///
/// `list` is absent from the table because its handler discards its input
/// (`admin.go:139`, `func(_ json.RawMessage)`), so nothing it is handed can be
/// wrong.
fn decode_args(name: &str, args: &Value) -> Result<(), String> {
    // (Go's struct name, the string fields it declares).
    let (struct_name, fields): (&str, &[&str]) = match name {
        "getself" => ("GetSelfRequest", &[]),
        "gettree" => ("GetTreeRequest", &[]),
        "getpaths" => ("GetPathsRequest", &[]),
        "getsessions" => ("GetSessionsRequest", &[]),
        "getpeers" => ("GetPeersRequest", &["sort"]),
        "addpeer" => ("AddPeerRequest", &["uri", "interface"]),
        "removepeer" => ("RemovePeerRequest", &["uri", "interface"]),
        _ => return Ok(()),
    };
    let Some(map) = args.as_object() else {
        // `null` unmarshals into a struct as a no-op, which is why
        // `"arguments": null` succeeds and echoes `null`.
        if args.is_null() {
            return Ok(());
        }
        return Err(format!(
            "json: cannot unmarshal {} into Go value of type admin.{struct_name}",
            go_kind(args)
        ));
    };
    // Known fields in table order, which for `uri`/`interface` is Go's
    // declaration order and happens to be alphabetical too. Go reports the first
    // wrongly-typed field *in the order the operator wrote them*; our `Value`
    // map is sorted, so a request with two bad fields can name the other one.
    for field in fields {
        if let Some(value) = map.get(*field)
            && !value.is_null()
            && !value.is_string()
        {
            return Err(format!(
                "json: cannot unmarshal {} into Go struct field {struct_name}.{field} of type string",
                go_kind(value)
            ));
        }
    }
    Ok(())
}

/// Go's `AdminSocketRequest` (`admin.go:31-35`). `arguments` is a
/// `json.RawMessage` with `omitempty`: an *absent* key still echoes the `{}`
/// that Go pre-sets, and only an explicit `null` prints as `null`.
#[derive(Clone, Serialize)]
struct Request {
    request: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    arguments: Option<Value>,
    #[serde(skip_serializing_if = "is_false")]
    keepalive: bool,
}

/// Go's `AdminSocketResponse` (`admin.go:37-42`). `response` has no
/// `omitempty`: a failed request answers `"response": null`.
///
/// The body is [`Body`], not a `serde_json::Value`, which is the difference
/// between Go's bytes and wrong ones: `serde_json`'s `Map` is a `BTreeMap`
/// unless `preserve_order` is on, so a body that round trips through `Value`
/// comes back with its keys sorted alphabetically — `address` before
/// `build_name`. A diff against a real Go node's admin socket shows it.
#[derive(Serialize)]
struct Response<'a> {
    status: &'a str,
    #[serde(skip_serializing_if = "String::is_empty")]
    error: String,
    request: Request,
    response: Body,
}

/// Every body the socket can send, in one type: `dyn Serialize` is not
/// object-safe, so the erasure has to be an enum. Each arm serialises as its
/// own struct, so Go's field order survives to the wire.
enum Body {
    /// `json.RawMessage(nil)` — what Go sends when the handler never ran.
    Null,
    /// Go's `AddPeerResponse`/`RemovePeerResponse`: an empty struct, which is
    /// `{}` on the wire rather than `null`.
    Empty,
    List(ListResponse),
    Self_(GetSelfResponse<'static>),
    Peers(GetPeersResponse),
    Tree(GetTreeResponse),
    Paths(GetPathsResponse),
    Sessions(GetSessionsResponse),
}

impl Serialize for Body {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            Body::Null => s.serialize_unit(),
            Body::Empty => EmptyBody {}.serialize(s),
            Body::List(b) => b.serialize(s),
            Body::Self_(b) => b.serialize(s),
            Body::Peers(b) => b.serialize(s),
            Body::Tree(b) => b.serialize(s),
            Body::Paths(b) => b.serialize(s),
            Body::Sessions(b) => b.serialize(s),
        }
    }
}

/// Go's `AddPeerResponse`/`RemovePeerResponse`: an empty struct, which is `{}`
/// on the wire rather than `null`.
#[derive(Serialize)]
struct EmptyBody {}

fn is_false(v: &bool) -> bool {
    !*v
}

/// Go's `omitempty` for a number: zero disappears.
fn is_zero(v: &u64) -> bool {
    *v == 0
}

/// A stream the admin socket can serve: either transport Go's `AdminListen`
/// understands, boxed because a trait object is the only way to name both.
/// `Unpin` is a supertrait so `Box<dyn AdminStream>` may be read from and
/// written to without pinning it first — every real stream here is already
/// `Unpin`, so it costs nothing but names the bound the helpers need.
pub trait AdminStream: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> AdminStream for T {}

/// A bound admin socket, the way Go's `New` leaves one (`admin.go:114-130`).
pub enum Bound {
    Tcp(TcpListener),
    Unix(UnixListener),
}

impl Bound {
    /// Go's startup line prints `strings.ToUpper(network())` (`admin.go:136`).
    pub fn network(&self) -> &'static str {
        match self {
            Bound::Tcp(_) => "TCP",
            Bound::Unix(_) => "UNIX",
        }
    }

    /// What Go prints after the network: the listener's own address.
    pub fn addr(&self) -> String {
        match self {
            Bound::Tcp(l) => l
                .local_addr()
                .map(|a| a.to_string())
                .unwrap_or_else(|_| "<unknown>".into()),
            Bound::Unix(l) => l
                .local_addr()
                .ok()
                .and_then(|a| a.as_pathname().map(|p| p.display().to_string()))
                .unwrap_or_else(|| "<abstract>".into()),
        }
    }

    async fn accept(&self) -> io::Result<Box<dyn AdminStream>> {
        match self {
            Bound::Tcp(l) => l
                .accept()
                .await
                .map(|(sock, _)| Box::new(sock) as Box<dyn AdminStream>),
            Bound::Unix(l) => l
                .accept()
                .await
                .map(|(sock, _)| Box::new(sock) as Box<dyn AdminStream>),
        }
    }
}

/// Go's stale-socket probe timeout: `net.DialTimeout("unix", path, 2*time.Second)`.
const STALE_PROBE: Duration = Duration::from_secs(2);

/// Go's `AdminListen` scheme dispatch (`admin.go:83-130`), minus its
/// `os.Exit(1)`: `Ok(None)` means the option asked for no socket at all.
pub async fn bind_admin(uri: &str) -> Result<Option<Bound>, io::Error> {
    if uri == "none" || uri.is_empty() {
        return Ok(None);
    }
    let (scheme, rest) = split_scheme(uri);
    match scheme.as_str() {
        "unix" => bind_unix(rest).await.map(Some),
        // Go dials `u.Host`; a scheme-less address string goes to `net.Listen`
        // verbatim, so the two branches differ only in how they got here.
        "tcp" => TcpListener::bind(rest).await.map(|l| Some(Bound::Tcp(l))),
        _ => TcpListener::bind(uri).await.map(|l| Some(Bound::Tcp(l))),
    }
}

/// `url.Parse` + `strings.ToLower(u.Scheme)`, for the shapes a Go admin address
/// ever takes. Anything without a `://` separator has no scheme, which is Go's
/// default branch.
fn split_scheme(uri: &str) -> (String, &str) {
    match uri.split_once("://") {
        Some((scheme, rest)) => (scheme.to_lowercase(), rest),
        None => (String::new(), uri),
    }
}

/// Go's stale-socket dance (`admin.go:92-121`): a live listener is fatal, a
/// dead socket file is removed, and the new one gets mode 0660 — unless the
/// name is abstract, which has no file to chmod.
async fn bind_unix(path: &str) -> Result<Bound, io::Error> {
    let abstract_socket = path.starts_with('@');
    if !abstract_socket && std::fs::metadata(path).is_ok() {
        // A timeout means "somebody is in there but slow", which Go also treats
        // as in use (`admin.go:97-101`).
        let in_use = match tokio::time::timeout(STALE_PROBE, UnixStream::connect(path)).await {
            Ok(Ok(_)) | Err(_) => true,
            Ok(Err(_)) => false,
        };
        if in_use {
            return Err(io::Error::other(format!(
                "Admin socket {path} already exists and is in use by another process"
            )));
        }
        std::fs::remove_file(path)?;
    }
    let listener = UnixListener::bind(path)?;
    if !abstract_socket
        && let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))
    {
        // Go warns and carries on (`admin.go:117-120`).
        eprintln!("WARNING: {path} may have unsafe permissions! ({e})");
    }
    Ok(Bound::Unix(listener))
}

/// Accept forever: one task per connection, exactly Go's `listen`
/// (`admin.go:288-304`).
pub async fn serve_admin(bound: Bound, tx: mpsc::UnboundedSender<Cmd>) {
    loop {
        match bound.accept().await {
            Ok(sock) => {
                let tx = tx.clone();
                tokio::spawn(async move {
                    admin_conn(sock, tx).await;
                });
            }
            // Go keeps looping here without pausing, which turns a dead
            // listener into a spin; a short wait is the whole difference.
            Err(e) => {
                eprintln!("admin accept: {e}");
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
}

/// Serve one admin connection, in Go's `handleRequest` shape (`admin.go:307`):
/// decode a value, answer it, and stop only when the request did not ask to be
/// kept alive — including when answering it failed.
async fn admin_conn(mut sock: Box<dyn AdminStream>, tx: mpsc::UnboundedSender<Cmd>) {
    let mut buf = Vec::new();
    let mut at_eof = false;
    loop {
        let (outcome, echo, keepalive) = handle_one(&mut sock, &mut buf, &mut at_eof, &tx).await;
        let resp = match outcome {
            Ok(response) => Response {
                status: "success",
                error: String::new(),
                request: echo,
                response,
            },
            Err(error) => Response {
                status: "error",
                error,
                request: echo,
                response: Body::Null,
            },
        };
        if write_value(&mut sock, &resp).await.is_err() {
            break;
        }
        if !keepalive {
            break;
        }
    }
    // Go's `defer conn.Close()` — dropping the stream closes it too, but say it.
    let _ = sock.shutdown().await;
}

/// Decode one request and answer it, returning the reply alongside the request
/// struct to echo. Both start as Go's zero values, so a request that never
/// decodes is echoed as the bare `{"request":""}` with no `arguments` key at
/// all — `resp.Request` is assigned only after the unmarshal succeeds
/// (`admin.go:322-330`).
async fn handle_one(
    sock: &mut Box<dyn AdminStream>,
    buf: &mut Vec<u8>,
    at_eof: &mut bool,
    tx: &mpsc::UnboundedSender<Cmd>,
) -> (Result<Body, String>, Request, bool) {
    let zero = Request {
        request: String::new(),
        arguments: None,
        keepalive: false,
    };
    let value = match next_value(sock, buf, at_eof).await {
        Ok(Some(value)) => value,
        // Go throws the decoder's own complaint away and says `failed to find
        // request`, for a syntax error and for EOF alike.
        Ok(None) | Err(_) => return (Err(FAILED_TO_FIND.to_string()), zero, false),
    };
    let Some(echo) = parse_request(&value) else {
        return (Err(FAILED_TO_UNMARSHAL.to_string()), zero, false);
    };
    let keepalive = echo.keepalive;
    if echo.request.is_empty() {
        return (Err(NO_REQUEST.to_string()), echo, keepalive);
    }
    let name = echo.request.to_lowercase();
    if !known(&name) {
        return (Err(unknown_action(&name)), echo, keepalive);
    }
    let args = echo.arguments.clone().unwrap_or(Value::Null);
    // Go decodes the arguments before the command runs, so a request that
    // cannot decode never reaches the link layer.
    if let Err(error) = decode_args(&name, &args) {
        return (Err(error), echo, keepalive);
    }
    (dispatch(&name, &args, tx).await, echo, keepalive)
}

/// Go's `decoder.Decode(&buf)` then `json.Unmarshal(buf, &req)`: a bare JSON
/// value, then a struct decode that ignores keys it does not know and refuses
/// one whose type does not fit.
fn parse_request(value: &Value) -> Option<Request> {
    let obj = value.as_object()?;
    let request = match obj.get("request") {
        None | Some(Value::Null) => String::new(),
        Some(Value::String(s)) => s.clone(),
        Some(_) => return None,
    };
    let keepalive = match obj.get("keepalive") {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(_) => return None,
    };
    let mut req = Request {
        request,
        // Go sets `req.Arguments = []byte("{}")` before the decode, so an
        // absent key still echoes `{}`.
        arguments: Some(json!({})),
        keepalive,
    };
    if let Some(args) = obj.get("arguments") {
        req.arguments = Some(args.clone());
    }
    Some(req)
}

/// One request value off the stream: values may be split across reads, and
/// several may share one read. `Ok(None)` is a clean EOF; `Err` is any decoder
/// or read complaint, which Go collapses into the same `failed to find
/// request`.
async fn next_value<S: AsyncRead + Unpin + ?Sized>(
    sock: &mut S,
    buf: &mut Vec<u8>,
    at_eof: &mut bool,
) -> io::Result<Option<Value>> {
    let mut scratch = [0u8; 4096];
    loop {
        if let Some(value) = take_value(buf)? {
            return Ok(Some(value));
        }
        if *at_eof {
            return Ok(None);
        }
        match sock.read(&mut scratch).await {
            Ok(0) => *at_eof = true,
            Ok(n) => buf.extend_from_slice(&scratch[..n]),
            Err(e) => {
                *at_eof = true;
                return Err(e);
            }
        }
    }
}

/// Pull the first complete JSON value off `buf`, consuming it and any leading
/// whitespace. `Ok(None)` means the buffer holds nothing decidable yet.
fn take_value(buf: &mut Vec<u8>) -> io::Result<Option<Value>> {
    let start = buf
        .iter()
        .position(|b| !matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
        .unwrap_or(buf.len());
    if start == buf.len() {
        return Ok(None);
    }
    // A `StreamDeserializer` rather than a one-shot `from_slice` decode because
    // it reports how many bytes the value actually took, which is what lets
    // several requests share one read and one request span two.
    let mut de = serde_json::Deserializer::from_slice(&buf[start..]).into_iter::<Value>();
    match de.next() {
        Some(Ok(value)) => {
            let used = start + de.byte_offset();
            buf.drain(0..used);
            Ok(Some(value))
        }
        // Truncated input: the slice ran out of bytes mid-value. Go's decoder
        // reads more and tries again, so that is what we do.
        Some(Err(e)) if e.is_eof() || e.is_io() => Ok(None),
        Some(Err(e)) => Err(io::Error::other(e.to_string())),
        None => Ok(None),
    }
}

/// Go's `encoder.SetIndent("", "  ")` + `Encode`: `MarshalIndent` output plus
/// one trailing newline, one value per write.
async fn write_value<S: AsyncWrite + Unpin + ?Sized>(
    sock: &mut S,
    value: &impl Serialize,
) -> io::Result<()> {
    let mut bytes =
        serde_json::to_vec_pretty(value).map_err(|e| io::Error::other(e.to_string()))?;
    bytes.push(b'\n');
    sock.write_all(&bytes).await
}

/// Ask the node task for its state: a `Cmd` in, one `Snapshot` back.
async fn report(tx: &mpsc::UnboundedSender<Cmd>) -> Result<Snapshot, String> {
    let (wt, rr) = oneshot::channel();
    tx.send(Cmd::Report { respond: wt })
        .map_err(|_| "node is not running".to_string())?;
    rr.await.map_err(|_| "node did not answer".to_string())
}

async fn dispatch(
    name: &str,
    args: &Value,
    tx: &mpsc::UnboundedSender<Cmd>,
) -> Result<Body, String> {
    if name == "list" {
        return Ok(Body::List(list_body()));
    }
    if name == "addpeer" || name == "removepeer" {
        return change_peer(name, args, tx).await;
    }
    let snap = report(tx).await?;
    Ok(match name {
        "getself" => Body::Self_(get_self(&snap)),
        "getpeers" => Body::Peers(get_peers(&snap)),
        "gettree" => Body::Tree(get_tree(&snap)),
        "getpaths" => Body::Paths(get_paths(&snap)),
        "getsessions" => Body::Sessions(get_sessions(&snap)),
        _ => unreachable!("{name} is not in COMMANDS"),
    })
}

#[derive(Serialize)]
struct ListEntry {
    command: String,
    description: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    fields: Vec<String>,
}

#[derive(Serialize)]
struct ListResponse {
    list: Vec<ListEntry>,
}

fn list_body() -> ListResponse {
    // Go builds its rows off a map and sorts them (`admin.go:139-152`). The
    // table is already in name order; sorting anyway keeps the promise that
    // `list` is sorted however COMMANDS grows.
    let mut list: Vec<ListEntry> = COMMANDS
        .iter()
        .map(|(command, description, fields)| ListEntry {
            command: (*command).to_string(),
            description: (*description).to_string(),
            fields: fields.iter().map(|f| (*f).to_string()).collect(),
        })
        .collect();
    list.sort_by(|a, b| a.command.cmp(&b.command));
    ListResponse { list }
}

#[derive(Serialize)]
struct GetSelfResponse<'a> {
    build_name: &'a str,
    build_version: &'a str,
    key: String,
    address: String,
    routing_entries: u64,
    subnet: String,
}

/// Go's `getSelf` (`getself.go:20-29`). `build_name`/`build_version` are ours:
/// claiming `yggdrasil` would be a lie about which implementation answered.
fn get_self(snap: &Snapshot) -> GetSelfResponse<'static> {
    let key = snap.key;
    GetSelfResponse {
        build_name: "roots",
        build_version: env!("CARGO_PKG_VERSION"),
        key: hex::encode(key),
        address: roots::addr_for_key(&key).to_string(),
        routing_entries: snap.routing_entries as u64,
        subnet: roots::subnet_for_key(&key).to_string(),
    }
}

/// Go's `PeerEntry` (`getpeers.go:21-38`) minus `rate_recvd`, `rate_sent` and
/// `last_error_time`: the library measures no throughput and timestamps no link
/// error, so there is nothing true to put in them. Absent rather than zero —
/// Go's `omitempty` drops a zero rate too, but it would show one it measured.
#[derive(Serialize)]
struct PeerEntry {
    #[serde(skip_serializing_if = "String::is_empty")]
    remote: String,
    up: bool,
    inbound: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    address: String,
    key: String,
    port: u64,
    priority: u64,
    cost: u64,
    #[serde(skip_serializing_if = "is_zero")]
    bytes_recvd: u64,
    #[serde(skip_serializing_if = "is_zero")]
    bytes_sent: u64,
    #[serde(skip_serializing_if = "Value::is_null")]
    uptime: Value,
    #[serde(skip_serializing_if = "is_zero")]
    latency: u64,
    #[serde(skip_serializing_if = "String::is_empty")]
    last_error: String,
}

#[derive(Serialize)]
struct GetPeersResponse {
    peers: Vec<PeerEntry>,
}

fn get_peers(snap: &Snapshot) -> GetPeersResponse {
    let peers = snap
        .peers
        .iter()
        .map(|p| PeerEntry {
            remote: p.uri.clone(),
            up: p.up,
            inbound: p.inbound,
            address: p
                .key
                .as_ref()
                .map(|k| roots::addr_for_key(k).to_string())
                .unwrap_or_default(),
            key: p.key.as_ref().map(hex::encode).unwrap_or_default(),
            port: p.port,
            priority: u64::from(p.priority),
            cost: p.cost,
            bytes_recvd: p.rx_bytes,
            bytes_sent: p.tx_bytes,
            uptime: go_seconds(p.up_for),
            // Slice 8: Go's `latency` is the raw last SigReq round trip
            // (`debug.go:85`, `peer.srrt.Sub(peer.srst)` rounded to 10 µs), a
            // different measurement from the `cost` EWMA above, and the library
            // keeps only the EWMA. Zero means `omitempty`, which is what a link
            // with no sample shows in Go too — but a link with one should not
            // read as if it had none.
            latency: 0,
            last_error: p.last_error.clone().unwrap_or_default(),
        })
        .collect();
    // Slice 8: Go sorts here (`getpeers.go:70-101`, three comparators). Until
    // then the rows stay in configuration order, which is what `Links` keeps.
    GetPeersResponse { peers }
}

/// Go's `float64` seconds: `encoding/json` writes a whole float without a
/// decimal point where `serde_json` writes `1.0`, and `omitempty` drops zero.
fn go_seconds(d: Duration) -> Value {
    let secs = d.as_secs_f64();
    if secs == 0.0 {
        return Value::Null;
    }
    if secs.fract() == 0.0 {
        return Value::from(secs as u64);
    }
    Value::from(secs)
}

#[derive(Serialize)]
struct TreeEntry {
    address: String,
    key: String,
    parent: String,
    sequence: u64,
}

#[derive(Serialize)]
struct GetTreeResponse {
    tree: Vec<TreeEntry>,
}

fn get_tree(snap: &Snapshot) -> GetTreeResponse {
    // Go's `gettree.go:29` skips a key whose address is not derivable; every
    // key we hold is 32 bytes, so every entry survives. Sorted by key, which
    // `Router::tree_entries` already is.
    let tree = snap
        .tree
        .iter()
        .map(|(key, parent, sequence)| TreeEntry {
            address: roots::addr_for_key(key).to_string(),
            key: hex::encode(key),
            parent: hex::encode(parent),
            sequence: *sequence,
        })
        .collect();
    GetTreeResponse { tree }
}

#[derive(Serialize)]
struct PathEntry {
    address: String,
    key: String,
    path: Vec<u64>,
    sequence: u64,
}

#[derive(Serialize)]
struct GetPathsResponse {
    paths: Vec<PathEntry>,
}

fn get_paths(snap: &Snapshot) -> GetPathsResponse {
    let paths = snap
        .paths
        .iter()
        .map(|(key, path, sequence)| PathEntry {
            address: roots::addr_for_key(key).to_string(),
            key: hex::encode(key),
            path: path.clone(),
            sequence: *sequence,
        })
        .collect();
    GetPathsResponse { paths }
}

#[derive(Serialize)]
struct SessionEntry {
    address: String,
    key: String,
}

#[derive(Serialize)]
struct GetSessionsResponse {
    sessions: Vec<SessionEntry>,
}

/// Go's `SessionEntry` (`getsessions.go:18-24`) also carries `bytes_recvd`,
/// `bytes_sent` and `uptime`; `SessionState` counts none of those, so the
/// fields are absent rather than filled with zeros that would read as
/// measurements.
fn get_sessions(snap: &Snapshot) -> GetSessionsResponse {
    let sessions = snap
        .sessions
        .iter()
        .map(|key| SessionEntry {
            address: roots::addr_for_key(key).to_string(),
            key: hex::encode(key),
        })
        .collect();
    GetSessionsResponse { sessions }
}

/// `addPeer` and `removePeer` (`addpeer.go`, `removepeer.go`): one required
/// URI, one optional interface, and the answer is the empty object or whatever
/// `Links` said.
async fn change_peer(
    name: &str,
    args: &Value,
    tx: &mpsc::UnboundedSender<Cmd>,
) -> Result<Body, String> {
    let uri = args.get("uri").and_then(Value::as_str).unwrap_or("");
    let sintf = args.get("interface").and_then(Value::as_str).unwrap_or("");
    let (wt, rr) = oneshot::channel();
    let cmd = if name == "addpeer" {
        Cmd::Dial {
            uri: uri.to_string(),
            sintf: sintf.to_string(),
            persistent: true,
            respond: Some(wt),
        }
    } else {
        Cmd::Drop {
            uri: uri.to_string(),
            sintf: sintf.to_string(),
            respond: Some(wt),
        }
    };
    tx.send(cmd)
        .map_err(|_| "node is not running".to_string())?;
    // Go's `url.Parse` only fails on bad escapes and control characters, so its
    // `unable to parse peering URI` wrapper almost never fires: what an
    // operator sees for a bad URI is the link error itself
    // (`link.go:149-157`).
    match rr.await {
        Ok(Ok(())) => Ok(Body::Empty),
        Ok(Err(e)) => Err(e.message()),
        Err(_) => Err("node did not answer".to_string()),
    }
}
