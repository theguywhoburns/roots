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

use std::cmp::Ordering;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, Instant};

use serde::Serialize;
use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, UnixListener, UnixStream};
use tokio::sync::{mpsc, oneshot};

use crate::node::{Cmd, RemoteQuery, Snapshot};

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
/// `AddHandler` triples, lowercased because Go registers and looks up with
/// `strings.ToLower`. Sorted, because `list` sorts.
///
/// All fourteen of Go's commands are here, which is the first time `list` says
/// fourteen.
const COMMANDS: &[(&str, &str, &[&str])] = &[
    (
        "addpeer",
        "Add a peer to the peer list",
        &["uri", "interface"],
    ),
    (
        "debug_remotegetself",
        // Go registers these three with the literal description
        // "Debug use only" (`core/api.go:245-256`), so that is what `list` says.
        "Debug use only",
        &["key"],
    ),
    ("debug_remotegetpeers", "Debug use only", &["key"]),
    ("debug_remotegettree", "Debug use only", &["key"]),
    (
        "getmulticastinterfaces",
        // Go's literal description (`multicast/admin.go:56`).
        "Show which interfaces multicast is enabled on",
        &[],
    ),
    (
        "getnodeinfo",
        "Request nodeinfo from a remote node by its public key",
        &["key"],
    ),
    ("getpaths", "Show established paths through this node", &[]),
    ("getpeers", "Show directly connected peers", &["sort"]),
    (
        "getsessions",
        "Show established traffic sessions with remote nodes",
        &[],
    ),
    ("getself", "Show details about this node", &[]),
    (
        "gettun",
        // Go's literal description (`tun/admin.go:56`).
        "Show information about the node's TUN interface",
        &[],
    ),
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

impl RemoteQuery {
    /// Which of the four remote commands this name is, if it is one.
    pub fn for_command(name: &str) -> Option<RemoteQuery> {
        Some(match name {
            "getnodeinfo" => RemoteQuery::NodeInfo,
            "debug_remotegetself" => RemoteQuery::SelfInfo,
            "debug_remotegetpeers" => RemoteQuery::Peers,
            "debug_remotegettree" => RemoteQuery::Tree,
            _ => return None,
        })
    }
}

/// Go's `ed25519.PublicKeySize`, the only length a `key` argument may be.
const KEY_SIZE: usize = 32;

/// The four remote queries, as Go's handlers write them.
///
/// Two of the four differ in a way that is easy to get wrong. `getNodeInfo`
/// checks for an empty key first and says "no remote public key supplied"
/// (`nodeinfo.go:157-160`); the three debug handlers do not, so an empty key
/// decodes to zero bytes and fails the length check instead
/// (`proto.go:270-281` and its two siblings). Same argument, different error.
async fn remote_query(
    what: RemoteQuery,
    args: &Value,
    tx: &mpsc::UnboundedSender<Cmd>,
) -> Result<Body, String> {
    let key_text = args.get("key").and_then(Value::as_str).unwrap_or("");
    if what == RemoteQuery::NodeInfo && key_text.is_empty() {
        return Err("no remote public key supplied".to_string());
    }
    let key = decode_remote_key(what, key_text)?;
    let (wt, rr) = oneshot::channel();
    tx.send(Cmd::Remote {
        key,
        what,
        respond: wt,
    })
    .map_err(|_| "node is not running".to_string())?;
    let answer = rr.await.map_err(|_| "node did not answer".to_string())?;
    let body = answer?;

    // The top-level key is the node's address for the debug three and its key
    // for nodeinfo, matching Go: `DebugGetSelfResponse{ip.String(): msg}`
    // (`proto.go:290-292`) against `GetNodeInfoResponse{key: msg}` with the
    // hex key (`nodeinfo.go:175-177`).
    let name = match what {
        RemoteQuery::NodeInfo => hex::encode(key),
        _ => roots::addr_for_key(&key).to_string(),
    };
    let mut map = serde_json::Map::new();
    map.insert(name, remote_body(what, &body)?);
    Ok(Body::Map(Value::Object(map)))
}

/// Decode the `key` argument, with Go's two error strings.
///
/// `hex.DecodeString` fails in exactly two ways and Go wraps both in the same
/// text (`nodeinfo.go:161-163`, `proto.go:274-276`): an odd number of digits
/// with `encoding/hex: odd length hex string`, and a non-hex digit with
/// `encoding/hex: invalid byte: U+0078 'x'`.
fn decode_remote_key(what: RemoteQuery, text: &str) -> Result<[u8; KEY_SIZE], String> {
    if !text.len().is_multiple_of(2) {
        return Err(go_hex_error(text, None));
    }
    let bytes = hex::decode(text).map_err(|e| go_hex_error(text, Some(&e)))?;
    if bytes.len() != KEY_SIZE {
        // `invalid public key length` is one of Go's, and it is what an empty
        // key reaches on the debug path (`proto.go:277-279`).
        let _ = what;
        return Err("invalid public key length".to_string());
    }
    let mut key = [0u8; KEY_SIZE];
    key.copy_from_slice(&bytes);
    Ok(key)
}

/// Go's `encoding/hex` error text, rebuilt from what `hex::decode` reports.
fn go_hex_error(text: &str, err: Option<&hex::FromHexError>) -> String {
    match err {
        Some(hex::FromHexError::OddLength) => {
            "failed to decode public key: encoding/hex: odd length hex string".to_string()
        }
        Some(hex::FromHexError::InvalidHexCharacter { c, .. }) => {
            format!(
                "failed to decode public key: encoding/hex: invalid byte: U+{:04X} '{c}'",
                *c as u32
            )
        }
        // `InvalidStringLength` is unreachable: `decode` only raises it for
        // `decode_slice`, which we do not call. It gets a wrapper rather than a
        // panic so a future caller of this function cannot take the node down.
        _ => format!("failed to decode public key: {text}"),
    }
}

/// Marshal a remote answer into the shape its handler returns.
fn remote_body(what: RemoteQuery, body: &[u8]) -> Result<Value, String> {
    let parsed: Value = serde_json::from_slice(body)
        .map_err(|e| format!("invalid character in remote response: {e}"))?;
    Ok(match what {
        // Nodeinfo is passed through verbatim: Go holds it as `json.RawMessage`
        // and marshals it back unchanged (`nodeinfo.go:174-177`).
        RemoteQuery::NodeInfo => parsed,
        // The self answer is also a map Go marshals as-is (`proto.go:290-292`),
        // including its string-typed `routing_entries` (`proto.go:132-133`,
        // which is `fmt.Sprintf("%v", …)` and so a JSON string, not a number).
        RemoteQuery::SelfInfo => parsed,
        // The peers and tree answers are concatenated 32-byte keys on the wire
        // (`peers.go:168-180`) and become a `keys` list in the reply
        // (`proto.go:300-315`, `:343-358`).
        RemoteQuery::Peers | RemoteQuery::Tree => {
            let keys: Vec<Value> = body
                .as_chunks::<KEY_SIZE>()
                .0
                .iter()
                .map(|c| Value::String(hex::encode(c)))
                .collect();
            let mut m = serde_json::Map::new();
            m.insert("keys".to_string(), Value::Array(keys));
            Value::Object(m)
        }
    })
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
        // The handler declares an empty struct and `json.Unmarshal`s into it
        // (`tun/admin.go:58-59`), so nothing in it can be the wrong type — but a
        // non-object argument still is, exactly as for `getself`.
        "gettun" => ("tun.GetTUNRequest", &[]),
        "getpaths" => ("GetPathsRequest", &[]),
        "getsessions" => ("GetSessionsRequest", &[]),
        "getpeers" => ("GetPeersRequest", &["sort"]),
        // The handler declares an empty struct and `json.Unmarshal`s into it
        // (`multicast/admin.go:58-59`), so nothing in it can be the wrong type —
        // but a non-object argument still is, exactly as for `getself`.
        "getmulticastinterfaces" => ("multicast.GetMulticastInterfacesRequest", &[]),
        "addpeer" => ("AddPeerRequest", &["uri", "interface"]),
        "removepeer" => ("RemovePeerRequest", &["uri", "interface"]),
        // The four remote handlers live in `core`, not `admin`, so their
        // request structs marshal as `core.GetNodeInfoRequest` and friends.
        // `core/api.go:241` registers `getNodeInfo` with `[]string{"key"}`, and
        // the three debug handlers with the same.
        "getnodeinfo" => ("core.GetNodeInfoRequest", &["key"]),
        "debug_remotegetself" => ("core.DebugGetSelfRequest", &["key"]),
        "debug_remotegetpeers" => ("core.DebugGetPeersRequest", &["key"]),
        "debug_remotegettree" => ("core.DebugGetTreeRequest", &["key"]),
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
    /// `getMulticastInterfaces` (`multicast/admin.go:15-20`).
    Multicast(GetMulticastInterfacesResponse),
    /// `getTun` (`tun/admin.go:11-15`).
    Tun(GetTunResponse),
    /// The four remote queries, which Go answers as a **map**, not a struct.
    ///
    /// `GetNodeInfoResponse map[string]json.RawMessage` (`nodeinfo.go:150`) and
    /// `DebugGetSelfResponse map[string]interface{}` (`proto.go:249`) are both
    /// maps, and `encoding/json` writes a map with its keys sorted — so a
    /// `serde_json` map, which is a `BTreeMap`, matches. This is the one place a
    /// map body is right, and the reason is that Go has one too. Each has
    /// exactly one entry, so key order cannot differ anyway.
    Map(Value),
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
            Body::Multicast(b) => b.serialize(s),
            Body::Tun(b) => b.serialize(s),
            Body::Map(v) => v.serialize(s),
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

/// ... and for a `float64`, which is what `uptime` is.
fn is_zero_f64(v: &f64) -> bool {
    *v == 0.0
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
pub async fn serve_admin(
    bound: Bound,
    tx: mpsc::UnboundedSender<Cmd>,
    ifaces: crate::multicast::InterfaceTable,
) {
    loop {
        match bound.accept().await {
            Ok(sock) => {
                let tx = tx.clone();
                let ifaces = ifaces.clone();
                tokio::spawn(async move {
                    admin_conn(sock, tx, ifaces).await;
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
async fn admin_conn(
    mut sock: Box<dyn AdminStream>,
    tx: mpsc::UnboundedSender<Cmd>,
    ifaces: crate::multicast::InterfaceTable,
) {
    let mut buf = Vec::new();
    let mut at_eof = false;
    loop {
        let (outcome, echo, keepalive) =
            handle_one(&mut sock, &mut buf, &mut at_eof, &tx, &ifaces).await;
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
    ifaces: &crate::multicast::InterfaceTable,
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
    (dispatch(&name, &args, tx, ifaces).await, echo, keepalive)
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
    ifaces: &crate::multicast::InterfaceTable,
) -> Result<Body, String> {
    if name == "list" {
        return Ok(Body::List(list_body()));
    }
    if name == "addpeer" || name == "removepeer" {
        return change_peer(name, args, tx).await;
    }
    if let Some(what) = RemoteQuery::for_command(name) {
        return remote_query(what, args, tx).await;
    }
    if name == "getmulticastinterfaces" {
        return Ok(multicast_interfaces(ifaces));
    }
    if name == "gettun" {
        return get_tun(tx).await;
    }
    let snap = report(tx).await?;
    Ok(match name {
        "getself" => Body::Self_(get_self(&snap)),
        "getpeers" => Body::Peers(get_peers(&snap, args)),
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

/// Go's `PeerEntry` (`getpeers.go:21-38`), field for field and in field order:
/// `encoding/json` writes a struct in declaration order, so a body with the same
/// keys in another order is a different answer on the wire.
///
/// Every `omitempty` is carried over, including the ones that hide a real zero —
/// a link with no traffic reports no `bytes_recvd` key at all rather than
/// `"bytes_recvd": 0`. `uptime` is Go's `float64` seconds (see
/// [`go_seconds`]); `latency` and `last_error_time` are `time.Duration`, which
/// marshals as an integer count of nanoseconds.
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
    #[serde(skip_serializing_if = "is_zero")]
    rate_recvd: u64,
    #[serde(skip_serializing_if = "is_zero")]
    rate_sent: u64,
    #[serde(skip_serializing_if = "is_zero_f64", serialize_with = "go_seconds")]
    uptime: f64,
    #[serde(skip_serializing_if = "is_zero")]
    latency: u64,
    #[serde(skip_serializing_if = "is_zero")]
    last_error_time: u64,
    #[serde(skip_serializing_if = "String::is_empty")]
    last_error: String,
}

#[derive(Serialize)]
struct GetPeersResponse {
    peers: Vec<PeerEntry>,
}

fn get_peers(snap: &Snapshot, args: &Value) -> GetPeersResponse {
    // One instant for the whole body, so two rows that failed at the same moment
    // print the same age (Go calls `time.Since` once per row, which can differ by
    // the odd nanosecond between them).
    let now = Instant::now();
    let mut peers: Vec<PeerEntry> = snap
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
            rate_recvd: p.rx_rate,
            rate_sent: p.tx_rate,
            uptime: p.up_for.as_secs_f64(),
            // Go keeps the raw round trip, not the cost EWMA above
            // (`debug.go:84-86`), and drops one that is not positive — which
            // `roots::Router::link_peers` has already done for us.
            latency: p.latency.map(|d| d.as_nanos() as u64).unwrap_or(0),
            // The *age* of the error, and only when there is one: Go gates both
            // fields on `p.LastError != nil` (`getpeers.go:64-67`), so a row with
            // a timestamp but no message prints neither.
            last_error_time: match (&p.last_error, p.err_at) {
                (Some(_), Some(at)) => now.duration_since(at).as_nanos() as u64,
                _ => 0,
            },
            last_error: p.last_error.clone().unwrap_or_default(),
        })
        .collect();
    // Go's `switch strings.ToLower(req.SortBy)` (`getpeers.go:70-77`): anything
    // that is not `uptime` or `cost` gets the default order, including a request
    // with no `sort` at all.
    let by = match args
        .get("sort")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_lowercase()
        .as_str()
    {
        "uptime" => by_uptime as fn(&PeerEntry, &PeerEntry) -> Ordering,
        "cost" => by_cost,
        _ => by_default,
    };
    // `slices.SortStableFunc` is a *stable* sort, not `sort_unstable`: rows a
    // comparator calls equal stay in configuration order.
    sort_stable(&mut peers, by);
    GetPeersResponse { peers }
}

/// Go's `slices.SortStableFunc` (`getpeers.go:71-77`), written out.
///
/// Deliberately not `slice::sort_by`. Go's uptime key is `int(a - b)`, which
/// calls two rows equal when they differ by less than a whole second, so "equal"
/// is not transitive: `a` ties `b` and `b` ties `c` while `a` and `c` are a
/// second apart. Rust looks for exactly that and panics with "user-provided
/// comparison function does not correctly implement a total order" once the
/// slice is big enough to leave its run-detection path — which would take the
/// node down over a `getPeers` with `sort: uptime`. Insertion sort has no such
/// check, is stable the way Go's is, and costs O(n²) on a peer list that is tens
/// of rows long; Go's own answer for a non-transitive comparator is
/// implementation-defined at large `n` anyway.
fn sort_stable(rows: &mut [PeerEntry], by: fn(&PeerEntry, &PeerEntry) -> Ordering) {
    for at in 1..rows.len() {
        let mut from = at;
        while from > 0 && by(&rows[from - 1], &rows[from]) == Ordering::Greater {
            rows.swap(from - 1, from);
            from -= 1;
        }
    }
}

/// Go's `if d := a - b; d != 0 { return int(d) }` on two `uint64`s: `None` means
/// the two are identical and the comparison moves on to the next key.
fn go_u64(a: u64, b: u64) -> Option<Ordering> {
    (a != b).then(|| (a.wrapping_sub(b) as i64).cmp(&0))
}

/// The same line on two `float64`s, where the `int(d)` conversion is the point:
/// a difference smaller than one whole second returns *from the comparator* as 0,
/// which means "equal" — and the keys after it are never consulted. Sorting by
/// uptime therefore leaves two links from the same second in configuration order,
/// in both directions. Reproduce it: `a.total_cmp(&b)` orders rows Go does not.
fn go_f64(a: f64, b: f64) -> Option<Ordering> {
    let d = a - b;
    (d != 0.0).then(|| (d as i64).cmp(&0))
}

/// `strings.Compare` on the hex key — byte order, which for fixed-length lowercase
/// hex is the same as the key's own order. A row with no key compares as the empty
/// string, which is before every real one.
fn go_key(a: &str, b: &str) -> Option<Ordering> {
    (a != b).then(|| a.cmp(b))
}

/// Go's `sortByDefault` (`getpeers.go:81-101`): outbound rows first, then key,
/// priority, cost, uptime. Direction is the only thing that outranks a key.
fn by_default(a: &PeerEntry, b: &PeerEntry) -> Ordering {
    if a.inbound != b.inbound {
        return if a.inbound {
            Ordering::Greater
        } else {
            Ordering::Less
        };
    }
    if let Some(d) = go_key(&a.key, &b.key) {
        return d;
    }
    if let Some(d) = go_u64(a.priority, b.priority) {
        return d;
    }
    if let Some(d) = go_u64(a.cost, b.cost) {
        return d;
    }
    go_f64(a.uptime, b.uptime).unwrap_or(Ordering::Equal)
}

/// Go's `sortByCost` (`getpeers.go:103-117`): cost, then key, priority, uptime.
fn by_cost(a: &PeerEntry, b: &PeerEntry) -> Ordering {
    if let Some(d) = go_u64(a.cost, b.cost) {
        return d;
    }
    if let Some(d) = go_key(&a.key, &b.key) {
        return d;
    }
    if let Some(d) = go_u64(a.priority, b.priority) {
        return d;
    }
    go_f64(a.uptime, b.uptime).unwrap_or(Ordering::Equal)
}

/// Go's `sortByUptime` (`getpeers.go:119-133`): uptime, then key, priority, cost.
fn by_uptime(a: &PeerEntry, b: &PeerEntry) -> Ordering {
    if let Some(d) = go_f64(a.uptime, b.uptime) {
        return d;
    }
    if let Some(d) = go_key(&a.key, &b.key) {
        return d;
    }
    if let Some(d) = go_u64(a.priority, b.priority) {
        return d;
    }
    go_u64(a.cost, b.cost).unwrap_or(Ordering::Equal)
}

/// Go's `float64` seconds: `encoding/json` writes a whole float without a decimal
/// point where `serde_json` writes `1.0`.
fn go_seconds<S: serde::Serializer>(v: &f64, s: S) -> Result<S::Ok, S::Error> {
    if v.fract() == 0.0 {
        s.serialize_u64(*v as u64)
    } else {
        s.serialize_f64(*v)
    }
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

/// Go's `GetMulticastInterfacesResponse` (`multicast/admin.go:15-20`), with its
/// one field and Go's spelling.
#[derive(Serialize)]
struct GetMulticastInterfacesResponse {
    multicast_interfaces: Vec<multicast_state::State>,
}

/// Go's `MulticastInterfaceState` (`multicast/admin.go:21-27`) has five fields
/// and no `omitempty`, so all five are always present. It needs `Serialize`, and
/// the field order must be Go's declaration order because a `serde_json` map
/// would sort them alphabetically instead.
mod multicast_state {
    use serde::Serialize;

    /// The row as Go declares it, field for field and in order.
    #[derive(Serialize)]
    pub(super) struct State {
        pub name: String,
        /// `-` when nothing is listening, which is Go's own placeholder
        /// (`multicast/admin.go:41`) rather than an empty string.
        pub address: String,
        pub beacon: bool,
        pub listen: bool,
        /// Whether a password is set, never the password: Go reports
        /// `len(intf.password) > 0` (`multicast/admin.go:44`).
        pub password: bool,
    }

    impl From<crate::multicast::MulticastInterfaceState> for State {
        fn from(s: crate::multicast::MulticastInterfaceState) -> Self {
            State {
                name: s.name,
                address: s.address,
                beacon: s.beacon,
                listen: s.listen,
                password: s.password,
            }
        }
    }
}

/// Go's `GetTUNResponse` (`tun/admin.go:11-15`).
///
/// Two fields carry `omitempty`, which is not decoration: with no TUN, Go's
/// handler returns early having set only `Enabled` (`tun/admin.go:30-32`), so a
/// disabled node's answer is `{"enabled": false}` and **not** `{"enabled":
/// false, "name": "", "mtu": 0}`. Printing the zeroes would make a node with no
/// TUN indistinguishable from one whose interface is called "".
#[derive(Serialize)]
struct GetTunResponse {
    enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mtu: Option<u16>,
}

/// `getTun`: what the node's own device says about itself.
///
/// Go reads `t.isEnabled`, `t.Name()` and `t.MTU()` off the adapter
/// (`tun/admin.go:27-33`) and does not ask the kernel — so neither do we, because
/// a device that exists and a device that carries traffic are different questions
/// and only the first one is what this command claims.
async fn get_tun(tx: &mpsc::UnboundedSender<Cmd>) -> Result<Body, String> {
    let (wt, rr) = oneshot::channel();
    tx.send(Cmd::Tun { respond: wt })
        .map_err(|_| "node is not running".to_string())?;
    let device = rr.await.map_err(|_| "node did not answer".to_string())?;
    Ok(Body::Tun(match device {
        Some((name, mtu)) => GetTunResponse {
            enabled: true,
            name: Some(name),
            mtu: Some(mtu),
        },
        None => GetTunResponse {
            enabled: false,
            name: None,
            mtu: None,
        },
    }))
}

/// `getMulticastInterfaces`: the multicast task's own table, read under its
/// lock.
///
/// Go answers from inside the multicast actor (`multicast/admin.go:30-48`),
/// which is what keeps the read consistent with the tick that writes it. Ours
/// publishes once a tick and reads here, which is the same consistency with a
/// cheaper hand-off — see `multicast::InterfaceTable` for why this is the only
/// lock in the client.
///
/// A node with no multicast module answers an empty list rather than an error,
/// because Go's handler is registered unconditionally and a host where the bind
/// failed still has the actor, with nothing in it.
fn multicast_interfaces(ifaces: &crate::multicast::InterfaceTable) -> Body {
    let mut rows: Vec<crate::multicast::MulticastInterfaceState> =
        ifaces.lock().map(|guard| guard.clone()).unwrap_or_default();
    // Go sorts here rather than where it collects, because its source is a map
    // and map order is random (`multicast/admin.go:46-48`,
    // `slices.SortStableFunc` on `res.Interfaces`). Ours is a list, but the sort
    // stays in the answer for the same reason: it is the answer's guarantee, not
    // the producer's.
    rows.sort_by(|a, b| a.name.cmp(&b.name));
    Body::Multicast(GetMulticastInterfacesResponse {
        multicast_interfaces: rows.into_iter().map(Into::into).collect(),
    })
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::PeerRow;
    use serde_json::json;

    /// A row built to be sorted: `key` is the first byte of a node key, so the
    /// hex text Go compares comes out `aa00…`, `bb00…`, and a first byte of 0
    /// stands for the no-key row a down link reports.
    fn row(
        remote: &str,
        first: u8,
        inbound: bool,
        priority: u8,
        cost: u64,
        uptime: f64,
    ) -> PeerRow {
        let mut key = [0u8; 32];
        key[0] = first;
        PeerRow {
            uri: remote.to_string(),
            sintf: String::new(),
            key: (first != 0).then_some(key),
            up: first != 0,
            inbound,
            port: 1,
            priority,
            cost,
            latency: None,
            up_for: Duration::from_secs_f64(uptime),
            rx_bytes: 0,
            tx_bytes: 0,
            rx_rate: 0,
            tx_rate: 0,
            last_error: None,
            err_at: None,
        }
    }

    fn snapshot(peers: Vec<PeerRow>) -> Snapshot {
        Snapshot {
            key: [7u8; 32],
            routing_entries: 1,
            tree: Vec::new(),
            paths: Vec::new(),
            sessions: Vec::new(),
            peers,
        }
    }

    /// The URIs in the order `getPeers` printed them. Every row is named, so a
    /// wrong order is visible rather than a count that happens to match.
    fn order(peers: Vec<PeerRow>, args: Value) -> Vec<String> {
        get_peers(&snapshot(peers), &args)
            .peers
            .into_iter()
            .map(|p| p.remote)
            .collect()
    }

    /// Five rows chosen so that all three comparators — and the configuration
    /// order they all start from — answer with five different orders.
    ///
    /// The uptimes are not free choices. `go_f64` calls two rows equal when they
    /// differ by less than a whole second, so a group whose members sit inside
    /// one second must be at least a second away from every other row's uptime:
    /// otherwise "equal" is not transitive (`cc` would tie `aa` *and* `dd`, which
    /// do not tie each other), and a comparator with a cycle like that is not the
    /// order Go sorts by either.
    fn five() -> Vec<PeerRow> {
        vec![
            row("out3", 0xbb, false, 0, 5, 4.0),
            row("cc", 0xcc, false, 0, 2, 1.4),
            row("aa", 0xaa, true, 0, 4, 1.0),
            row("dead", 0, false, 0, 0, 0.0),
            row("dd", 0xdd, false, 0, 2, 2.5),
        ]
    }

    #[test]
    fn getpeers_sort_modes_match_go_three_for_three() {
        // `sortByDefault`: direction, then key, priority, cost, uptime. The
        // inbound row is `aa`, which leads every other key — so it comes last
        // here and first in the other two modes.
        assert_eq!(
            order(five(), json!({"sort": ""})),
            ["dead", "out3", "cc", "dd", "aa"],
            "the default order puts outbound rows first"
        );
        // `sortByCost`: cost, then key. `cc` and `dd` share cost 2 and are then
        // ordered by key, and neither is where the default order put them.
        assert_eq!(
            order(five(), json!({"sort": "cost"})),
            ["dead", "cc", "dd", "aa", "out3"],
            "`sort: cost` ignores direction, and the key only breaks a cost tie"
        );
        // `sortByUptime`: whole seconds, because Go returns `int(a - b)` from the
        // comparator — so `cc` at 1.4 s and `aa` at 1.0 s are *equal*, and a
        // stable sort leaves them in configuration order rather than putting the
        // smaller uptime (or the smaller key) first.
        assert_eq!(
            order(five(), json!({"sort": "uptime"})),
            ["dead", "cc", "aa", "dd", "out3"],
            "sub-second uptime differences do not reorder rows"
        );
    }

    #[test]
    fn getpeers_sort_argument_is_go_indifferent() {
        // `strings.ToLower(req.SortBy)` (`getpeers.go:70`), and the `default` arm
        // of the switch covers every other value — including no argument at all.
        let want = order(five(), json!({"sort": "cost"}));
        assert_eq!(order(five(), json!({"sort": "CoSt"})), want);
        assert_eq!(
            order(five(), json!({"sort": "nonsense"})),
            order(five(), json!({}))
        );
        assert_eq!(
            order(five(), json!({"sort": null})),
            order(five(), Value::Null),
            "a null `sort` and no arguments both mean the default order"
        );
        assert_eq!(
            order(five(), json!({"sort": "UPTIME"})),
            order(five(), json!({"sort": "uptime"}))
        );
    }

    #[test]
    fn getpeers_priority_ranks_after_the_key_and_before_the_cost() {
        // Two rows with the same key: the default order falls through to
        // priority, and priority outranks the cost that follows it. Go's
        // comparator reads key, priority, cost, uptime in that order
        // (`getpeers.go:88-99`) and the cost mode inverts the answer.
        let same = || {
            vec![
                row("low-priority", 0xaa, false, 1, 1, 0.0),
                row("high-cost", 0xaa, false, 0, 9, 0.0),
            ]
        };
        assert_eq!(
            order(same(), json!({"sort": ""})),
            ["high-cost", "low-priority"],
            "priority decides when the keys are equal"
        );
        assert_eq!(
            order(same(), json!({"sort": "cost"})),
            ["low-priority", "high-cost"],
            "and loses to cost in the cost mode"
        );
    }

    /// Go's uptime key makes "equal" non-transitive, and Rust's `sort_by` reacts
    /// to that by panicking. 300 shuffled rows is what it takes to see it: below
    /// Rust's small-sort threshold the check never runs, so 200 rows sort quietly
    /// and a mutation to `sort_by` would survive a smaller set. The assertion is
    /// that an answer comes back at all, and that it is the same set of rows.
    #[test]
    fn getpeers_sorts_where_go_s_truncation_breaks_a_total_order() {
        let n = 300usize;
        let many: Vec<PeerRow> = (0..n)
            .map(|i| {
                row(
                    &format!("p{i:03}"),
                    (i % 250 + 1) as u8,
                    false,
                    0,
                    0,
                    0.5 + f64::from((i * 7919 % n) as u32) * 0.5,
                )
            })
            .collect();
        let got = order(many, json!({"sort": "uptime"}));
        assert_eq!(got.len(), n, "every row must still be answered for");
        let mut sorted = got.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), n, "no row was duplicated or dropped");
    }

    #[test]
    fn getpeers_uptime_is_the_last_tiebreak_in_the_other_two_modes() {
        // Nothing above reaches a comparator's trailing uptime key: `five` gives
        // every row its own cost and key. Two rows that tie on cost *and* key *and*
        // priority force the sort down to the last step in `sortByDefault`
        // (`getpeers.go:96-99`) and `sortByCost` (`:114-117`). Their uptimes are a
        // whole second and a half apart, because a smaller gap would be reported as
        // equal and leave them in configuration order.
        let tied = |first: f64, second: f64| {
            vec![
                row("first", 0xaa, false, 3, 7, first),
                row("second", 0xaa, false, 3, 7, second),
            ]
        };
        // Configuration order is the wrong answer for both modes, so a comparator
        // that stops short of the uptime key fails here rather than passing by
        // accident.
        assert_eq!(
            order(tied(2.5, 1.0), json!({"sort": ""})),
            ["second", "first"],
            "the default order falls through to uptime"
        );
        assert_eq!(
            order(tied(2.5, 1.0), json!({"sort": "cost"})),
            ["second", "first"],
            "and so does the cost order"
        );
        assert_eq!(
            order(tied(1.0, 2.5), json!({"sort": ""})),
            ["first", "second"],
            "the answer follows the uptimes, not the configuration order"
        );
    }

    /// Go gates both error fields on the *message* (`getpeers.go:64-67`), so a row
    /// that carries a timestamp but no message prints neither. Nothing in the node
    /// produces that combination — `Links` writes both together — which is why the
    /// gate is checked here rather than over a socket.
    #[test]
    fn getpeers_reports_an_error_age_only_with_an_error() {
        let mut silent = row("silent", 0xbb, false, 0, 0, 0.0);
        silent.err_at = Some(Instant::now());
        let mut loud = row("loud", 0xcc, false, 0, 0, 0.0);
        loud.err_at = Some(Instant::now());
        loud.last_error = Some("connection refused".to_string());

        let peers = get_peers(&snapshot(vec![silent, loud]), &json!({})).peers;
        let quiet = peers
            .iter()
            .find(|p| p.remote == "silent")
            .expect("the row with a timestamp and no message");
        let loud = peers
            .iter()
            .find(|p| p.remote == "loud")
            .expect("the row with both");
        assert_eq!(
            quiet.last_error_time, 0,
            "a timestamp with no message is not an error Go would age"
        );
        assert!(
            quiet.last_error.is_empty(),
            "and no message is invented for it either"
        );
        assert!(
            loud.last_error_time > 0,
            "a real error prints the nanoseconds since it happened"
        );
        assert_eq!(loud.last_error, "connection refused");
    }
}
