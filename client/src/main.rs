//! The `roots` binary. Config mode first — Go's document flags, in Go's
//! precedence order — and a loaded config runs a node, as Go's does. Without a
//! config it is the demo probe: dial one peer, converge, optionally resolve an
//! address and fetch its nodeinfo, hold the link, report status.
//!
//! Node policy lives in this package (`roots_client::node`); the `roots`
//! library only talks wires and owns state.
//!
//! Run: `roots -genconf` / `roots -useconf -address` for the config face,
//! `roots -useconffile /etc/yggdrasil.conf` for a node, and
//! `cargo run -q -p roots-client -- [peer-uri] [hold_secs] [resolve-ipv6]` for
//! the probe.

use std::time::Duration;

use roots::{Client, Router, addr_for_key, subnet_for_key};
use roots_client::admin::{bind_admin, serve_admin};
use roots_client::config::{Config, ConfigError, Flags, USAGE};
use roots_client::listen::spawn_listeners;
use roots_client::multicast::{Discovery, MulticastRow};
use roots_client::node::{Cmd, DEFAULT_TICK, Node};

fn show(tag: &str, key: &[u8; 32]) {
    println!("{tag:<8} {} {}", hex::encode(key), addr_for_key(key));
}

fn report(router: &Router) {
    match router.parent() {
        Some(p) => show("parent", &p),
        None => println!("parent   <none>"),
    }
    match router.root_and_depth() {
        Some((r, d)) => {
            show("root", &r);
            println!("depth    {d}");
        }
        None => println!("root     <unknown>"),
    }
    println!(
        "known    {} nodes, announces sent {}/{}, frames {:?}",
        router.known_nodes(),
        router.announces_sent(),
        router.announces_recv(),
        router.frames
    );
    if std::env::var("ROOTS_DBG_DUMP").is_ok() {
        print!("{}", router.dump());
    }
}

/// Go's second switch (`cmd/yggdrasil/main.go:147-165`): at most one of these
/// prints, in that order, and each returns before a node is built — which is
/// what makes the cross-check against the Go binary runnable without root.
/// `false` means nothing was asked to print.
fn print_identity(flags: &Flags, cfg: &Config) -> Result<bool, ConfigError> {
    if flags.address {
        println!("{}", cfg.address()?);
        return Ok(true);
    }
    if flags.subnet {
        println!("{}", cfg.subnet()?);
        return Ok(true);
    }
    if flags.publickey {
        println!("{}", hex::encode(cfg.public_key()?));
        return Ok(true);
    }
    Ok(false)
}

/// The config face of the binary: `-genconf`, then `-useconf`/`-useconffile`
/// with `-address`/`-subnet`/`-publickey`. Returns the loaded config only when
/// a document flag asked for one and nothing printed.
fn config_stage(flags: &Flags) -> Option<Config> {
    if flags.genconf {
        println!("{}", Config::generate());
        std::process::exit(0);
    }
    let source = flags.source()?;
    let cfg = match Config::load(&source) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("config: {e}");
            std::process::exit(1);
        }
    };
    match print_identity(flags, &cfg) {
        Ok(true) => std::process::exit(0),
        Ok(false) => {}
        Err(e) => {
            eprintln!("config: {e}");
            std::process::exit(1);
        }
    }
    Some(cfg)
}

/// Go's `node.Start` order, as far as this build has the parts: identity, admin
/// socket, listeners, persistent dials, then the one task that owns the router.
/// Multicast and the TUN arrive with their own slices, so a config that asks for
/// them gets a node that simply does not do those things yet.
async fn boot(cfg: Config) {
    let (key, opts) = match (cfg.signing_key(), cfg.link_options()) {
        (Ok(key), Ok(opts)) => (key, opts),
        (Err(e), _) | (_, Err(e)) => {
            eprintln!("config: {e}");
            std::process::exit(1);
        }
    };
    let (mut node, tx) = Node::from_client(
        roots::Client::with_options(key.clone(), opts.clone()),
        DEFAULT_TICK,
    );
    // Go's three startup lines, on stderr like its logger (`main.go:228-231`).
    let pubkey = key.verifying_key().to_bytes();
    eprintln!("Your public key is {}", hex::encode(pubkey));
    eprintln!("Your IPv6 address is {}", addr_for_key(&pubkey));
    eprintln!("Your IPv6 subnet is {}", subnet_for_key(&pubkey));

    // One interface table, shared between the admin socket that reports it and
    // the multicast task that fills it. Created here so both tasks are wired to
    // the same one before either starts.
    let ifaces = roots_client::multicast::empty_table();

    match bind_admin(&cfg.admin_listen).await {
        Ok(Some(bound)) => {
            eprintln!(
                "{} admin socket listening on {}",
                bound.network(),
                bound.addr()
            );
            tokio::spawn(serve_admin(bound, tx.clone(), ifaces.clone()));
        }
        Ok(None) => {}
        // Go's `os.Exit(1)` from here (`admin.go:134-136`).
        Err(e) => {
            eprintln!("Admin socket failed to listen: {e}");
            std::process::exit(1);
        }
    }

    if let Err(e) = spawn_listeners(&key, &opts, &cfg.listen, &tx).await {
        eprintln!("listener: {e}");
        std::process::exit(1);
    }

    for uri in &cfg.peers {
        let _ = tx.send(Cmd::Dial {
            uri: uri.clone(),
            sintf: String::new(),
            persistent: true,
            respond: None,
        });
    }
    for (sintf, uris) in &cfg.interface_peers {
        for uri in uris {
            let _ = tx.send(Cmd::Dial {
                uri: uri.clone(),
                sintf: sintf.clone(),
                persistent: true,
                respond: None,
            });
        }
    }

    // Multicast discovery is its own task, because it owns sockets and a timer
    // rather than router state. Go starts it inside `core.New` before the admin
    // socket exists (`core.go:106-120`); the order is the same thing seen from
    // the other side, because nothing before this point is *driven* and this
    // task only ever sends `Cmd`s.
    let multicast_rows: Vec<MulticastRow> = cfg
        .multicast_interfaces
        .iter()
        .map(|i| MulticastRow {
            regex: i.regex.clone(),
            beacon: i.beacon,
            listen: i.listen,
            port: i.port,
            // The config carries priority as a `uint64` because gobind cannot
            // export a `uint8` (`config.go:60-67`), and the wire is a `uint8`.
            priority: i.priority.min(u64::from(u8::MAX)) as u8,
            password: i.password.clone(),
        })
        .collect();
    tokio::spawn(run_multicast(
        tx.clone(),
        key.clone(),
        opts.clone(),
        multicast_rows,
        pubkey,
        ifaces.clone(),
    ));

    // The TUN bridge, when `IfName` asks for one. Opened before the loop starts,
    // so a missing capability is the operator's first line rather than a device
    // that exists and drops everything: Go's node panics at startup for the same
    // reason (`cmd/yggdrasil/main.go:282`).
    if !cfg.if_name.is_empty() && cfg.if_name != "auto" {
        let subnet = roots::subnet_for_key(&pubkey);
        match node
            .open_tun(&cfg.if_name, addr_for_key(&pubkey), cfg.if_mtu as u16)
            .await
        {
            Ok(()) => eprintln!("Your subnet is {subnet}"),
            // Go exits rather than carrying on (`main.go:282-286`), and a node
            // with a TUN that silently drops every packet is worse than one that
            // says why it has none.
            Err(e) => {
                eprintln!("TUN {}: {e}", cfg.if_name);
                std::process::exit(1);
            }
        }
    }

    if let Err(e) = node.run().await {
        eprintln!("node: {e}");
        std::process::exit(1);
    }
}

/// Run multicast discovery for as long as the node runs.
///
/// Go starts the module inside `core.New`, before the admin socket exists
/// (`core.go:106-120`). Ours starts alongside the node task, which is the same
/// thing seen from the other side: nothing before this point is *driven*, and
/// this task only ever sends `Cmd`s.
///
/// A bind failure is **not** fatal. Go returns the error and the node carries on
/// without the module (`multicast.go:96-108` sets `running` back and returns),
/// and that is right here too: a host with no usable multicast should still be a
/// mesh node.
async fn run_multicast(
    tx: tokio::sync::mpsc::UnboundedSender<Cmd>,
    key: ed25519_dalek::SigningKey,
    opts: roots::LinkOptions,
    rows: Vec<MulticastRow>,
    pubkey: [u8; 32],
    ifaces: roots_client::multicast::InterfaceTable,
) {
    if rows.iter().all(|r| !r.beacon && !r.listen) {
        // Go's `_start` returns early and without error when no interface asks
        // for anything (`multicast.go:80-86`), so there is nothing to do.
        return;
    }
    let mut discovery = match Discovery::with_table(pubkey, ifaces).await {
        Ok(d) => d,
        Err(e) => {
            eprintln!("multicast: not listening: {e}");
            return;
        }
    };
    discovery.set_config(rows);
    eprintln!("multicast listening on {}", roots::multicast::GROUP);

    // The port each interface's listener got, which is what its beacons
    // advertise. A beacon cannot go out in the same tick as the bind, because it
    // carries the *bound* port rather than the requested one (`multicast.go:352`
    // reads `addr.Port` off the listener it just made, and the default config
    // asks for port 0), so the port is reported on the following tick through
    // `listener_up`.
    let mut listeners: std::collections::HashMap<String, u16> = Default::default();
    loop {
        let cmds = {
            // A snapshot, because the closure borrows and the map is mutated
            // again straight after.
            let known = listeners.clone();
            let mut bind = |iface: &str, _addr: std::net::Ipv6Addr| known.get(iface).copied();
            discovery.tick(&mut bind).await
        };
        for cmd in cmds {
            match cmd {
                roots::multicast::Command::Bind { iface, uri, .. } => {
                    // Already bound: the state machine asks for a listener it
                    // has, and `tick` has just told it the port, so this is the
                    // normal steady state and there is nothing to spawn.
                    if listeners.contains_key(&iface) {
                        continue;
                    }
                    // The index goes in because this URI is for a `bind()`, and
                    // a bind with a zone *name* fails on a host with two
                    // interfaces. The beacon keeps the name, because the name is
                    // what the peer reads.
                    let Some(index) = iface_index(&iface) else {
                        eprintln!("multicast: {iface} has no index, not listening on it");
                        continue;
                    };
                    let uri = with_zone_index(&uri, index);
                    match spawn_listeners(&key, &opts, std::slice::from_ref(&uri), &tx).await {
                        Ok(served) => match bound_addr(served.first()) {
                            Some((addr, port)) => {
                                // The admin socket reports the listener's own
                                // address in Go's `Addr().String()` form
                                // (`multicast/admin.go:41`), which is the served
                                // URI without its scheme.
                                discovery.listener_bound(&iface, &addr);
                                listeners.insert(iface.clone(), port);
                                eprintln!("multicast: listening on {iface} port {port}");
                            }
                            None => eprintln!("multicast: {iface} bound an address with no port"),
                        },
                        // Go logs and carries on to the next interface
                        // (`multicast.go:338-341`).
                        Err(e) => eprintln!("multicast: not listening on {iface}: {e}"),
                    }
                }
                roots::multicast::Command::Unbind { iface } => {
                    listeners.remove(&iface);
                    discovery.listener_gone(&iface);
                }
                roots::multicast::Command::Dial { uri, sintf, .. } => {
                    dial_once(&tx, &uri, &sintf);
                }
                // `Beacon` was already sent by `tick`, which owns the socket.
                roots::multicast::Command::Beacon { .. } => {}
            }
        }

        // Read whatever beacons arrived since the last tick, with the library
        // deciding which of them are ours to answer. Most of them are not: one
        // from a version we do not speak, from ourselves, or on an interface we
        // are not listening on, and Go drops each in its own `continue`
        // (`multicast.go:410-441`).
        //
        // This does not block — the sockets are drained non-blocking — so a node
        // with no peers and a node with twenty both spend one tick here.
        for cmd in discovery.receive(std::time::Instant::now()) {
            if let roots::multicast::Command::Dial { uri, sintf, .. } = cmd {
                dial_once(&tx, &uri, &sintf);
            }
        }

        tokio::time::sleep(
            discovery
                .next_tick()
                .saturating_duration_since(std::time::Instant::now()),
        )
        .await;
    }
}

/// Put an interface's **index** into a bracketed IPv6 URI's zone slot.
///
/// `tls://[fe80::1]:0?…` becomes `tls://[fe80::1%2]:0?…`.
///
/// A number, not a name, because this URI is for a `bind()` and the kernel's
/// socket API takes a scope *id*. Go never faces the question: its listen URI
/// carries no zone at all, because Go hands the interface to `ListenLocal` as a
/// separate argument (`multicast.go:322-330`, `:353-357`). Ours takes a URI, so
/// the index has to go into the address — and it stays a local detail: the
/// beacon and the dial keep the interface **name**, because that is the wire
/// form (`multicast.go:361-366` sets `Zone = iface.Name`, and the dial URI at
/// `:443-451` is printed with the name in it).
fn with_zone_index(uri: &str, index: u32) -> String {
    let Some(open) = uri.find('[') else {
        return uri.to_string();
    };
    let Some(close) = uri[open..].find(']').map(|at| open + at) else {
        return uri.to_string();
    };
    if uri[open + 1..close].contains('%') {
        return uri.to_string();
    }
    format!("{}%{}{}", &uri[..close], index, &uri[close..])
}

/// The interface's index, for the listen URI. Go's `net` resolves the name for
/// every zone it is given; ours has to do it once, here.
fn iface_index(iface: &str) -> Option<u32> {
    roots_client::multicast::interface_index(iface).ok()
}

/// The bound address and port out of a served URI.
///
/// `spawn_listeners` answers with the URI it bound, in the form
/// `tls://[addr%iface]:port` (`listen.rs:47-49`). Go reports the listener's
/// `Addr().String()`, which is that same form **without** the scheme, so the
/// scheme is stripped rather than reconstructed.
fn bound_addr(uri: Option<&String>) -> Option<(String, u16)> {
    let uri = uri?;
    let addr = uri.split_once("://")?.1;
    let port = addr.rsplit_once(':')?.1.parse().ok()?;
    Some((addr.to_string(), port))
}

/// Dial a peer we discovered, once.
///
/// Go uses `CallPeer`, which does not add a persistent peer and does not
/// redial (`core/api.go:221-223`), and `persistent: false` is ours for the same
/// thing: the link lives as long as it does, and a node that has gone away is
/// found again by the next beacon rather than by a backoff loop.
fn dial_once(tx: &tokio::sync::mpsc::UnboundedSender<Cmd>, uri: &str, sintf: &str) {
    let _ = tx.send(Cmd::Dial {
        uri: uri.to_string(),
        sintf: sintf.to_string(),
        persistent: false,
        respond: None,
    });
}

async fn run(
    client: Client,
    mut conn: roots::AnyConn,
    hold: Option<std::time::Duration>,
    resolve: Option<roots::address::Address>,
) {
    show("remote", &conn.remote_key);
    let (peer_key, link_id) = (conn.remote_key, conn.id);
    let mut router = Router::new(client.key);
    let mut no_out = Vec::new();
    if let Err(e) = router.register(&mut conn, peer_key, link_id).await {
        eprintln!("register failed: {e}");
        std::process::exit(1);
    }
    let mut links = roots::LinkSet::single(conn);
    // Converge first so resolve/session have a tree to work with.
    let end = std::time::Instant::now() + Duration::from_secs(60);
    while router.parent().is_none() && std::time::Instant::now() < end {
        if let Err(e) = router
            .serve(&mut links, Some(Duration::from_millis(250)), &mut no_out)
            .await
        {
            eprintln!("link dropped: {e}");
            std::process::exit(1);
        }
    }
    if router.parent().is_none() {
        eprintln!("mesh convergence timed out");
        std::process::exit(1);
    }
    if let Some(addr) = resolve {
        match router
            .resolve(&mut links, link_id, &addr, Duration::from_secs(60))
            .await
        {
            Ok(key) => {
                show("target", &key);
                if let Err(e) = router.request_nodeinfo(&mut links, key).await {
                    eprintln!("nodeinfo request failed: {e}");
                } else {
                    // Pump briefly for the reply.
                    let end = std::time::Instant::now() + Duration::from_secs(15);
                    while std::time::Instant::now() < end {
                        if router.proto_inbox.iter().any(|(k, p)| {
                            *k == key && p.first() == Some(&roots::proto::PROTO_NODEINFO_RES)
                        }) {
                            break;
                        }
                        if let Err(e) = router
                            .serve(&mut links, Some(Duration::from_millis(250)), &mut no_out)
                            .await
                        {
                            eprintln!("link dropped: {e}");
                            std::process::exit(1);
                        }
                    }
                    for (k, p) in router.proto_inbox.drain(..).filter(|(k, _)| *k == key) {
                        println!(
                            "nodeinfo {}: {}",
                            hex::encode(k),
                            String::from_utf8_lossy(&p[1..])
                        );
                    }
                }
            }
            Err(e) => eprintln!("resolve failed: {e}"),
        }
    }
    if let Err(e) = router.serve(&mut links, hold, &mut no_out).await {
        eprintln!("link dropped: {e}");
        std::process::exit(1);
    }
    report(&router);
}

#[tokio::main]
async fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let flags = Flags::parse(&argv);
    if let Some(msg) = &flags.rejected {
        // Go's `flag` package stops here too: a flag we do not define must not
        // turn into a silently different run.
        eprintln!("roots: {msg}\n{USAGE}");
        std::process::exit(2);
    }
    if flags.help {
        println!("{USAGE}");
        return;
    }
    if let Some(cfg) = config_stage(&flags) {
        boot(cfg).await;
        return;
    }

    let mut positional = flags.positionals.iter();
    let uri = positional
        .next()
        .cloned()
        .unwrap_or_else(|| "tcp://bode.theender.net:42069".to_string());
    let hold_secs: u64 = positional.next().and_then(|s| s.parse().ok()).unwrap_or(45);
    let hold = Some(Duration::from_secs(hold_secs));
    let resolve = positional.next().and_then(|s| {
        s.parse::<std::net::Ipv6Addr>()
            .ok()
            .map(|ip| roots::address::Address(ip.octets()))
    });
    let mut rng = rand::thread_rng();
    let key = ed25519_dalek::SigningKey::generate(&mut rng);
    let client = Client::new(key);
    println!("local  addr {}", client.address());
    // Single scheme-erased dial path (see `link::dial_any`).
    match client.connect_any(&uri).await {
        Ok(conn) => run(client, conn, hold, resolve).await,
        Err(e) => {
            eprintln!("connect failed: {e}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod zone_tests {
    use super::with_zone_index;

    /// The library's `Bind` URI has no zone because Go passes the interface to
    /// `ListenLocal` separately (`multicast.go:322-330`), and ours has to put it
    /// in the address for a `bind()`.
    ///
    /// An **index**, not a name: this exact bug was found by running two nodes,
    /// where `tls://[fe80::…%enp3s0]:0` failed with `Name or service not known`
    /// while the beacon carrying the same name worked fine. The beacon is a
    /// `sendto`, the listener is a `bind`, and only the second needs a number.
    #[test]
    fn the_zone_go_passes_separately_goes_into_the_address_as_an_index() {
        assert_eq!(
            with_zone_index("tls://[fe80::1]:0?password=&priority=0", 2),
            "tls://[fe80::1%2]:0?password=&priority=0"
        );
    }

    /// A URI that already carries a zone is left alone, so binding twice does not
    /// append a second one.
    #[test]
    fn an_existing_zone_is_not_replaced() {
        assert_eq!(
            with_zone_index("tls://[fe80::1%3]:0", 2),
            "tls://[fe80::1%3]:0"
        );
    }

    /// Anything without a bracketed address has no zone slot, and inventing one
    /// would produce a URI nothing can parse.
    #[test]
    fn a_uri_with_no_address_is_untouched() {
        for uri in ["tcp://127.0.0.1:0", "tls://host:0", ""] {
            assert_eq!(with_zone_index(uri, 2), uri);
        }
        // An unclosed bracket is not an address either.
        assert_eq!(with_zone_index("tls://[fe80::1:0", 2), "tls://[fe80::1:0");
    }
}
