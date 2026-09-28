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

    match bind_admin(&cfg.admin_listen).await {
        Ok(Some(bound)) => {
            eprintln!(
                "{} admin socket listening on {}",
                bound.network(),
                bound.addr()
            );
            tokio::spawn(serve_admin(bound, tx.clone()));
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

    if let Err(e) = node.run().await {
        eprintln!("node: {e}");
        std::process::exit(1);
    }
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
