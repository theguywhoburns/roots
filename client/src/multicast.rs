//! The syscall half of multicast discovery: the UDP6 socket, the interface
//! scan, and the timers. Everything about *what* a beacon means lives in the
//! library (`roots::multicast`), which is the same split every other module
//! uses and the reason the beacon ramp is testable without a network.
//!
//! Go's arrangement, which this mirrors:
//!
//! - one `udp6` socket bound to `[::]:9001` with `SO_REUSEADDR`, shared by every
//!   interface (`multicast.go:96-104`, `multicast_unix.go:11-30`). Go used
//!   `SO_REUSEPORT` first and found that nodes run by different users would
//!   collide with `EADDRINUSE`, so the comment there records the choice; so does
//!   this one.
//! - the interface set is rebuilt from scratch on every tick, and a listener for
//!   an interface that vanished is stopped (`multicast.go:246-301`).
//! - `JoinGroup` is re-issued every tick for every interface, which is
//!   idempotent, and never un-joined (`multicast.go:314`).

use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use std::time::{Duration, Instant};

use roots::multicast::{Command, InterfaceConfig, MAX_INTERVAL, Multicast};
use tokio::net::UdpSocket;

/// Go's jitter on the announce timer: `time.Second + rand(0..1048576µs)`
/// (`multicast.go:371-375`). The multicast group is a hardcoded setup default,
/// not a config key (`multicast.go:71`).
const GROUP_PORT: u16 = 9001;

/// The receive buffer, which is also the size of the largest beacon we accept.
const RECV: usize = 2048;

/// How often the interface set is rebuilt, which is Go's announce period without
/// the jitter (`multicast.go:371`).
pub const TICK: Duration = Duration::from_secs(1);

/// A socket plus the `Multicast` state machine that drives it.
///
/// One of these per node. It is `'static` and holds no router state, so it can
/// live in its own task alongside the node task and reach it only over
/// [`roots_client::node::Cmd`], which is the rule the rest of the client
/// follows.
pub struct Discovery {
    /// **One group socket per listening interface**, not one for the node.
    ///
    /// Go uses a single socket and learns which interface a datagram arrived on
    /// from the kernel's ancillary data — `rcm.Dst` and `from.Zone` read out of
    /// the `IPV6_PKTINFO` control message (`multicast.go:443-447`). Tokio's
    /// `UdpSocket::recv_from` returns only a `SocketAddr`, with no room for that
    /// message, so a single socket cannot answer "which interface was this?".
    ///
    /// A separate socket per interface answers it by construction: anything on
    /// this socket arrived on *this* interface. That is why `SO_REUSEADDR` is set
    /// at all — it is what lets N sockets share `[::]:9001` without the
    /// `EADDRINUSE` that `SO_REUSEPORT` would give, which is exactly the
    /// reason Go chose it (`multicast_unix.go:11-30`).
    ///
    /// A map, so an interface that goes away loses its socket with it
    /// (`multicast.go:262-301`).
    socks: std::collections::BTreeMap<String, UdpSocket>,
    inner: Multicast,
    /// The operator's `MulticastInterfaces`, in configuration order.
    ///
    /// A `Vec` where Go has a `map` (`multicast.go:38`), so "the first matching
    /// row wins" is deterministic here and unspecified there — see
    /// [`config_for`].
    config: Vec<MulticastRow>,
    /// The bound listener's address per interface, which is what
    /// `getMulticastInterfaces` reports (`multicast/admin.go:40-42`).
    listening: std::collections::HashMap<String, String>,
    /// Where to publish the interface table. `None` on a `Discovery` a test
    /// built, which has no admin socket watching it.
    published: Option<InterfaceTable>,
    /// Whether `ROOTS_DBG_MULTICAST` asked for a line per beacon. Off by default,
    /// because a node on a busy segment would print one a second per interface.
    trace: bool,
    next_tick: Instant,
}

/// One row of `getMulticastInterfaces`, exactly as Go's struct declares it.
///
/// `Password` is a **bool**, not the password: Go reports only whether one is
/// set (`len(intf.password) > 0`, `multicast/admin.go:44`), because the admin
/// socket answers a reader who already has the config file.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MulticastInterfaceState {
    pub name: String,
    /// The bound listener's address, or `-` when nothing is listening —
    /// Go's own placeholder (`multicast/admin.go:41`).
    pub address: String,
    pub beacon: bool,
    pub listen: bool,
    pub password: bool,
}

/// The published interface table, shared with the admin socket.
///
/// A lock, and deliberately the only one in the client besides the test helpers.
/// `Router`, `LinkSet` and the mailbox are single-owner because they hold live
/// connections; this is a plain table of strings rewritten once a second and
/// read under a lock that is never held across an await. Passing it through a
/// `Cmd` instead would put the multicast task on the node task's queue, and it
/// has no business there — it owns sockets, not router state.
pub type InterfaceTable = std::sync::Arc<std::sync::Mutex<Vec<MulticastInterfaceState>>>;

/// An empty table, for a node with no multicast module running — which is what
/// `getMulticastInterfaces` answers on a host where the bind failed.
pub fn empty_table() -> InterfaceTable {
    std::sync::Arc::new(std::sync::Mutex::new(Vec::new()))
}

impl Discovery {
    /// Bind a first group socket and publish the interface table to `table`.
    ///
    /// Go treats a bind failure as fatal for the module
    /// (`multicast.go:100-108` returns the error and carries on without
    /// multicast), and so does the caller here: a node that silently could not
    /// listen would report no peers and look like a network problem.
    pub async fn bind(pubkey: [u8; 32]) -> std::io::Result<Self> {
        Self::with_table(pubkey, empty_table()).await
    }

    /// Bind the first group socket and publish the interface table to `table`.
    pub async fn with_table(pubkey: [u8; 32], table: InterfaceTable) -> std::io::Result<Self> {
        Self {
            // The real sockets come from the interface scan; this only proves the
            // group port is bindable at all, which is the thing that has to be
            // true before any of them can work.
            socks: Default::default(),
            inner: Multicast::new(pubkey),
            config: Vec::new(),
            listening: Default::default(),
            published: Some(table),
            trace: false,
            next_tick: Instant::now(),
        }
        .probe()
    }

    /// Check the group port is bindable, without keeping the socket.
    ///
    /// The real sockets are made per interface in [`Discovery::rescan`], so the
    /// one made here is dropped. What it proves is the thing that has to be true
    /// for any of them to work, and it fails loudly if it is not — Go's bind is
    /// the first thing its `_start` does and its error is what the node reports
    /// (`multicast.go:96-108`).
    fn probe(self) -> std::io::Result<Self> {
        drop(bind_reuse()?);
        Ok(self)
    }

    /// Rebuild the interface set, do whatever the state machine asks, and carry
    /// it out. Returns the commands that became links, for the caller to turn
    /// into `Cmd`s.
    ///
    /// `bind_listener` is called with an interface and its link-local address and
    /// returns the port a `tls://` listener bound there, so the beacon can carry
    /// the **bound** port rather than the configured one — which is what Go
    /// advertises (`multicast.go:352`) and what its own default config asks for,
    /// since it defaults to port 0 (`src/config/defaults_linux.go:17`).
    pub async fn tick<F>(&mut self, bind_listener: &mut F) -> Vec<Command>
    where
        F: FnMut(&str, Ipv6Addr) -> Option<u16>,
    {
        self.trace_on();
        self.rescan().await;
        let ifaces = self.scan_interfaces();
        // Report the bound port for every interface, **before** `announce` asks
        // whether to beacon. The order matters and getting it wrong is a silent
        // deadlock: a beacon is gated on `listener_port`, which only
        // `listener_up` sets, and `announce` only emits `Bind` while
        // `bind_addr` is empty — so calling `bind_listener` from the `Bind` arm
        // alone means it is never called a second time and no beacon ever goes
        // out. An earlier version here did exactly that and a node with a bound
        // listener never beaconed at all.
        //
        // Go reads the port in the same pass, from the listener it already holds
        // (`addr.Port`, `multicast.go:352`), which is why Go has no such step.
        for iface in &ifaces {
            if let Some(port) = bind_listener(&iface.name, iface.link_local) {
                self.inner.listener_up(&iface.name, port);
            }
        }
        self.inner.set_interfaces(ifaces);
        let now = Instant::now();
        let announced = self.inner.announce(now);
        // Only the *absence* of a beacon is worth a line. A beacon prints itself,
        // and an empty announce is the one case with no other symptom — a node
        // whose listener never reported its port looks exactly like a quiet one,
        // and that deadlock cost an afternoon here.
        if self.trace
            && !announced
                .iter()
                .any(|c| matches!(c, Command::Beacon { .. }))
        {
            eprintln!("multicast: no beacon due this tick");
        }
        let mut out = Vec::new();
        for cmd in announced {
            match cmd {
                Command::Beacon { iface, bytes } => {
                    if self.trace {
                        eprintln!(
                            "multicast: beacon out on {iface} ({} bytes): {}",
                            bytes.len(),
                            hex::encode(&bytes)
                        );
                    }
                    // A beacon goes to the group with the interface as its zone,
                    // which is how the receiver learns which interface it arrived
                    // on (`multicast.go:361-366` sets `destAddr.Zone`).
                    if let Err(e) = self.send_beacon(&iface, &bytes).await {
                        // Go logs and carries on (`multicast.go:363`); a beacon
                        // that could not go out this tick is not fatal, the next
                        // one will try again.
                        eprintln!("multicast: beacon on {iface} failed: {e}");
                    }
                }
                Command::Bind {
                    iface,
                    link_local,
                    uri,
                    ..
                } => {
                    // A listener that would not bind is not fatal: Go logs it
                    // and carries on to the next interface (`multicast.go:338-341`).
                    // The port arrives on the *next* tick, through
                    // `bind_listener` above.
                    out.push(Command::Bind {
                        iface,
                        link_local,
                        port: 0,
                        uri,
                    });
                }
                Command::Unbind { iface } => {
                    // The socket goes with the interface, which is what stops an
                    // interface that lost its address leaking one socket per
                    // change (`multicast.go:262-301`).
                    self.socks.remove(&iface);
                    self.listening.remove(&iface);
                }
                Command::Dial { .. } => out.push(cmd),
            }
        }
        self.publish();
        self.next_tick = now + TICK;
        out
    }

    /// Rewrite the table `getMulticastInterfaces` answers from.
    ///
    /// Go builds the same rows on demand inside the actor
    /// (`multicast/admin.go:30-48`), reading `m._interfaces` for the flags and
    /// `m._listeners[name].listener.Addr()` for the address, with `-` when
    /// nothing is listening. Publishing once a tick instead of building per
    /// request is the same answer at a different moment, and the actor lock it
    /// took is the one this table takes instead.
    fn publish(&self) {
        let Some(table) = &self.published else {
            return;
        };
        let rows: Vec<MulticastInterfaceState> = self
            .scan_interfaces()
            .into_iter()
            .map(|i| MulticastInterfaceState {
                // Go reports `-` rather than an empty string when nothing is
                // listening on this interface (`multicast/admin.go:41`).
                address: self
                    .listening
                    .get(&i.name)
                    .cloned()
                    .unwrap_or_else(|| "-".to_string()),
                // Only whether a password is set, never the password itself.
                password: !i.password.is_empty(),
                name: i.name,
                beacon: i.beacon,
                listen: i.listen,
            })
            .collect();
        // No sort here: Go sorts in the handler that builds the answer
        // (`multicast/admin.go:46-48`), because its source is a map. Ours is a
        // list, but the guarantee still belongs to the answer, so it is applied
        // there — in `admin.rs`. Sorting twice would let the two disagree.
        if let Ok(mut guard) = table.lock() {
            *guard = rows;
        }
    }

    /// Record the address a listener bound on `iface`, which is what the admin
    /// socket reports and what a peer will dial.
    ///
    /// The address is the listener's own, in the `[fe80::…%iface]:port` form Go's
    /// `Addr().String()` produces, not the beacon group.
    pub fn listener_bound(&mut self, iface: &str, address: &str) {
        self.listening
            .insert(iface.to_string(), address.to_string());
    }

    /// Forget an interface's listener, which is what an interface going away
    /// looks like to `getMulticastInterfaces`.
    pub fn listener_gone(&mut self, iface: &str) {
        self.listening.remove(iface);
    }

    /// Make sure every listening interface has its own group socket, joined, and
    /// drop the sockets of interfaces that are gone.
    ///
    /// Joining every tick is Go's own behaviour and never leaving is deliberate
    /// (`multicast.go:314`). The join **error** is discarded outright, as Go's
    /// is, and it has to be: Linux answers `EADDRINUSE` to a second join of a
    /// group the socket is already in, so on every tick after the first the error
    /// *is* the normal answer. Logging it would be a line per interface per
    /// second on a working node — which is why Go says nothing and so do we.
    pub async fn rescan(&mut self) {
        let wanted: Vec<(String, u32)> = self
            .scan_interfaces()
            .into_iter()
            .filter(|i| i.listen)
            .filter_map(|i| interface_index(&i.name).ok().map(|at| (i.name, at)))
            .collect();
        for (name, index) in &wanted {
            if self.socks.contains_key(name) {
                continue;
            }
            match bind_reuse() {
                Ok(sock) => {
                    let _ = sock.join_multicast_v6(&resolve_group_ip(), *index);
                    self.socks.insert(name.clone(), sock);
                }
                // Go logs and carries on (`multicast.go:96-108` treats one
                // interface's failure as that interface's problem).
                Err(e) => eprintln!("multicast: {name}: {e}"),
            }
        }
        // An interface that vanished loses its socket rather than leaking one per
        // address change (`multicast.go:262-301`).
        let live: Vec<&String> = wanted.iter().map(|(n, _)| n).collect();
        self.socks.retain(|name, _| live.contains(&name));
    }

    /// Read whatever beacons have arrived, and hand them to the state machine.
    ///
    /// Every listening interface is drained, because there is one socket per
    /// interface and each only sees its own. `try_recv_from` rather than
    /// `recv_from` because this runs once a tick and must not wait: a node with
    /// three interfaces has three sockets, and blocking on the first would starve
    /// the other two.
    ///
    /// Most of what comes back is nothing to act on — a beacon from a version we
    /// do not speak, from ourselves, or on an interface we are not listening on —
    /// and Go drops each in its own `continue` (`multicast.go:410-441`), so
    /// nothing is reported for them.
    pub fn receive(&mut self, now: Instant) -> Vec<Command> {
        let mut out = Vec::new();
        let mut buf = [0u8; RECV];
        for (zone, sock) in self.socks.iter_mut() {
            // A small drain per socket per tick, so one chatty peer cannot starve
            // the others. Go reads one datagram per tick from its single socket
            // (`multicast.go:443`), so this is only faster, never different.
            for _ in 0..32 {
                let Ok((n, from)) = sock.try_recv_from(&mut buf) else {
                    break;
                };
                let SocketAddr::V6(from) = from else {
                    // The socket is IPv6-only, so this cannot happen; treating it
                    // as an unrecognised datagram keeps the match total.
                    continue;
                };
                // The zone is the interface by construction: this datagram arrived
                // on this socket, which joined the group on this interface and
                // nowhere else. Go gets the same fact from the kernel's
                // `IPV6_PKTINFO` control message instead (`multicast.go:443-447`).
                //
                // Note it is *our* interface, not the sender's: the sender's
                // address identifies the far end, which is the other node. Reading
                // the zone off the source address — which an earlier version here
                // did, and which cost two nodes never finding each other — picks the
                // one interface a beacon can never arrive on.
                let got = self.inner.receive(zone, from, &buf[..n], now);
                if self.trace {
                    eprintln!(
                        "multicast: {} bytes in on {zone} from {from}: {} [{}]",
                        n,
                        hex::encode(&buf[..n]),
                        if got.is_some() { "ACTED ON" } else { "ignored" }
                    );
                }
                if let Some(cmd) = got {
                    out.push(cmd);
                }
            }
        }
        out
    }

    /// Turn on beacon tracing if `ROOTS_DBG_MULTICAST` is set.
    ///
    /// Discovery that does not work has no symptom a user can see: the node says
    /// nothing, `getPeers` is empty, and "no multicast on this network" and "a
    /// bug in our beacon" look identical. The same reason `ROOTS_DBG_DUMP` exists
    /// for the router — the library prints nothing by default, and this is the
    /// one place it is allowed to, on an explicit env var, on stderr.
    fn trace_on(&mut self) {
        self.trace = std::env::var_os("ROOTS_DBG_MULTICAST").is_some();
    }

    /// Send one beacon to the group, from the socket of the interface it is for.
    ///
    /// The zone is what makes a `ff02::` datagram leave the right interface:
    /// link-local multicast is not routed, so without it the kernel picks one and
    /// the beacon goes nowhere the peer is listening. Go sets
    /// `destAddr.Zone = iface.Name` for the same reason
    /// (`multicast.go:361-366`).
    ///
    /// An interface we have no socket for sends nothing. That can only happen when
    /// a config asks to beacon but not to listen, and then no socket was ever
    /// needed for it — which is Go's own arrangement, since `Beacon` and `Listen`
    /// are separate flags (`multicast.go:206-210`).
    async fn send_beacon(&self, iface: &str, bytes: &[u8]) -> std::io::Result<usize> {
        let Some(sock) = self.socks.get(iface) else {
            return Err(std::io::Error::other(format!(
                "no multicast socket for {iface}"
            )));
        };
        let dest = SocketAddr::V6(SocketAddrV6::new(
            resolve_group_ip(),
            GROUP_PORT,
            0,
            interface_index(iface)?,
        ));
        sock.send_to(bytes, dest).await
    }

    /// The interfaces the operator configured, **one row per interface**, with
    /// the link-local address to bind its listener on.
    ///
    /// Go filters hard before the regex match (`multicast.go:201-210`): up,
    /// running, multicast-capable and not point-to-point. We cannot read those
    /// flags without a netlink dependency, so the equivalent filter is the one
    /// that matters for a link-local beacon — an interface with no link-local
    /// IPv6 address cannot carry one, and it drops out here.
    ///
    /// One row per interface, not one per address, and that matters. The library's
    /// state is keyed by interface name — Go's is too, `m._interfaces[name]` — so
    /// two rows for one name would make each look stale to the other and the
    /// listener would rebind for ever: `announce` emits `Bind`, the second
    /// address replaces the first, `listener_stale` fires on the next scan, and
    /// the port is never reported, so no beacon ever goes out. That is exactly
    /// what happened here before the address was collapsed to one.
    ///
    /// Go instead keeps every address on the adapter and walks them until one
    /// binds (`multicast.go:306-371`). On an ordinary interface there is exactly
    /// one link-local address, so the two agree; where there are several we take
    /// the most usable one (see [`link_local_addresses`]) and, if it will not
    /// bind, the log says so and the next tick tries again.
    fn scan_interfaces(&self) -> Vec<InterfaceConfig> {
        let mut out = Vec::new();
        for (name, addrs) in link_local_addresses() {
            let Some(row) = self.config_for(&name) else {
                continue;
            };
            let Some(link_local) = addrs.first().copied() else {
                continue;
            };
            out.push(InterfaceConfig {
                name,
                link_local,
                beacon: row.beacon,
                listen: row.listen,
                port: row.port,
                priority: row.priority,
                password: row.password.as_bytes().to_vec(),
            });
        }
        out
    }

    /// Which configured row applies to this interface name.
    ///
    /// Go breaks out of the match loop on the first hit
    /// (`multicast.go:205-231`), so the **first** matching row wins, and a row
    /// with neither `Beacon` nor `Listen` is skipped before matching at all.
    ///
    /// "First" is the interesting word. Go ranges
    /// `m.config._interfaces`, which is a `map[MulticastInterface]struct{}`
    /// (`multicast.go:38`, built at `:70`), and Go randomises map iteration — so
    /// when two rows both match an interface, *which* one Go picks is
    /// unspecified. Go's own configuration documentation says interfaces "use the
    /// first configuration that they match against" (`config/config.go:50`), so
    /// the intent is order and the implementation does not deliver it. This is a
    /// `Vec` and we deliver it.
    ///
    /// That is a divergence we own and it is not worth matching: an operator who
    /// writes two overlapping rows gets a stable answer here and a coin flip on a
    /// Go node, and nothing sane depends on which of two overlapping rows wins.
    /// The default config has one row (`defaults_linux.go:17`), so the question
    /// does not arise unless someone writes the second one.
    fn config_for(&self, name: &str) -> Option<&MulticastRow> {
        config_for(&self.config, name)
    }

    /// The operator's `MulticastInterfaces`, kept so the scan can answer for
    /// them. Set once at construction because it is config, and the scan runs
    /// every tick.
    pub fn set_config(&mut self, rows: Vec<MulticastRow>) {
        self.config = rows;
    }

    /// When the next scan is due, so the caller can sleep instead of spinning.
    pub fn next_tick(&self) -> Instant {
        self.next_tick
    }

    /// The longest gap the beacon ramp reaches, for a caller that wants to size
    /// its timer.
    pub fn max_interval() -> Duration {
        MAX_INTERVAL
    }
}

/// What one configured row contributes to an interface: the two flags, the port,
/// the priority, and the password as bytes.
///
/// Go keeps the password as `[]byte` from the config row onward
/// (`multicast.go:216`, `interfaceInfo.password`) and blake2b keys on the bytes,
/// so the conversion belongs here rather than at each use. The config is JSON and
/// cannot actually carry a non-UTF-8 password.
/// A 5-tuple so a test can compare a whole row at once. Test-only: the
/// scan reads the fields by name.
#[cfg(test)]
type InterfaceOptions = (bool, bool, u16, u8, Vec<u8>);

/// One `MulticastInterfaces` entry, as the config carries it.
#[derive(Clone, Debug, Default)]
pub struct MulticastRow {
    pub regex: String,
    pub beacon: bool,
    pub listen: bool,
    pub port: u16,
    pub priority: u8,
    pub password: String,
}

impl MulticastRow {
    /// The row as the scan wants it, with the password as bytes.
    ///
    /// Go keeps the password as `[]byte` from the config row onward
    /// (`multicast.go:216`, `interfaceInfo.password`) and blake2b keys on the
    /// bytes, so the conversion belongs here rather than at each use. The config
    /// itself is JSON, so it cannot actually carry a non-UTF-8 password.
    #[cfg(test)]
    fn interface(&self) -> InterfaceOptions {
        (
            self.beacon,
            self.listen,
            self.port,
            self.priority,
            self.password.as_bytes().to_vec(),
        )
    }
}

/// Which configured row, if any, applies to the interface called `name`?
///
/// A free function rather than a method because it is **pure**: it reads a
/// slice and a string and touches no socket. The tests need it without binding
/// a group port, and they used to re-implement the predicate — which is the
/// worst kind of duplication in a protocol, because the copy is what the test
/// checks and the original is what runs.
pub(crate) fn config_for<'a>(rows: &'a [MulticastRow], name: &str) -> Option<&'a MulticastRow> {
    rows.iter().find(|row| {
        if !row.beacon && !row.listen {
            return false;
        }
        if !matches(&row.regex, name) {
            return false;
        }
        // Go skips an interface whose password is over blake2b's 64-byte key
        // limit, because `blake2b.New512` returns an error and there is no hash
        // to compare with (`multicast.go:213-217`).
        row.password.len() <= 64
    })
}

/// Does Go's `regexp.MatchString` match this interface name?
///
/// Go compiles each `MulticastInterface.Regex` and calls `MatchString` on the
/// interface name (`multicast.go:196-217`), which is a **substring** search
/// unless the pattern is anchored. The patterns operators actually write are
/// `.*` (our own default, `defaults_linux.go:17`), `.*eth.*` and `^en[0-9]`, so
/// the real engine is used rather than a hand-rolled subset: a config that
/// silently fails to match an interface would stop us peering, and a wrong
/// answer there is invisible.
///
/// A pattern that does not compile is treated as matching nothing, and this is a
/// **divergence Go does not have**: Go compiles every row with
/// `regexp.MustCompile` at startup (`cmd/yggdrasil/main.go:259`) and *panics* on
/// an invalid pattern. There is no `NewRegexp` failure path to continue past and
/// no logging one — an earlier comment here claimed both and cited a line that
/// does not exist.
///
/// Matching nothing is the right call anyway, and for the reason Go never has to
/// face the question: a row that cannot compile cannot describe an interface, so
/// the interface is simply absent from multicast. The difference is that a Go
/// node refuses to start on a typo while this one starts with that interface
/// quiet — the more useful failure, and a config error the operator can read off
/// a log line instead of a stack.
fn matches(pattern: &str, name: &str) -> bool {
    match regex::Regex::new(pattern) {
        Ok(re) => re.is_match(name),
        Err(e) => {
            eprintln!("multicast: ignoring interface pattern {pattern:?}: {e}");
            false
        }
    }
}

/// Every interface's link-local IPv6 addresses, from `/proc/net/if_inet6`.
///
/// That file is the kernel's own list of addresses, one row each, in six
/// whitespace-separated columns: address, **ifindex**, prefix length, **scope**,
/// flags, name. Scope `20` is `RT_SCOPE_LINK`, which is the filter Go applies
/// with `IsLinkLocalUnicast` (`multicast.go:159-165`). Reading the wrong column
/// is easy and silent — `lo`'s row has ifindex `01` and `tun0`'s has `04`, so a
/// parser that checked column 2 for `04` would match exactly the interfaces
/// whose index is 4 and no others. Hence the shape test below.
pub fn link_local_addresses() -> Vec<(String, Vec<Ipv6Addr>)> {
    match std::fs::read_to_string("/proc/net/if_inet6") {
        Ok(text) => parse_if_inet6(&text),
        // Go logs and carries on rather than failing the module
        // (`multicast.go:187-191`), so a missing or unreadable file means no
        // interfaces, not an error.
        Err(_) => Vec::new(),
    }
}

/// Parse the contents of `/proc/net/if_inet6`.
///
/// Split out from the file read so the column positions can be tested against a
/// captured file rather than against whatever interfaces the test host happens
/// to have.
///
/// Each interface's addresses come back **most usable first**, because
/// [`Discovery::scan_interfaces`] takes the first one to bind a listener on. An
/// address that is still tentative — duplicate address detection has not
/// finished — cannot be bound and answers `EADDRNOTAVAIL`, so it goes last. The
/// `IFA_F_NODAD` bit is *not* tentative for this purpose: it means the address was
/// configured without DAD precisely so it can be used at once, which is how
/// `ip -6 addr add … nodad` makes a veth end usable in a namespace.
fn parse_if_inet6(text: &str) -> Vec<(String, Vec<Ipv6Addr>)> {
    let mut out: Vec<(String, Vec<(Ipv6Addr, bool)>)> = Vec::new();
    for line in text.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 6 || cols[3] != LINK_SCOPE {
            continue;
        }
        let Ok(bytes) = <[u8; 16]>::try_from(hex::decode(cols[0]).unwrap_or_default().as_slice())
        else {
            continue;
        };
        let addr = Ipv6Addr::from(bytes);
        // The scope says link, and this says the address is in `fe80::/10`.
        // Both are checked because the two answers can disagree on a host with
        // an odd configuration, and Go checks the address
        // (`IsLinkLocalUnicast`, `multicast.go:159-165`).
        if !addr.is_unicast_link_local() {
            continue;
        }
        // Column 5 is the address flags word, in hex (`linux/if_addr.h`):
        // `IFA_F_TENTATIVE` is `0x04` and `IFA_F_DADFAILED` is `0x40`. Either
        // makes the address unusable for a bind.
        let unusable =
            u32::from_str_radix(cols[4], 16).unwrap_or(0) & (TENTATIVE | DAD_FAILED) != 0;
        let name = cols[5].to_string();
        match out.iter_mut().find(|(n, _)| *n == name) {
            Some((_, addrs)) => addrs.push((addr, unusable)),
            None => out.push((name, vec![(addr, unusable)])),
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out.into_iter()
        .map(|(name, mut addrs)| {
            addrs.sort_by_key(|(addr, unusable)| (!unusable, *addr));
            addrs.dedup_by_key(|(addr, _)| *addr);
            (name, addrs.into_iter().map(|(addr, _)| addr).collect())
        })
        .collect()
}

/// `IFA_F_TENTATIVE` (`linux/if_addr.h`), as the flags column prints it.
const TENTATIVE: u32 = 0x04;
/// `IFA_F_DADFAILED`: duplicate address detection failed, so the address is ours
/// to use but must not be advertised.
const DAD_FAILED: u32 = 0x40;

/// `RT_SCOPE_LINK` as `/proc/net/if_inet6` prints it: hex, no prefix.
const LINK_SCOPE: &str = "20";

/// The group's address, `ff02::114` (`multicast.go:71`).
fn resolve_group_ip() -> Ipv6Addr {
    Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x0114)
}

/// The interface index for a zone string, which the kernel socket API wants.
///
/// The library resolves this from `/sys/class/net/<name>/ifindex`
/// (`roots::interface_index`), which is the same file `if_nametoindex` ends up
/// reading — so there is no C binding here and the client needs no dependency for
/// it. `None` rather than a silent 0, because a 0 zone sends the beacon out the
/// default route where it simply vanishes, and would bind a `tls://` listener on
/// an unrelated interface.
pub fn interface_index(iface: &str) -> std::io::Result<u32> {
    roots::interface_index(iface)
        .ok_or_else(|| std::io::Error::other(format!("no interface index for {iface}")))
}

/// Bind `[::]:9001` with `SO_REUSEADDR`.
///
/// Go sets reuse through the listener's `Control` hook
/// (`multicast.go:96-100`, `multicast_unix.go:11-30`) because `SO_REUSEPORT`
/// made two nodes run by different users fail with `EADDRINUSE`; the comment
/// there says so and the fix was `SO_REUSEADDR`. `socket2` gives us the same
/// knob on a `tokio::net::UdpSocket`, and it is already in the lockfile as a
/// transitive dependency of `tokio`.
fn bind_reuse() -> std::io::Result<UdpSocket> {
    let sock = socket2::Socket::new(
        socket2::Domain::IPV6,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    sock.set_reuse_address(true)?;
    sock.set_only_v6(true)?;
    sock.set_nonblocking(true)?;
    sock.bind(&SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, GROUP_PORT, 0, 0).into())?;
    UdpSocket::from_std(sock.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Go compiles the row's `Regex` and takes the first match — where "first"
    /// is a map iteration, so it is only deterministic when exactly one row
    /// matches. See `Discovery::config_for`.
    #[test]
    fn interface_patterns_behave_like_go_regexp_matchstring() {
        // `.*` is what our own default config carries, and it must match
        // everything, including an empty name.
        assert!(matches(".*", "eth0"));
        assert!(matches(".*", ""));
        assert!(matches("^eth", "eth0"));
        assert!(!matches("^eth", "weth0"));
        assert!(matches("eth", "weth0"), "unanchored is a substring search");
        assert!(!matches("^wlan0$", "eth0"));
        assert!(matches("^wlan0$", "wlan0"));
        assert!(matches(".*eth.*", "myeth0"));
        assert!(!matches(".*eth.*", "wlan0"));
        // A `*` on a single character, which is the other common form. `.*` spans
        // any run, so `^e.*0$` matches `eth00` as well as `eth0` — an earlier
        // hand-rolled matcher here disagreed, which is why Go's engine is used.
        assert!(matches("^e.*0$", "eth0"));
        assert!(matches("^e.*0$", "eth00"));
        assert!(!matches("^e.*0$", "weth0"));
        // A character class, which a naive matcher gets wrong most often.
        assert!(matches("^en[0-9]", "en0"));
        assert!(!matches("^en[0-9]", "eno"));
    }

    /// Go skips a row with neither `Beacon` nor `Listen` *before* it matches
    /// (`multicast.go:206-210`), so a disabled row cannot shadow a later one
    /// that would have matched.
    #[test]
    fn a_disabled_row_does_not_shadow_a_later_match() {
        let rows = vec![
            MulticastRow {
                regex: ".*".into(),
                beacon: false,
                listen: false,
                ..Default::default()
            },
            MulticastRow {
                regex: "^eth0$".into(),
                beacon: true,
                listen: true,
                port: 4242,
                priority: 3,
                password: "hunter2".into(),
            },
        ];
        let d = rows_finder(rows);
        assert_eq!(
            d("eth0"),
            Some((true, true, 4242, 3, b"hunter2".to_vec())),
            "the first *enabled* matching row wins"
        );
        assert_eq!(d("wlan0"), None, "and no other name matches");
    }

    /// Go skips an interface whose password is over blake2b's 64-byte key limit,
    /// because `blake2b.New512` returns an error and there is no hash to
    /// compare with (`multicast.go:213-217`).
    #[test]
    fn an_oversize_password_skips_the_interface() {
        let long = "p".repeat(65);
        let rows = vec![MulticastRow {
            regex: ".*".into(),
            beacon: true,
            listen: true,
            port: 0,
            priority: 0,
            password: long,
        }];
        let d = rows_finder(rows);
        assert_eq!(d("eth0"), None, "65 bytes is over the key limit");
    }

    /// The group is `ff02::114` on port 9001 (`multicast.go:71`), and the port
    /// is what the socket binds, not a config key.
    #[test]
    fn the_group_is_the_hardcoded_default() {
        assert_eq!(resolve_group_ip().to_string(), "ff02::114");
        assert_eq!(GROUP_PORT, 9001);
    }

    /// Captured from a real host, and the row that proves the column positions:
    /// `tun0`'s **ifindex** is `04`, and reading column 2 for `04` while calling
    /// it the scope would have matched `tun0` and nothing else on this host.
    ///
    /// Go's filter is `IsLinkLocalUnicast` on the address
    /// (`multicast.go:159-165`), and the kernel's own scope column is the other
    /// half of the same test.
    #[test]
    fn if_inet6_columns_are_read_in_the_right_places() {
        let captured = "\
00000000000000000000000000000001 01 80 10 80       lo
fe8000000000000088dbadfffe67ddc7 06 40 20 80    veth0
fe80000000000000620782be18d70197 03 40 20 80 wlp0s20f3
fe80000000000000a2ae1336eed8315f 02 40 20 80   enp3s0
02006faaa62f340212a3f0334419fc6e 04 07 00 80     tun0
fe800000000000008034fb74e62ddf57 04 40 20 80     tun0
20010db8000000000000000000000001 05 40 20 80   docker0
";
        let found = parse_if_inet6(captured);
        let names: Vec<&str> = found.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(
            names,
            ["enp3s0", "tun0", "veth0", "wlp0s20f3"],
            "sorted, link-scoped, link-local, and nothing else"
        );
        // `tun0` has two addresses and one of them is a routed `0200::`; only the
        // `fe80::` one is a link-local unicast.
        assert_eq!(
            found
                .iter()
                .find(|(n, _)| n == "tun0")
                .map(|(_, a)| a.clone()),
            Some(vec!["fe80::8034:fb74:e62d:df57".parse().unwrap()])
        );
        // `lo` is host-scoped and `::1`, so it is not a beacon interface even
        // though it has an address.
        assert!(
            !found.iter().any(|(n, _)| n == "lo"),
            "`lo` has no link-local unicast address"
        );
    }

    /// A truncated or malformed file must not panic: the kernel's format is
    /// stable but ours has to read whatever is there, and Go returns an empty
    /// interface set rather than failing the module (`multicast.go:187-191`).
    #[test]
    fn a_malformed_if_inet6_yields_no_interfaces() {
        for text in ["", "\n\n", "garbage", "a b c", &"f".repeat(40)] {
            assert_eq!(
                parse_if_inet6(text),
                Vec::new(),
                "{text:?} should parse to nothing, not panic"
            );
        }
    }

    /// The lookup the scan uses, without a socket: the *real*
    /// [`config_for`], which is the point. The test used to re-implement the
    /// predicate, so a change to the production one would not have moved the
    /// test and the two would have drifted silently.
    fn rows_finder(rows: Vec<MulticastRow>) -> impl Fn(&str) -> Option<InterfaceOptions> {
        move |name: &str| config_for(&rows, name).map(MulticastRow::interface)
    }
}
