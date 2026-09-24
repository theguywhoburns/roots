//! The node configuration, in Go's shape: same key names, same defaults, same
//! "generate then overlay" load order, so a config file is interchangeable with
//! `yggdrasil`'s.
//!
//! Port of `reference/yggdrasil-go/src/config/config.go` (`NodeConfig`,
//! `GenerateConfig`, `ReadFrom`, `postprocessConfig`) plus the platform column of
//! `defaults_linux.go` and the printing rules of `cmd/yggdrasil/main.go:120-132`.
//! Citations are to Go's struct fields, because the JSON keys *are* the Go field
//! names — `encoding/json` renamed nothing but `omitempty`.

use std::collections::BTreeMap;
use std::fmt;
use std::io::Read;

use ed25519_dalek::SigningKey;
use ed25519_dalek::pkcs8::DecodePrivateKey;
use roots::{Address, LinkOptions, Subnet, addr_for_key, subnet_for_key};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// Go's `platformDefaultParameters` for Linux (`defaults_linux.go:7-25`). The
/// other platforms differ only in `DefaultAdminListen`, `DefaultIfName` and
/// `DefaultConfigFile`; we build for Linux, so that is the column we mirror.
/// Go's `MaximumIfMTU` is declared but never read anywhere, so it has no twin.
pub const DEFAULT_ADMIN_LISTEN: &str = "unix:///var/run/yggdrasil.sock";
pub const DEFAULT_IF_NAME: &str = "auto";
pub const DEFAULT_IF_MTU: u64 = 65535;

/// Go's `config.KeyBytes` is a `[]byte` that marshals as lowercase hex, and
/// `GenerateConfig` fills it from `ed25519.GenerateKey` — Go's private key is
/// 64 bytes, the seed followed by the public key (`PrivateKey[32:]`).
const PRIVATE_KEY_LEN: usize = 64;

#[derive(Debug)]
pub enum ConfigError {
    Io(std::io::Error),
    Json(serde_json::Error),
    /// `PrivateKey` or an `AllowedPublicKeys` entry was not hex. Go panics
    /// outright on a bad `AllowedPublicKeys` entry (`main.go:224`).
    Hex(String),
    /// A key that decoded but was not 64 bytes (private) or 32 (public).
    Length {
        want: usize,
        found: usize,
    },
    /// Our one deliberate divergence: Go takes `PrivateKey[32:]` as the public
    /// key without checking it, while a `SigningKey` derives its own. A config
    /// whose halves disagree would run with two identities, so we refuse it.
    KeyMismatch,
    /// `PrivateKeyPath` pointed at something that is not a PKCS#8 ed25519 PEM.
    KeyFile(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::Io(e) => write!(f, "config read: {e}"),
            ConfigError::Json(e) => write!(f, "config parse: {e}"),
            ConfigError::Hex(e) => write!(f, "config key: {e}"),
            ConfigError::Length { want, found } => {
                write!(f, "config key: expected {want} bytes, found {found}")
            }
            ConfigError::KeyMismatch => write!(
                f,
                "config key: the public half of PrivateKey does not match its seed"
            ),
            ConfigError::KeyFile(e) => write!(f, "PrivateKeyPath: {e}"),
        }
    }
}

impl std::error::Error for ConfigError {}

impl From<std::io::Error> for ConfigError {
    fn from(e: std::io::Error) -> Self {
        ConfigError::Io(e)
    }
}

impl From<serde_json::Error> for ConfigError {
    fn from(e: serde_json::Error) -> Self {
        ConfigError::Json(e)
    }
}

/// Go's `config.MulticastInterfaceConfig` (`config.go:60-67`). `Priority` is a
/// `uint64` there even though it is a link `uint8` on the wire — the comment
/// says it is only that wide because gobind cannot export `uint8`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
pub struct MulticastIface {
    pub regex: String,
    pub beacon: bool,
    pub listen: bool,
    #[serde(skip_serializing_if = "is_zero_u16")]
    pub port: u16,
    #[serde(skip_serializing_if = "is_zero_u64")]
    pub priority: u64,
    pub password: String,
}

fn is_zero_u16(v: &u16) -> bool {
    *v == 0
}

fn is_zero_u64(v: &u64) -> bool {
    *v == 0
}

fn ser_hex<S: serde::Serializer>(bytes: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&hex::encode(bytes))
}

fn de_hex<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    let s = String::deserialize(d)?;
    hex::decode(s).map_err(serde::de::Error::custom)
}

/// Go's `encoding/json` documents that unmarshalling a `null` into any
/// non-pointer value has no effect, and the value it has no effect on is the
/// one `GenerateConfig` put there — so a `null` key behaves exactly like an
/// absent one, at every depth. serde rejects `null` for a `Vec`/`String`/`bool`
/// field, so we drop those keys before parsing.
fn strip_nulls(value: &mut Value) {
    match value {
        Value::Object(map) => {
            map.retain(|_, v| !v.is_null());
            for v in map.values_mut() {
                strip_nulls(v);
            }
        }
        Value::Array(items) => {
            for v in items {
                strip_nulls(v);
            }
        }
        _ => {}
    }
}

/// Go's `NodeConfig` (`config.go:42-58`), field for field and in declaration
/// order, because that is the order Go's `encoding/json` writes them in.
///
/// `#[serde(default = "defaults")]` is what reproduces Go's load order: `ReadFrom`
/// starts from `GenerateConfig()` and parses the supplied document *on top of*
/// it, so every key that is absent keeps its default (`config.go:112-120`).
/// Absent means absent — an explicit `"Listen": []` still overrides.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default = "defaults", rename_all = "PascalCase")]
pub struct Config {
    /// `PrivateKey KeyBytes` with `json:",omitempty"`.
    #[serde(
        skip_serializing_if = "Vec::is_empty",
        serialize_with = "ser_hex",
        deserialize_with = "de_hex"
    )]
    pub private_key: Vec<u8>,
    /// `PrivateKeyPath` with `omitempty`; read in `postprocess`.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub private_key_path: String,
    pub peers: Vec<String>,
    /// `map[string][]string`; a `BTreeMap` so our output is stable where Go's is
    /// random-ordered.
    pub interface_peers: BTreeMap<String, Vec<String>>,
    pub listen: Vec<String>,
    /// `omitempty`, which is why a generated config has no admin key at all
    /// (`main.go:121` blanks it before marshalling).
    #[serde(skip_serializing_if = "String::is_empty")]
    pub admin_listen: String,
    pub multicast_interfaces: Vec<MulticastIface>,
    pub allowed_public_keys: Vec<String>,
    pub group_password: String,
    pub if_name: String,
    #[serde(rename = "IfMTU")]
    pub if_mtu: u64,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub log_lookups: bool,
    pub node_info_privacy: bool,
    /// `map[string]interface{}`, and `null` when unset — hence `Option`.
    pub node_info: Option<Map<String, Value>>,
}

/// Go's `config.GenerateConfig()` (`config.go:72-91`): the Linux defaults, plus
/// a fresh identity. Calling it is how a config with no `PrivateKey` still boots
/// — with a different address every run, which is exactly Go's behaviour.
pub fn defaults() -> Config {
    let mut rng = rand::thread_rng();
    let key = SigningKey::generate(&mut rng);
    Config {
        private_key: go_private_key_bytes(&key),
        private_key_path: String::new(),
        peers: Vec::new(),
        interface_peers: BTreeMap::new(),
        listen: Vec::new(),
        admin_listen: DEFAULT_ADMIN_LISTEN.to_string(),
        multicast_interfaces: vec![MulticastIface {
            regex: ".*".to_string(),
            beacon: true,
            listen: true,
            ..MulticastIface::default()
        }],
        allowed_public_keys: Vec::new(),
        group_password: String::new(),
        if_name: DEFAULT_IF_NAME.to_string(),
        if_mtu: DEFAULT_IF_MTU,
        log_lookups: false,
        node_info_privacy: false,
        node_info: None,
    }
}

impl Config {
    /// `-genconf`: the generated config as JSON, with `AdminListen` blanked so it
    /// is omitted the way Go's is (`main.go:120-131`).
    ///
    /// Deviation: Go prints HJSON unless `-json`, and its HJSON carries the
    /// struct's `comment:` tags. We only ever speak JSON, which is a subset Go
    /// reads happily — so `-json` is accepted for compatibility and means
    /// nothing to us.
    pub fn generate() -> String {
        let mut cfg = defaults();
        cfg.admin_listen = String::new();
        cfg.to_json()
    }

    /// Go's `ReadFrom`: `-useconf` is stdin, `-useconffile` a path.
    pub fn load(source: &ConfigSource) -> Result<Config, ConfigError> {
        let mut text = String::new();
        match source {
            ConfigSource::Stdin => {
                std::io::stdin().read_to_string(&mut text)?;
            }
            ConfigSource::File(p) => text = std::fs::read_to_string(p)?,
        }
        Self::from_json(&text)
    }

    /// Go's `UnmarshalHJSON`: parse, then postprocess.
    pub fn from_json(text: &str) -> Result<Config, ConfigError> {
        let mut doc: Value = serde_json::from_str(text)?;
        strip_nulls(&mut doc);
        let mut cfg: Config = serde_json::from_value(doc)?;
        cfg.postprocess()?;
        Ok(cfg)
    }

    /// Go's `postprocessConfig` (`config.go:130-154`): a `PrivateKeyPath` wins
    /// over an inline key. Go also regenerates its self-signed TLS certificate
    /// here; we have no certificate to keep, because our `tls://` identity comes
    /// from the `meta` handshake and the listener cert is throwaway
    /// (`src/tls.rs:94`).
    fn postprocess(&mut self) -> Result<(), ConfigError> {
        if self.private_key_path.is_empty() {
            return Ok(());
        }
        let pem = std::fs::read_to_string(&self.private_key_path)
            .map_err(|e| ConfigError::KeyFile(format!("{e}")))?;
        let key =
            SigningKey::from_pkcs8_pem(&pem).map_err(|e| ConfigError::KeyFile(e.to_string()))?;
        self.private_key = go_private_key_bytes(&key);
        Ok(())
    }

    /// The Go-format 64-byte private key (seed followed by public key), which is
    /// what `PrivateKey` holds on the wire.
    pub fn signing_key(&self) -> Result<SigningKey, ConfigError> {
        if self.private_key.len() != PRIVATE_KEY_LEN {
            return Err(ConfigError::Length {
                want: PRIVATE_KEY_LEN,
                found: self.private_key.len(),
            });
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&self.private_key[..32]);
        let key = SigningKey::from_bytes(&seed);
        if key.verifying_key().to_bytes()[..] != self.private_key[32..] {
            return Err(ConfigError::KeyMismatch);
        }
        Ok(key)
    }

    pub fn public_key(&self) -> Result<[u8; 32], ConfigError> {
        Ok(self.signing_key()?.verifying_key().to_bytes())
    }

    pub fn address(&self) -> Result<Address, ConfigError> {
        Ok(addr_for_key(&self.public_key()?))
    }

    /// Go's `-subnet` value: the /64 a node routes. `Subnet`'s `Display` is
    /// Go's `net.IPNet.String()` form, so printing it matches `-useconf -subnet`.
    pub fn subnet(&self) -> Result<Subnet, ConfigError> {
        Ok(subnet_for_key(&self.public_key()?))
    }

    /// `AllowedPublicKeys` is a link option, not a feature: `complete_accept`
    /// already refuses an inbound peer that is not on the list
    /// (`src/link.rs:580-585`), and only on the inbound side, which is what the
    /// Go comment promises ("This does not affect outgoing peerings").
    ///
    /// Go decodes each entry with `hex.DecodeString` and panics on failure
    /// (`main.go:222-228`); we report it. Go also accepts a wrong-length key and
    /// then never matches it, so a typo there is a silent lockout — we reject
    /// anything that is not 32 bytes.
    ///
    /// `GroupPassword` is deliberately not wired here: it filters *traffic* by
    /// group membership, not links, and nothing in the library does that yet.
    pub fn link_options(&self) -> Result<LinkOptions, ConfigError> {
        let mut allowed_keys = Vec::with_capacity(self.allowed_public_keys.len());
        for entry in &self.allowed_public_keys {
            let bytes =
                hex::decode(entry).map_err(|e| ConfigError::Hex(format!("{entry}: {e}")))?;
            if bytes.len() != 32 {
                return Err(ConfigError::Length {
                    want: 32,
                    found: bytes.len(),
                });
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(&bytes);
            allowed_keys.push(key);
        }
        Ok(LinkOptions {
            password: Vec::new(),
            priority: 0,
            pinned_key: None,
            allowed_keys,
        })
    }

    /// The config as Go's `-genconf -json` would print it.
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("a Config always serializes")
    }
}

/// Go's `ed25519.PrivateKey` is seed-then-public; dalek's is just the seed.
pub fn go_private_key_bytes(key: &SigningKey) -> Vec<u8> {
    let mut bytes = key.to_bytes().to_vec();
    bytes.extend_from_slice(&key.verifying_key().to_bytes());
    bytes
}

/// Where the config document comes from. Go's switch puts `-useconf` (stdin)
/// ahead of `-useconffile` (`main.go:105-118`), so giving both reads stdin and
/// drops the path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigSource {
    Stdin,
    File(String),
}

/// The flags that read or write a configuration, in Go's precedence order
/// (`cmd/yggdrasil/main.go:95-191`). `roots` also takes a peer URI positionally
/// for its demo probe, so a document flag is what selects config mode.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Flags {
    pub genconf: bool,
    pub useconf: bool,
    pub useconffile: Option<String>,
    pub address: bool,
    pub subnet: bool,
    pub publickey: bool,
    /// Accepted for Go compatibility: our output is always JSON, which is what
    /// `-json` asks for.
    pub json: bool,
    pub help: bool,
    /// A flag we do not define, or one missing its value. Go's `flag` package
    /// rejects both and exits 2; without this a typo like `-suseconf` would
    /// silently run the demo probe instead of reading a config.
    pub rejected: Option<String>,
    /// Arguments that are not flags — the demo probe's positional inputs. The
    /// value after `-useconffile` is not one of them.
    pub positionals: Vec<String>,
}

impl Flags {
    /// Go's `flag` package accepts `-name`, `--name`, `-name value` for string
    /// flags and `-name=value` for both kinds, so we do too.
    pub fn parse(args: &[String]) -> Flags {
        let mut out = Flags::default();
        let mut next_is_file = false;
        for arg in args {
            if next_is_file {
                out.useconffile = Some(arg.clone());
                next_is_file = false;
                continue;
            }
            let (name, inline) = match arg.strip_prefix("--").or_else(|| arg.strip_prefix('-')) {
                Some(rest) => match rest.split_once('=') {
                    Some((n, v)) => (n, Some(v.to_string())),
                    None => (rest, None),
                },
                // A positional argument: the demo probe's peer URI, not a flag.
                None => {
                    out.positionals.push(arg.clone());
                    continue;
                }
            };
            match name {
                "genconf" => out.genconf = true,
                "useconf" => out.useconf = true,
                "useconffile" => match inline {
                    Some(path) => out.useconffile = Some(path),
                    None => next_is_file = true,
                },
                "address" => out.address = true,
                "subnet" => out.subnet = true,
                "publickey" => out.publickey = true,
                "json" => out.json = true,
                "help" | "h" => out.help = true,
                _ if out.rejected.is_none() => {
                    out.rejected = Some(format!("flag provided but not defined: -{name}"));
                }
                _ => {}
            }
        }
        if next_is_file && out.rejected.is_none() {
            out.rejected = Some("flag needs an argument: -useconffile".to_string());
        }
        out
    }

    /// The document to load, if a document flag was given.
    pub fn source(&self) -> Option<ConfigSource> {
        if self.useconf {
            Some(ConfigSource::Stdin)
        } else {
            self.useconffile.clone().map(ConfigSource::File)
        }
    }
}

pub const USAGE: &str = "\
roots - a Yggdrasil node

  -genconf              print a new config to stdout
  -useconf              read a JSON config from stdin
  -useconffile <path>   read a JSON config from a file
  -json                 accepted for compatibility; config output is always JSON
  -address              with -useconf/-useconffile, print this node's IPv6 address
  -subnet               with -useconf/-useconffile, print this node's IPv6 subnet
  -publickey            with -useconf/-useconffile, print this node's public key

  <peer-uri> [hold_secs] [target-ipv6]   run the demo probe against one peer";

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// `yggdrasil -genconf -json` on 2026-09-24, verbatim, from the installed
    /// 0.5.14 binary. Its `-address` was `201:c6de:e01b:c88a:8ee1:5666:52d7:d1e7`
    /// and its `-publickey` the last half of the key below.
    const GO_GENERATED: &str = r#"{
  "PrivateKey": "cea91b87c8e41ad858f40b4a5ec0f7119b0776d82cebf4663b1cb754ec0355944e4847f90ddd5c47aa666b4a0b863af88991d0f32ea8fe4019766246ef1bb4ae",
  "Peers": [],
  "InterfacePeers": {},
  "Listen": [],
  "MulticastInterfaces": [
    {
      "Regex": ".*",
      "Beacon": true,
      "Listen": true,
      "Password": ""
    }
  ],
  "AllowedPublicKeys": [],
  "GroupPassword": "",
  "IfName": "auto",
  "IfMTU": 65535,
  "NodeInfoPrivacy": false,
  "NodeInfo": null
}"#;

    const GO_ADDRESS: &str = "201:c6de:e01b:c88a:8ee1:5666:52d7:d1e7";
    const GO_SUBNET: &str = "301:c6de:e01b:c88a::/64";

    #[test]
    fn generated_config_has_go_keys_and_defaults() {
        let ours: Value = serde_json::from_str(&Config::generate()).expect("valid JSON");
        let theirs: Value = serde_json::from_str(GO_GENERATED).expect("fixture is valid JSON");
        // Same keys, same order, same shapes — Go's field order is `encoding/json`'s
        // output order, and a config that gains or loses a key is a config Go or we
        // would refuse to interpret the same way.
        let keys = |v: &Value| -> Vec<String> {
            v.as_object()
                .expect("object")
                .keys()
                .cloned()
                .collect::<Vec<_>>()
        };
        assert_eq!(keys(&ours), keys(&theirs));
        // `AdminListen` is `omitempty` and `-genconf` blanks it, so it must be
        // absent from both — the loader puts the platform default back.
        assert!(
            ours.get("AdminListen").is_none(),
            "a generated config must not pin the admin socket"
        );
        assert_eq!(ours["IfName"], "auto");
        assert_eq!(ours["IfMTU"], 65535);
        assert_eq!(ours["GroupPassword"], "");
        assert_eq!(ours["NodeInfo"], Value::Null);
        assert_eq!(ours["Peers"], json!([]));
        assert_eq!(ours["Listen"], json!([]));
        assert_eq!(ours["InterfacePeers"], json!({}));
        assert_eq!(ours["AllowedPublicKeys"], json!([]));
        assert_eq!(ours["MulticastInterfaces"], theirs["MulticastInterfaces"]);
        assert_eq!(
            ours["PrivateKey"].as_str().unwrap().len(),
            PRIVATE_KEY_LEN * 2,
            "Go writes the 64-byte private key as 128 hex characters"
        );
    }

    #[test]
    fn go_generated_config_loads_and_yields_go_address() {
        let cfg = Config::from_json(GO_GENERATED).expect("Go's own output must parse");
        assert_eq!(cfg.address().unwrap().to_string(), GO_ADDRESS);
        assert_eq!(cfg.subnet().unwrap().to_string(), GO_SUBNET);
        assert_eq!(
            cfg.admin_listen, DEFAULT_ADMIN_LISTEN,
            "absent means default"
        );
        assert_eq!(cfg.multicast_interfaces.len(), 1);
        assert_eq!(cfg.multicast_interfaces[0].regex, ".*");
        assert!(cfg.multicast_interfaces[0].beacon && cfg.multicast_interfaces[0].listen);
        assert_eq!(
            cfg.multicast_interfaces[0].port, 0,
            "Port is omitempty in Go and must still default to 0"
        );
    }

    #[test]
    fn absent_and_null_keys_keep_defaults_and_present_ones_replace_them() {
        // Go generates, then overlays: `{}` alone is a complete config.
        let cfg = Config::from_json("{}").expect("an empty config is legal");
        assert_eq!(cfg.if_mtu, DEFAULT_IF_MTU);
        assert_eq!(cfg.if_name, DEFAULT_IF_NAME);
        assert_eq!(
            cfg.multicast_interfaces.len(),
            1,
            "an absent `MulticastInterfaces` keeps Go's default row"
        );
        assert!(
            !cfg.private_key.is_empty(),
            "no PrivateKey means a fresh random identity, as in Go"
        );
        // A `null` is not a value: Go leaves the destination untouched, so it
        // has to keep the default exactly like an absent key does.
        let cfg = Config::from_json(
            r#"{"Listen":null,"MulticastInterfaces":null,"IfName":null,"IfMTU":null,
                "LogLookups":null,"NodeInfo":null,"PrivateKeyPath":null}"#,
        )
        .expect("nulls are legal");
        assert_eq!(
            cfg.multicast_interfaces.len(),
            1,
            "a `null` must not wipe the default row"
        );
        assert_eq!(cfg.if_mtu, DEFAULT_IF_MTU);
        assert_eq!(cfg.if_name, DEFAULT_IF_NAME);
        assert!(cfg.listen.is_empty());
        // An explicit value does replace the default, including an explicit
        // empty one — Go overlays by key presence, not by emptiness.
        let cfg = Config::from_json(
            r#"{"MulticastInterfaces":[],"IfMTU":1280,"IfName":"","LogLookups":true,
                "NodeInfo":{"name":"box"},"Peers":["tcp://h:1"]}"#,
        )
        .expect("explicit values");
        assert!(
            cfg.multicast_interfaces.is_empty(),
            "an explicit `[]` means no multicast"
        );
        assert_eq!(cfg.if_mtu, 1280);
        assert!(cfg.if_name.is_empty());
        assert!(cfg.log_lookups);
        assert_eq!(cfg.node_info.as_ref().unwrap()["name"], "box");
        assert_eq!(cfg.peers, vec!["tcp://h:1".to_string()]);
        assert_eq!(cfg.admin_listen, DEFAULT_ADMIN_LISTEN);
    }

    #[test]
    fn unknown_keys_are_ignored_like_go() {
        // Go never calls `DisallowUnknownFields`, so a config full of comments-as-
        // keys and stale options still starts. Ours must too, or `-useconf` breaks
        // on the first upgrade.
        let cfg = Config::from_json(r#"{"IfName":"auto","Whatever":42,"GroupPassword":"x"}"#)
            .expect("junk keys must not fail the load");
        assert_eq!(cfg.group_password, "x");
    }

    #[test]
    fn allowed_public_keys_become_the_link_allowlist() {
        let cfg = Config::from_json(
            r#"{"AllowedPublicKeys":["0000000000000000000000000000000000000000000000000000000000000001",
               "02a1b2c3d4e5f60708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"]}"#,
        )
        .expect("a real allowlist");
        let opts = cfg.link_options().unwrap();
        assert_eq!(opts.allowed_keys.len(), 2);
        assert_eq!(
            opts.allowed_keys[1][..],
            hex::decode("02a1b2c3d4e5f60708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
                .unwrap()[..]
        );
        assert!(
            opts.password.is_empty() && opts.pinned_key.is_none(),
            "the config sets no link password; per-peer passwords live in the URI"
        );
        for bad in [
            r#"{"AllowedPublicKeys":["nothex"]}"#,
            r#"{"AllowedPublicKeys":["00"]}"#,
        ] {
            let cfg = Config::from_json(bad).expect("the document itself is fine");
            assert!(
                cfg.link_options().is_err(),
                "{bad} must not quietly become an allowlist that matches nothing"
            );
        }
    }

    #[test]
    fn a_key_that_is_not_gos_shape_is_refused() {
        // 32 bytes is a seed, not a Go private key: accepting it would let two
        // implementations disagree about who this node is.
        let cfg = Config {
            private_key: vec![7u8; 32],
            ..defaults()
        };
        assert!(matches!(
            cfg.signing_key(),
            Err(ConfigError::Length {
                want: 64,
                found: 32
            })
        ));
        // And a key whose public half was tampered with.
        let cfg = Config {
            private_key: {
                let mut v = go_private_key_bytes(&SigningKey::from_bytes(&[7u8; 32]));
                v[63] ^= 0xff;
                v
            },
            ..defaults()
        };
        assert!(matches!(cfg.signing_key(), Err(ConfigError::KeyMismatch)));
    }

    #[test]
    fn private_key_path_overrides_the_inline_key() {
        // The PEM below is `yggdrasil -useconf -exportkey` for the config above,
        // so this asserts we read what Go writes — and that the path wins.
        const GO_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
             MC4CAQAwBQYDK2VwBCIEIM6pG4fI5BrYWPQLSl7A9xGbB3bYLOv0Zjsct1TsA1WU\n\
             -----END PRIVATE KEY-----\n";
        let path = std::env::temp_dir().join(format!("roots-s6-{}", std::process::id()));
        std::fs::write(&path, GO_PEM).expect("temp PEM");
        let cfg = Config::from_json(&format!(
            r#"{{"PrivateKey":"{}","PrivateKeyPath":"{}"}}"#,
            "aa".repeat(PRIVATE_KEY_LEN),
            path.display()
        ));
        std::fs::remove_file(&path).ok();
        let cfg = cfg.expect("Go's own PEM must load");
        assert_eq!(cfg.address().unwrap().to_string(), GO_ADDRESS);
    }

    #[test]
    fn a_generated_config_roundtrips_through_our_loader() {
        let cfg = Config::from_json(&Config::generate()).expect("our own output must parse");
        let again = Config::from_json(&cfg.to_json()).expect("and again");
        assert_eq!(cfg, again, "normalising a config must not change it");
        assert_eq!(cfg.address().unwrap(), again.address().unwrap());
    }

    #[test]
    fn config_flags_parse_like_gos_flag_package() {
        let argv = |args: &[&str]| -> Vec<String> { args.iter().map(|s| s.to_string()).collect() };
        let file = Some(ConfigSource::File("/etc/yggdrasil.conf".to_string()));
        // Go's `flag` accepts `-name value`, `-name=value` and `--name=value`.
        assert_eq!(
            Flags::parse(&argv(&["-useconffile", "/etc/yggdrasil.conf"])).source(),
            file
        );
        assert_eq!(
            Flags::parse(&argv(&["-useconffile=/etc/yggdrasil.conf"])).source(),
            file
        );
        assert_eq!(
            Flags::parse(&argv(&["--useconffile=/etc/yggdrasil.conf"])).source(),
            file
        );
        // Stdin beats a path, and `-genconf` alone loads nothing (`main.go:105`).
        assert_eq!(
            Flags::parse(&argv(&["-useconf", "-useconffile", "/etc/yggdrasil.conf"])).source(),
            Some(ConfigSource::Stdin)
        );
        assert_eq!(Flags::parse(&argv(&["-genconf"])).source(), None);
        // The demo probe's positional arguments survive a flag in front of them.
        let f = Flags::parse(&argv(&["-json", "tcp://h:1", "5"]));
        assert!(
            f.json,
            "-json must be recognised, not treated as a peer URI"
        );
        assert_eq!(
            f.positionals,
            vec!["tcp://h:1".to_string(), "5".to_string()]
        );
        // An undefined flag, or one missing its value, stops the run instead of
        // silently becoming a different one.
        assert_eq!(
            Flags::parse(&argv(&["-logto", "stdout"]))
                .rejected
                .as_deref(),
            Some("flag provided but not defined: -logto")
        );
        assert_eq!(
            Flags::parse(&argv(&["-useconffile"])).rejected.as_deref(),
            Some("flag needs an argument: -useconffile")
        );
        assert!(Flags::parse(&argv(&["-genconf"])).rejected.is_none());
        assert!(
            Flags::parse(&argv(&["-h"])).help,
            "Go's flag package treats -h as -help"
        );
    }
}
