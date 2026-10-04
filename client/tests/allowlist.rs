//! `AllowedPublicKeys` end to end: a config key, a `LinkOptions`, and a real
//! loopback listener that refuses an unlisted inbound peer and admits a listed
//! one.
//!
//! The library has gated inbound links on `allowed_keys` since before the parity
//! plan (`src/link.rs:580-585`, Go's `link.go:308-319`); nothing had ever
//! exercised it. This drives it through the config face, so the wiring Slice 6
//! adds — JSON key → `Config::link_options()` → `complete_accept` — is what the
//! test covers, not a hand-built `LinkOptions`.

use ed25519_dalek::SigningKey;
use roots::link::{accept, listen};
use roots::{Client, CoreError, Error};
use roots_client::config::Config;

fn public_hex(key: &SigningKey) -> String {
    hex::encode(key.verifying_key().to_bytes())
}

fn allowlist_of(keys: &[&SigningKey]) -> Config {
    let entries: Vec<String> = keys
        .iter()
        .map(|k| format!(r#""{}""#, public_hex(k)))
        .collect();
    let text = format!(r#"{{"AllowedPublicKeys":[{}]}}"#, entries.join(","));
    Config::from_json(&text).expect("an allowlist config must parse")
}

#[tokio::test]
async fn allowed_public_keys_gate_inbound_links_only() {
    let host_key = SigningKey::from_bytes(&[0x11; 32]);
    let listed = SigningKey::from_bytes(&[0x22; 32]);
    let unlisted = SigningKey::from_bytes(&[0x33; 32]);
    let opts = allowlist_of(&[&listed]).link_options().expect("valid keys");
    assert_eq!(opts.allowed_keys.len(), 1);

    let listener = listen("tcp://127.0.0.1:0")
        .await
        .expect("loopback listener");
    let uri = format!("tcp://127.0.0.1:{}", listener.local_addr().unwrap().port());

    // An unlisted dialer gets a refusal. Go's check runs *after* the listener
    // has written its own `meta`, so the dialer's handshake completes and the
    // link only dies on the next read — the asymmetry is the wire behaviour,
    // and the `is_ok()` below is what pins it.
    let (inbound, outbound) = {
        let dialer = Client::new(unlisted);
        tokio::join!(
            accept(&listener, &host_key, &opts),
            dialer.connect_any(&uri)
        )
    };
    assert!(
        matches!(inbound, Err(Error::Core(CoreError::KeyNotAllowed))),
        "an unlisted peer must be refused with KeyNotAllowed"
    );
    assert!(
        outbound.is_ok(),
        "a refusal is indistinguishable from a live link to the peer that made it"
    );

    // A listed dialer is admitted, and both ends name the right peer. Its own
    // config allows somebody else entirely: `AllowedPublicKeys` must not touch
    // outgoing peerings, which is what Go's comment promises and what the
    // `is_inbound` guard in `run_handshake` enforces.
    let stranger = SigningKey::from_bytes(&[0x66; 32]);
    let dialer_opts = allowlist_of(&[&stranger])
        .link_options()
        .expect("valid keys");
    let listed_pub = listed.verifying_key().to_bytes();
    let (inbound, outbound) = {
        let dialer = Client::with_options(listed, dialer_opts);
        tokio::join!(
            accept(&listener, &host_key, &opts),
            dialer.connect_any(&uri)
        )
    };
    let inbound = inbound.expect("the listed key is allowed in");
    assert_eq!(inbound.remote_key, listed_pub);
    assert!(inbound.inbound, "the accepted side is an inbound link");
    let outbound = outbound.expect("an allowlist of my own must not block my dial");
    assert_eq!(outbound.remote_key, host_key.verifying_key().to_bytes());
}

#[tokio::test]
async fn an_empty_allowlist_admits_everyone() {
    // The default is an empty list, which Go reads as "no restriction" — not
    // "nobody". A config that turned the default into a lockout would take down
    // every node that upgrades into it.
    let host_key = SigningKey::from_bytes(&[0x44; 32]);
    let peer = SigningKey::from_bytes(&[0x55; 32]);
    let opts = allowlist_of(&[])
        .link_options()
        .expect("an empty list is valid");
    assert!(opts.allowed_keys.is_empty());

    let listener = listen("tcp://127.0.0.1:0")
        .await
        .expect("loopback listener");
    let uri = format!("tcp://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let (inbound, outbound) = {
        let dialer = Client::new(peer);
        tokio::join!(
            accept(&listener, &host_key, &opts),
            dialer.connect_any(&uri)
        )
    };
    assert!(inbound.is_ok(), "an empty allowlist must gate nobody");
    assert!(outbound.is_ok());
}
