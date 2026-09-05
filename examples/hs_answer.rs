//! Cross-implementation handshake check: decrypt a Go-built session init,
//! answer as responder, print our ack hex for Go-side verification.
//! Usage: cargo run -q --example hs_answer -- <GO_INIT hex file>

use roots::session::{SESSION_TYPE_ACK, Session, SessionInit};

fn main() {
    let path = std::env::args().nth(1).expect("go init hex file");
    let hexs = std::fs::read_to_string(path).expect("read");
    let raw = hex::decode(hexs.trim()).expect("hex");
    let seed_a: [u8; 32] = core::array::from_fn(|i| 0xA0 + i as u8);
    let seed_b: [u8; 32] = core::array::from_fn(|i| 0xB0 + i as u8);
    let a_sk = ed25519_dalek::SigningKey::from_bytes(&seed_a);
    let pa = a_sk.verifying_key().to_bytes();
    let b_box = roots::session::ed_to_curve_priv(&seed_b);
    let init = SessionInit::decrypt_msg(&b_box, &pa, &raw).expect("go init decrypts");
    eprintln!("init key_seq={} seq={}", init.key_seq, init.seq);
    let mut sess = Session::for_init(pa, &init);
    let ack = sess.handle_init(&init).expect("accept");
    let b_sk = ed25519_dalek::SigningKey::from_bytes(&seed_b);
    let enc = ack.encrypt_msg(SESSION_TYPE_ACK, &b_sk, &pa);
    println!("{}", hex::encode(enc));
}
