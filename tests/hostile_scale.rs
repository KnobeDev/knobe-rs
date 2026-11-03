//! Resource bounds on hostile input: verification must stay linear in the
//! number of keys (a duplicate-key check by linear scan made a 3 MB file take
//! tens of seconds), and deep nesting must fail cleanly.

use std::time::{Duration, Instant};

use knobe::verify::State;

fn b64(bytes: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::new();
    for c in bytes.chunks(3) {
        let n = u32::from(c[0]) << 16 | u32::from(*c.get(1).unwrap_or(&0)) << 8 | u32::from(*c.get(2).unwrap_or(&0));
        for i in 0..4 {
            s.push(if i <= c.len() { char::from(A[(n >> (18 - 6 * i) & 63) as usize]) } else { '=' });
        }
    }
    s
}

fn file_with_payload(payload: &str) -> Vec<u8> {
    format!("---\ntitle: T\n---\n\n-----BEGIN KNOBE B64-----\n{}\n-----END KNOBE B64-----\n", b64(payload.as_bytes()))
        .into_bytes()
}

#[test]
fn many_keys_verify_in_linear_time() {
    let keys: Vec<String> = (0..200_000).map(|i| format!("\"k{i}\":\"v\"")).collect();
    let file = file_with_payload(&format!("{{{}}}", keys.join(",")));
    let start = Instant::now();
    let r = knobe::verify_bytes(&file);
    let took = start.elapsed();
    assert_eq!(r.state, State::Failed); // no payload_hash, but fully evaluated
    // Quadratic scanning took minutes at this size; linear takes well under a second.
    assert!(took < Duration::from_secs(10), "200k-key payload took {took:?}");
}

#[test]
fn many_nfc_variant_keys_are_detected_without_blowup() {
    let mut keys: Vec<String> = (0..100_000).map(|i| format!("\"k{i}\":\"v\"")).collect();
    keys.push("\"caf\u{e9}\":\"1\"".into());
    keys.push("\"cafe\u{301}\":\"2\"".into());
    let start = Instant::now();
    let r = knobe::verify_bytes(&file_with_payload(&format!("{{{}}}", keys.join(","))));
    assert_eq!(r.state, State::Unreadable);
    assert!(r.reason.unwrap().contains("collide under NFC"));
    assert!(start.elapsed() < Duration::from_secs(10));
}

#[test]
fn deep_nesting_is_unreadable_not_a_stack_overflow() {
    let deep = format!("{{\"a\":{}{}}}", "[".repeat(100_000), "]".repeat(100_000));
    let r = knobe::verify_bytes(&file_with_payload(&deep));
    assert_eq!(r.state, State::Unreadable);
}
