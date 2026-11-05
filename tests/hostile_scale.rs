//! Resource bounds on hostile input: verification must stay linear in the
//! number of keys (a duplicate-key check by linear scan made a 3 MB file take
//! tens of seconds), and deep nesting must fail cleanly. The parser keeps its
//! own stack; only payloads lens.py can walk (498 levels) reach the
//! recursive steps (hashing, NFC checks, output, drop).

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
    assert_eq!(r.reason.as_deref(), Some("payload could not be decoded or parsed"));
}

/// On a thread with Rust's default stack (2 MB). Measured need: about 700 KB
/// in a debug build, 250 KB in release.
fn on_default_thread(file: Vec<u8>) -> knobe::Report {
    std::thread::Builder::new().stack_size(2 << 20).spawn(move || knobe::verify_bytes(&file)).unwrap().join().unwrap()
}

#[test]
fn the_deepest_payload_lens_py_accepts_verifies_on_a_default_thread() {
    // Arrays, objects and payload_hash (which is printed whole) at 498 levels.
    let arrays = format!("{}{}", "[".repeat(498), "]".repeat(498));
    let objects = format!("{}\"v\"{}", "{\"k\":".repeat(497), "}".repeat(497));
    let payload = format!(r#"{{"spec_version":"1.0","x":{arrays},"y":{objects},"payload_hash":{arrays}}}"#);
    let r = on_default_thread(file_with_payload(&payload));
    assert_eq!(r.state, State::Failed); // fully evaluated: hashed, checked, compared
    assert!(r.to_json().len() > 400_000);
}

#[test]
fn nesting_lens_py_cannot_walk_is_a_verifier_error_with_no_blocks() {
    for (levels, blocks) in [(499, 0), (9997, 0)] {
        let deep = format!("{{\"a\":{}{}}}", "[".repeat(levels), "]".repeat(levels));
        let r = on_default_thread(file_with_payload(&deep));
        assert_eq!(r.reason.as_deref(), Some("verifier error (RecursionError); rejected"), "{levels}");
        assert_eq!((r.state, r.block_count), (State::Unreadable, blocks), "{levels}");
    }
}
