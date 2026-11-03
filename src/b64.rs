//! Standard Base64 (RFC 4648 §4) with lens.py's decoding rules:
//! `"".join(block.split())` then `b64decode(validate=True)`. Padding is
//! required (ERRATA E7); non-zero unused trailing bits are accepted, as
//! CPython does.

use crate::pyfmt::is_py_space;

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn sextet(c: u8) -> Option<u32> {
    ALPHABET.iter().position(|&a| a == c).map(|p| p as u32)
}

/// Decode a payload block. None if it is not strict, padded standard Base64.
pub fn decode_block(block: &str) -> Option<Vec<u8>> {
    let mut clean = Vec::with_capacity(block.len());
    for c in block.chars().filter(|c| !is_py_space(*c)) {
        clean.push(u8::try_from(c).ok().filter(u8::is_ascii)?);
    }
    if clean.len() % 4 != 0 {
        return None;
    }
    let pad = clean.iter().rev().take_while(|&&c| c == b'=').count();
    if pad > 2 {
        return None;
    }
    let mut out = Vec::with_capacity(clean.len() / 4 * 3);
    let (mut acc, mut bits) = (0u32, 0u32);
    for &c in &clean[..clean.len() - pad] {
        acc = (acc << 6) | sextet(c)?;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

pub fn encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n =
            (chunk[0] as u32) << 16 | (*chunk.get(1).unwrap_or(&0) as u32) << 8 | *chunk.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            s.push(if i <= chunk.len() { ALPHABET[(n >> (18 - 6 * i) & 63) as usize] as char } else { '=' });
        }
    }
    s
}

/// Base64 broken into lines of `width` characters, joined by "\n".
pub fn encode_wrapped(bytes: &[u8], width: usize) -> String {
    let b = encode(bytes);
    b.as_bytes().chunks(width).map(|c| std::str::from_utf8(c).expect("ascii")).collect::<Vec<_>>().join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_follows_cpython_validate_true() {
        assert_eq!(decode_block("QQ=="), Some(b"A".to_vec()));
        assert_eq!(decode_block("QR=="), Some(b"A".to_vec())); // trailing bits accepted
        assert_eq!(decode_block(""), Some(vec![]));
        assert_eq!(decode_block(" Q\tQ\u{a0}=\u{1c}=\n"), Some(b"A".to_vec()));
        for bad in ["QQ=", "QQ", "QQ==QQ==", "=QQ=", "Q===", "QQ-_", "QQ\u{200b}=="] {
            assert_eq!(decode_block(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn encode_round_trips_and_wraps() {
        for n in 0..10 {
            let data: Vec<u8> = (0..n).map(|i| (i * 37) as u8).collect();
            assert_eq!(decode_block(&encode(&data)), Some(data));
        }
        assert_eq!(encode_wrapped(&[0u8; 60], 76).split('\n').map(str::len).collect::<Vec<_>>(), vec![76, 4]);
    }
}
