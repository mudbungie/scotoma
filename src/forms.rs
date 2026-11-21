//! The detector: the forms in which a secret value is looked for on its way
//! out. Each is an exact byte string, so matching stays one linear pass.
//!
//! - as stored;
//! - as it reads inside a JSON string;
//! - percent-encoded, as in a URL or a form body;
//! - base64, wherever it falls inside a longer encoded run (a Basic-auth
//!   header encodes `user:password` as one).

use std::fmt::Write;

/// The shortest base64 fragment worth looking for: shorter ones match text
/// that has nothing to do with the secret.
const FRAGMENT: usize = 8;
const STANDARD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const URL_SAFE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Every form of `value` to look for.
pub(crate) fn of(value: &str) -> Vec<Vec<u8>> {
    let mut forms = vec![value.as_bytes().to_vec(), json(value).into_bytes()];
    for (upper, plus) in [(true, false), (false, false), (true, true), (false, true)] {
        forms.push(percent(value, upper, plus).into_bytes());
    }
    for alphabet in [STANDARD, URL_SAFE] {
        for lead in 0..3 {
            forms.push(fragment(value.as_bytes(), lead, alphabet));
        }
    }
    forms.retain(|form| !form.is_empty());
    forms
}

/// How a value reads inside a JSON string, as the common serializers write it.
fn json(value: &str) -> String {
    let mut out = String::new();
    for character in value.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            control if control < ' ' => {
                let _ = write!(out, "\\u{:04x}", u32::from(control));
            }
            other => out.push(other),
        }
    }
    out
}

/// Percent-encoding: everything but letters, digits and `-._~` becomes `%XX`,
/// in upper or lower hex; with `plus`, a space becomes `+` as in a form body.
fn percent(value: &str, upper: bool, plus: bool) -> String {
    let mut out = String::new();
    for &byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(char::from(byte));
            }
            b' ' if plus => out.push('+'),
            _ if upper => {
                let _ = write!(out, "%{byte:02X}");
            }
            _ => {
                let _ = write!(out, "%{byte:02x}");
            }
        }
    }
    out
}

/// The base64 characters that `value` alone decides when `lead` unknown
/// bytes come before it in the encoded run (0, 1 or 2: the three ways a
/// value can sit against base64's three-byte groups). The characters it
/// shares with its neighbours are left out, so what remains appears in the
/// encoding of any text that holds the value at that alignment. Empty when
/// too short to mean anything.
fn fragment(value: &[u8], lead: usize, alphabet: &[u8; 64]) -> Vec<u8> {
    let (mut sextets, mut pending, mut bits) = (Vec::new(), 0, 0);
    for &byte in std::iter::repeat_n(&0, lead).chain(value) {
        pending = (pending << 8 | usize::from(byte)) & 0xffff;
        bits += 8;
        while bits >= 6 {
            bits -= 6;
            sextets.push(alphabet.get(pending >> bits & 63).copied().unwrap_or(b'='));
        }
    }
    // One leading byte spoils two characters, two spoil three.
    let own = sextets.get((lead * 4).div_ceil(3)..).unwrap_or_default();
    if own.len() < FRAGMENT {
        return Vec::new();
    }
    own.to_vec()
}

#[cfg(test)]
#[path = "forms_tests.rs"]
mod tests;
