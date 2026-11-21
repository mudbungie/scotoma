//! The usage log.
//!
//! One append-only file of tab-separated lines:
//!
//! ```text
//! <unix seconds> \t <actor> \t <event> \t <secret or *> \t <grant id or -> \t <note or ->
//! ```
//!
//! No field holds a tab or a newline, so a line parses by splitting on tabs.
//! It holds names and identifiers, never a value, and is not encrypted.

use crate::Error;
use crate::grant;
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub(crate) struct Audit {
    pub path: PathBuf,
    pub actor: String,
}

/// One line's last four fields.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Act<'a> {
    pub event: &'a str,
    pub secret: &'a str,
    pub grant: &'a str,
    pub note: &'a str,
}

impl Audit {
    pub fn record(&self, act: Act) -> Result<(), Error> {
        let Act {
            event,
            secret,
            grant,
            note,
        } = act;
        let (at, actor) = (grant::now(), &self.actor);
        let line = format!("{at}\t{actor}\t{event}\t{secret}\t{grant}\t{note}\n");
        let mut file = OpenOptions::new();
        file.append(true).create(true).mode(0o600);
        file.open(&self.path)
            .and_then(|mut file| file.write_all(line.as_bytes()))
            .map_err(Error::io(&self.path))
    }
}

/// Sixteen random bytes as a random (version 4) UUID.
pub(crate) fn uuid(bytes: [u8; 16]) -> String {
    let random = u128::from_be_bytes(bytes);
    let uuid = random & !(0xf << 76) | (0x4 << 76);
    let uuid = uuid & !(0x3 << 62) | (0x2 << 62);
    format!(
        "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
        uuid >> 96,
        (uuid >> 80) & 0xffff,
        (uuid >> 64) & 0xffff,
        (uuid >> 48) & 0xffff,
        uuid & 0xffff_ffff_ffff
    )
}

#[cfg(test)]
#[path = "audit_tests.rs"]
mod tests;
