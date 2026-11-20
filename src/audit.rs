//! The usage log, and the only record of which handles exist.
//!
//! One append-only file of tab-separated lines:
//!
//! ```text
//! <unix seconds> \t <actor> \t <event> \t <secret or *> \t <handle or -> \t <grant id or ->
//! ```
//!
//! Every field is drawn from the name alphabet, so a line needs no escaping
//! and parses without heuristics. It holds names and identifiers, never a
//! value, and is not encrypted. Handles are not stored anywhere else: a
//! handle is valid because its `issue` line is in this file.

use crate::Error;
use crate::grant;
use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

pub(crate) const ISSUE: &str = "issue";

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
    pub handle: &'a str,
    pub grant: &'a str,
}

impl Audit {
    pub fn record(&self, act: Act) -> Result<(), Error> {
        let Act {
            event,
            secret,
            handle,
            grant,
        } = act;
        let (at, actor) = (grant::now(), &self.actor);
        let line = format!("{at}\t{actor}\t{event}\t{secret}\t{handle}\t{grant}\n");
        let mut file = OpenOptions::new();
        file.append(true).create(true).mode(0o600);
        file.open(&self.path)
            .and_then(|mut file| file.write_all(line.as_bytes()))
            .map_err(Error::io(&self.path))
    }

    /// Every `(handle, secret name)` ever issued, oldest first.
    pub fn issued(&self) -> Result<Vec<(String, String)>, Error> {
        let log = match fs::read_to_string(&self.path) {
            Ok(log) => log,
            Err(error) if error.kind() == ErrorKind::NotFound => String::new(),
            Err(error) => return Err(Error::io(&self.path)(error)),
        };
        let mut issued = Vec::new();
        for line in log.lines() {
            let fields: Vec<&str> = line.split('\t').collect();
            if let [_, _, ISSUE, secret, handle, _] = fields.as_slice() {
                issued.push(((*handle).to_owned(), (*secret).to_owned()));
            }
        }
        Ok(issued)
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
