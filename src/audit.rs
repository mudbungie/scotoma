//! The usage log, and the only other state there is.
//!
//! One append-only file of tab-separated lines:
//!
//! ```text
//! <unix seconds> \t <actor> \t <event> \t <secret name> \t <handle or ->
//! ```
//!
//! Every field is drawn from the name alphabet, so a line needs no escaping
//! and parses without heuristics. Handles are not stored anywhere else: a
//! handle is valid because its `issue` line is in this file.

use crate::Error;
use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) const ISSUE: &str = "issue";

#[derive(Debug, Clone)]
pub(crate) struct Audit {
    pub path: PathBuf,
    pub actor: String,
}

impl Audit {
    pub fn record(&self, event: &str, secret: &str, handle: &str) -> Result<(), Error> {
        let at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |since| since.as_secs());
        let line = format!("{at}\t{}\t{event}\t{secret}\t{handle}\n", self.actor);
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
            if let [_, _, ISSUE, secret, handle] = fields.as_slice() {
                issued.push(((*handle).to_owned(), (*secret).to_owned()));
            }
        }
        Ok(issued)
    }
}

/// A fresh handle: a random (version 4) UUID drawn from `entropy`.
pub(crate) fn mint(entropy: &Path) -> Result<String, Error> {
    let mut bytes = [0; 16];
    File::open(entropy)
        .and_then(|mut file| file.read_exact(&mut bytes))
        .map_err(Error::io(entropy))?;
    let random = u128::from_be_bytes(bytes);
    let uuid = random & !(0xf << 76) | (0x4 << 76);
    let uuid = uuid & !(0x3 << 62) | (0x2 << 62);
    Ok(format!(
        "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
        uuid >> 96,
        (uuid >> 80) & 0xffff,
        (uuid >> 64) & 0xffff,
        (uuid >> 48) & 0xffff,
        uuid & 0xffff_ffff_ffff
    ))
}

#[cfg(test)]
#[path = "audit_tests.rs"]
mod tests;
