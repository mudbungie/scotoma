//! The public surface: a vault directory, and the two streams over it.

use crate::Error;
use crate::audit::{self, Audit};
use crate::store::{self, Store};
use crate::table::{Entry, Filter};
use std::fmt::Write;
use std::path::{Path, PathBuf};

const ENTROPY: &str = "/dev/urandom";

/// A vault: the secrets under one directory and the log of their use.
///
/// Opening touches nothing; the directory appears with the first secret.
/// Nothing is cached, so any number of processes may share one vault.
#[derive(Debug, Clone)]
pub struct Scotoma {
    store: Store,
    audit: Audit,
}

impl Scotoma {
    /// `actor` is who the log will say did it; it obeys the name alphabet.
    pub fn open(home: impl Into<PathBuf>, actor: &str) -> Result<Self, Error> {
        store::check(actor)?;
        let home = home.into();
        Ok(Self {
            store: Store {
                dir: home.join("secrets"),
            },
            audit: Audit {
                path: home.join("audit.tsv"),
                actor: actor.to_owned(),
            },
        })
    }

    /// Store `value` under `name`, replacing any previous value.
    pub fn set(&self, name: &str, value: &str) -> Result<(), Error> {
        self.store.put(name, value)?;
        self.audit.record("set", name, "-")
    }

    /// Delete a secret. Its handles stop substituting.
    pub fn remove(&self, name: &str) -> Result<(), Error> {
        self.store.drop(name)?;
        self.audit.record("remove", name, "-")
    }

    /// The names of the stored secrets, sorted. Names are not secret.
    pub fn names(&self) -> Result<Vec<String>, Error> {
        Ok(self
            .store
            .all()?
            .into_iter()
            .map(|(name, _)| name)
            .collect())
    }

    /// Mint a handle for a secret: a random UUID that is safe to show a
    /// model. It stands for the secret's current value for as long as the
    /// secret exists, in every process that opens this vault.
    pub fn issue(&self, name: &str) -> Result<String, Error> {
        self.mint(name, Path::new(ENTROPY))
    }

    fn mint(&self, name: &str, entropy: &Path) -> Result<String, Error> {
        if self.store.get(name)?.is_none() {
            return Err(Error::Unknown(name.to_owned()));
        }
        let handle = audit::mint(entropy)?;
        self.audit.record(audit::ISSUE, name, &handle)?;
        Ok(handle)
    }

    /// A stream that replaces every issued handle with its secret's value.
    /// **Its output carries secrets**: send it to the thing that executes,
    /// never to a model, a log or a transcript.
    pub fn substituter(&self) -> Result<Stream, Error> {
        let secrets = self.store.all()?;
        let value = |name: &str| secrets.iter().find(|(known, _)| known == name);
        let entries = self
            .audit
            .issued()?
            .into_iter()
            .filter_map(|(handle, name)| {
                value(&name).map(|(_, value)| Entry {
                    find: handle.clone().into_bytes(),
                    put: value.clone().into_bytes(),
                    secret: name,
                    handle,
                })
            });
        Ok(self.stream(entries.collect(), "use"))
    }

    /// A stream that replaces every stored secret value with
    /// `[scotoma:NAME]`. The value is matched as stored and as it appears
    /// inside a JSON string.
    pub fn redactor(&self) -> Result<Stream, Error> {
        let mut entries = Vec::new();
        for (name, value) in self.store.all()? {
            for find in [json(&value), value] {
                entries.push(Entry {
                    find: find.into_bytes(),
                    put: format!("[scotoma:{name}]").into_bytes(),
                    secret: name.clone(),
                    handle: "-".to_owned(),
                });
            }
        }
        Ok(self.stream(entries, "redact"))
    }

    fn stream(&self, entries: Vec<Entry>, event: &'static str) -> Stream {
        Stream {
            filter: Filter::new(entries),
            audit: self.audit.clone(),
            event,
        }
    }

    /// [`Self::substituter`] over one whole string.
    pub fn substitute(&self, text: &str) -> Result<String, Error> {
        self.substituter()?.whole(text)
    }

    /// [`Self::redactor`] over one whole string.
    pub fn redact(&self, text: &str) -> Result<String, Error> {
        self.redactor()?.whole(text)
    }
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

/// A streaming replacement over bytes, from [`Scotoma::substituter`] or
/// [`Scotoma::redactor`]. A match may straddle chunks: bytes that could still
/// begin one are held back until [`Stream::finish`].
#[derive(Debug, Clone)]
pub struct Stream {
    filter: Filter,
    audit: Audit,
    event: &'static str,
}

impl Stream {
    /// Feed a chunk; get back the bytes that are now decided.
    pub fn push(&mut self, chunk: &[u8]) -> Result<Vec<u8>, Error> {
        self.feed(chunk, false)
    }

    /// The input has ended: get back whatever was held.
    pub fn finish(&mut self) -> Result<Vec<u8>, Error> {
        self.feed(&[], true)
    }

    /// Every replacement is logged BEFORE its bytes are released: if the log
    /// cannot be written, nothing comes out.
    fn feed(&mut self, chunk: &[u8], last: bool) -> Result<Vec<u8>, Error> {
        let (bytes, fired) = self.filter.feed(chunk, last);
        for entry in fired {
            self.audit
                .record(self.event, &entry.secret, &entry.handle)?;
        }
        Ok(bytes)
    }

    fn whole(mut self, text: &str) -> Result<String, Error> {
        let bytes = self.feed(text.as_bytes(), true)?;
        // Whole UTF-8 strings replaced inside a UTF-8 string: still UTF-8.
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }
}

#[cfg(test)]
#[path = "vault_tests.rs"]
mod tests;
