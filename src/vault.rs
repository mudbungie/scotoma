//! The unlocked vault: the keyed core that only the resident process holds.
//!
//! Everything that touches a secret value is here. Nothing in this file is
//! public; other processes reach it through the socket (`resident.rs`).

use crate::Error;
use crate::audit::{self, Act, Audit};
use crate::crypt::{self, Secret};
use crate::grant::Grant;
use crate::store::{self, Store};
use crate::table::{Entry, Filter};
use std::fmt::Write;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub(crate) struct Vault {
    pub store: Store,
    pub audit: Audit,
    pub entropy: PathBuf,
}

impl Vault {
    pub fn new(home: &Path, key: Secret, entropy: &Path) -> Self {
        Self {
            store: Store {
                dir: home.join("secrets"),
                key,
            },
            audit: Audit {
                path: home.join("audit.tsv"),
                actor: "resident".to_owned(),
            },
            entropy: entropy.to_owned(),
        }
    }

    /// The same vault, logging as `actor`.
    pub fn acting(&self, actor: &str) -> Result<Self, Error> {
        store::check(actor)?;
        let audit = Audit {
            actor: actor.to_owned(),
            ..self.audit.clone()
        };
        Ok(Self {
            audit,
            ..self.clone()
        })
    }

    fn log(&self, event: &str, secret: &str) -> Result<(), Error> {
        self.audit.record(Act {
            event,
            secret,
            handle: "-",
            grant: "-",
        })
    }

    pub fn set(&self, name: &str, value: &str) -> Result<(), Error> {
        let nonce = crypt::random(&self.entropy)?;
        self.store.put(name, value, nonce)?;
        self.log("set", name)
    }

    pub fn remove(&self, name: &str) -> Result<(), Error> {
        self.store.drop(name)?;
        self.log("remove", name)
    }

    /// Mint a handle for a secret the grant covers.
    pub fn issue(&self, name: &str, grant: &Grant) -> Result<String, Error> {
        if self.store.get(name)?.is_none() {
            return Err(Error::Unknown(name.to_owned()));
        }
        allow(grant, name)?;
        let handle = audit::uuid(crypt::random(&self.entropy)?);
        let act = Act {
            event: audit::ISSUE,
            secret: name,
            handle: &handle,
            grant: &grant.id,
        };
        self.audit.record(act)?;
        Ok(handle)
    }

    /// A flow that replaces every issued handle with its secret's value, for
    /// the secrets `grant` covers.
    pub fn substituter(&self, grant: Grant) -> Result<Flow, Error> {
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
        Ok(self.flow(entries.collect(), "use", grant, false))
    }

    /// A flow that replaces every stored value with `[scotoma:NAME]`.
    pub fn redactor(&self) -> Result<Flow, Error> {
        Ok(self.flow(self.values()?, "redact", Grant::none(), false))
    }

    /// A flow that fails with [`Error::Leak`] at the first stored value.
    pub fn guard(&self) -> Result<Flow, Error> {
        Ok(self.flow(self.values()?, "leak", Grant::none(), true))
    }

    /// Ready a command: its words with handles substituted, and the flow that
    /// redacts its output. A value that went in through a handle comes back
    /// out as that same handle; any other secret as `[scotoma:NAME]`.
    pub fn arm(&self, command: &[String], grant: Grant) -> Result<(Vec<String>, Flow), Error> {
        let mut entries = self.values()?;
        let mut substituter = self.substituter(grant)?;
        let (mut words, mut used) = (Vec::new(), Vec::new());
        for word in command {
            let (bytes, fired) = substituter.feed(word.as_bytes(), true)?;
            words.push(String::from_utf8_lossy(&bytes).into_owned());
            used.extend(fired);
        }
        for entry in &mut entries {
            let handle = used.iter().find(|used| used.secret == entry.secret);
            entry.put = handle.map_or(entry.put.clone(), |used| used.handle.clone().into_bytes());
        }
        Ok((words, self.flow(entries, "redact", Grant::none(), false)))
    }

    /// What to look for on the way out: every stored value, as stored and as
    /// it reads inside a JSON string. This is the detector; a looser one
    /// (partial or transformed values) replaces this table and nothing else.
    fn values(&self) -> Result<Vec<Entry>, Error> {
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
        Ok(entries)
    }

    fn flow(&self, entries: Vec<Entry>, event: &'static str, grant: Grant, refuse: bool) -> Flow {
        Flow {
            filter: Filter::new(entries),
            audit: self.audit.clone(),
            event,
            grant,
            refuse,
        }
    }
}

fn allow(grant: &Grant, name: &str) -> Result<(), Error> {
    if grant.covers(name) {
        Ok(())
    } else {
        Err(Error::Denied(format!("the grant does not cover {name:?}")))
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

/// One streaming pass over bytes: substitution, redaction or the guard. A
/// match may straddle chunks; bytes that could still begin one are held.
#[derive(Debug, Clone)]
pub(crate) struct Flow {
    filter: Filter,
    audit: Audit,
    event: &'static str,
    grant: Grant,
    /// A guard: a match is an error, not a replacement.
    refuse: bool,
}

impl Flow {
    /// Feed a chunk (`last` ends the input); get back the bytes now decided
    /// and the entries that fired. Every match is authorized and logged
    /// BEFORE its bytes are released: if either fails, nothing comes out.
    pub fn feed(&mut self, chunk: &[u8], last: bool) -> Result<(Vec<u8>, Vec<Entry>), Error> {
        let (bytes, fired) = self.filter.feed(chunk, last);
        for entry in &fired {
            allow(&self.grant, &entry.secret)?;
            let (event, grant) = (self.event, self.grant.id.as_str());
            self.audit.record(Act {
                event,
                secret: &entry.secret,
                handle: &entry.handle,
                grant,
            })?;
        }
        match fired.first() {
            Some(entry) if self.refuse => Err(Error::Leak(entry.secret.clone())),
            _ => Ok((bytes, fired)),
        }
    }
}

#[cfg(test)]
#[path = "vault_tests.rs"]
mod tests;
