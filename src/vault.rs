//! The unlocked vault: the keyed core that only the resident process holds.
//!
//! Everything that touches a secret value is here. Nothing in this file is
//! public; other processes reach it through the socket (`resident.rs`).

use crate::Error;
use crate::audit::{Act, Audit};
use crate::crypt::{self, Secret};
use crate::forms;
use crate::grant::Grant;
use crate::store::{self, Store};
use crate::table::{Entry, Filter};
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
    pub fn acting(&self, actor: &str) -> Self {
        Self {
            audit: self.audit.by(actor),
            ..self.clone()
        }
    }

    fn log(&self, event: &str, secret: &str, grant: &Grant) -> Result<(), Error> {
        self.audit.record(Act {
            event,
            secret,
            grant: &grant.id,
            note: "-",
        })
    }

    /// Store a value. Changing what a name stands for needs a grant over it.
    pub fn set(&self, name: &str, value: &str, grant: &Grant) -> Result<(), Error> {
        store::check(name)?;
        allow(grant, name)?;
        let nonce = crypt::random(&self.entropy)?;
        self.store.put(name, value, nonce)?;
        self.log("set", name, grant)
    }

    pub fn remove(&self, name: &str, grant: &Grant) -> Result<(), Error> {
        store::check(name)?;
        allow(grant, name)?;
        self.store.drop(name)?;
        self.log("remove", name, grant)
    }

    /// A flow that replaces each secret's placeholder, `[scotoma:NAME]`, with
    /// its value. A placeholder for a secret the grant does not cover is an
    /// error; one for a secret that does not exist is left as it is.
    pub fn substituter(&self, grant: Grant) -> Result<Flow, Error> {
        let entries = self.store.all()?.into_iter().map(|(name, value)| Entry {
            find: marker(&name),
            put: value.into_bytes(),
            secret: name,
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

    /// Ready a command: its words with placeholders substituted, and the
    /// flow that redacts its output, which turns each value back into the
    /// placeholder it came from.
    pub fn arm(&self, command: &[String], grant: Grant) -> Result<(Vec<String>, Flow), Error> {
        let mut substituter = self.substituter(grant)?;
        let mut words = Vec::new();
        for word in command {
            let (bytes, _) = substituter.feed(word.as_bytes(), true)?;
            words.push(String::from_utf8_lossy(&bytes).into_owned());
        }
        self.redactor().map(|output| (words, output))
    }

    /// What to look for on the way out: every stored value in every form
    /// `forms::of` knows. That function is the detector; a looser one
    /// changes it and nothing else.
    fn values(&self) -> Result<Vec<Entry>, Error> {
        let mut entries = Vec::new();
        for (name, value) in self.store.all()? {
            for find in forms::of(&value) {
                entries.push(Entry {
                    find,
                    put: marker(&name),
                    secret: name.clone(),
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
            paid: false,
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

/// A secret's placeholder: what a model writes to use it, and what it reads
/// where the value was.
fn marker(name: &str) -> Vec<u8> {
    format!("[scotoma:{name}]").into_bytes()
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
    /// The grant has been charged its one use for this flow.
    paid: bool,
}

impl Flow {
    /// Feed a chunk (`last` ends the input); get back the bytes now decided
    /// and the entries that fired. Every match is authorized and logged
    /// BEFORE its bytes are released: if either fails, nothing comes out.
    pub fn feed(&mut self, chunk: &[u8], last: bool) -> Result<(Vec<u8>, Vec<Entry>), Error> {
        let (bytes, fired) = self.filter.feed(chunk, last);
        fired
            .iter()
            .try_for_each(|entry| allow(&self.grant, &entry.secret))?;
        // One flow (one command, one stream) is one use, however many
        // placeholders it holds; a flow that matches nothing costs nothing,
        // and neither does one that is refused.
        if !(self.paid || fired.is_empty()) {
            self.paid = self.grant.charge();
            if !self.paid {
                return Err(Error::Denied("the grant is used up".to_owned()));
            }
        }
        for entry in &fired {
            let (event, grant) = (self.event, self.grant.id.as_str());
            self.audit.record(Act {
                event,
                secret: &entry.secret,
                grant,
                note: "-",
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
