//! The one error type. No variant ever carries a secret value.

use std::fmt;
use std::io;

/// Why an operation was refused or failed.
#[derive(Debug)]
pub enum Error {
    /// A secret or actor name is not 1-128 of `A-Z a-z 0-9 . _ -`, or starts
    /// with a dot. A name is a file name; nothing else is accepted.
    Name(String),
    /// No secret is stored under this name.
    Unknown(String),
    /// A secret value may not be empty.
    Empty,
    /// The named secret's value was found in content passed to a guard.
    Leak(String),
    /// Authorization was missing, expired, too narrow, or refused; the text
    /// says which.
    Denied(String),
    /// Stored ciphertext did not authenticate: it was altered, or belongs to
    /// another vault.
    Sealed,
    /// No resident process is serving this vault: it has not been unlocked.
    Locked,
    /// The password was wrong, empty, or mistyped when choosing it.
    Password,
    /// The filesystem (or a stream) said no; `context` names what was touched.
    Io { context: String, source: io::Error },
}

impl Error {
    /// The adapter for `map_err`: `fallible.map_err(Error::io(&path))`.
    pub fn io(context: impl fmt::Debug) -> impl FnOnce(io::Error) -> Self {
        let context = format!("{context:?}");
        move |source| Self::Io { context, source }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Name(name) => write!(f, "invalid name {name:?}: use 1-128 of A-Z a-z 0-9 . _ -"),
            Self::Unknown(name) => write!(f, "no secret named {name:?}"),
            Self::Empty => write!(f, "a secret value may not be empty"),
            Self::Leak(name) => write!(f, "secret {name:?} found in outgoing content"),
            Self::Denied(why) => write!(f, "denied: {why}"),
            Self::Sealed => write!(
                f,
                "stored data failed to decrypt: altered, or not this vault's"
            ),
            Self::Locked => write!(f, "the vault is locked: run `scotoma unlock`"),
            Self::Password => write!(f, "wrong password"),
            Self::Io { context, source } => write!(f, "{context}: {source}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

#[cfg(test)]
#[path = "error_tests.rs"]
mod tests;
