//! Where secrets live: one encrypted file per secret, named by the secret.
//!
//! The name is the path, so there is no index to drift. Each file is sealed
//! under the vault key and bound to its own name, so a file copied over
//! another secret's does not open.

use crate::Error;
use crate::crypt::{self, Nonce, Secret};
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{self, ErrorKind, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

/// A name is a file name and a log field: one conservative alphabet for both.
pub(crate) fn check(name: &str) -> Result<(), Error> {
    let legal = |byte: u8| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-');
    if (1..=128).contains(&name.len()) && !name.starts_with('.') && name.bytes().all(legal) {
        Ok(())
    } else {
        Err(Error::Name(name.to_owned()))
    }
}

/// Write `bytes` to `dir/file`, private to the user, creating `dir` (0700).
pub(crate) fn write_private(dir: &Path, file: &str, bytes: &[u8]) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true).mode(0o600);
    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .and_then(|()| options.open(dir.join(file)))
        .and_then(|mut file| file.write_all(bytes))
}

#[derive(Debug, Clone)]
pub(crate) struct Store {
    pub dir: PathBuf,
    pub key: Secret,
}

impl Store {
    fn path(&self, name: &str) -> Result<PathBuf, Error> {
        check(name)?;
        Ok(self.dir.join(name))
    }

    pub fn put(&self, name: &str, value: &str, nonce: Nonce) -> Result<(), Error> {
        let path = self.path(name)?;
        if value.is_empty() {
            return Err(Error::Empty);
        }
        crypt::seal(&self.key, nonce, name.as_bytes(), value.as_bytes())
            .ok_or(Error::Sealed)
            .and_then(|blob| write_private(&self.dir, name, &blob).map_err(Error::io(&path)))
    }

    pub fn get(&self, name: &str) -> Result<Option<String>, Error> {
        let path = self.path(name)?;
        let blob = match fs::read(&path) {
            Ok(blob) => blob,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(Error::io(&path)(error)),
        };
        crypt::open(&self.key, name.as_bytes(), &blob)
            .and_then(|plain| String::from_utf8(plain).ok())
            .ok_or(Error::Sealed)
            .map(Some)
    }

    pub fn drop(&self, name: &str) -> Result<(), Error> {
        let path = self.path(name)?;
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == ErrorKind::NotFound => {
                Err(Error::Unknown(name.to_owned()))
            }
            Err(error) => Err(Error::io(&path)(error)),
        }
    }

    /// The stored names, sorted. A file whose name is not a legal secret
    /// name is not a secret and is skipped. Needs no key.
    pub fn names(&self) -> Result<Vec<String>, Error> {
        let listing = fs::read_dir(&self.dir).and_then(Iterator::collect::<Result<Vec<_>, _>>);
        let files = match listing {
            Ok(files) => files,
            Err(error) if error.kind() == ErrorKind::NotFound => Vec::new(),
            Err(error) => return Err(Error::io(&self.dir)(error)),
        };
        let names = files
            .iter()
            .map(|file| file.file_name().to_string_lossy().into_owned());
        let mut names: Vec<String> = names.filter(|name| check(name).is_ok()).collect();
        names.sort();
        Ok(names)
    }

    /// Every `(name, value)`, sorted by name.
    pub fn all(&self) -> Result<Vec<(String, String)>, Error> {
        let mut secrets = Vec::new();
        for name in self.names()? {
            secrets.extend(self.get(&name)?.map(|value| (name, value)));
        }
        Ok(secrets)
    }
}

#[cfg(test)]
#[path = "store_tests.rs"]
mod tests;
