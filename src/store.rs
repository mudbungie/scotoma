//! Where secrets live: one file per secret, named by the secret.
//!
//! The name is the path, so there is no index to drift. The directory is
//! 0700 and each file 0600; the values are NOT encrypted at rest.

use crate::Error;
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{ErrorKind, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::PathBuf;

/// A name is a file name and a log field: one conservative alphabet for both.
pub(crate) fn check(name: &str) -> Result<(), Error> {
    let legal = |byte: u8| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-');
    if (1..=128).contains(&name.len()) && !name.starts_with('.') && name.bytes().all(legal) {
        Ok(())
    } else {
        Err(Error::Name(name.to_owned()))
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Store {
    pub dir: PathBuf,
}

impl Store {
    fn path(&self, name: &str) -> Result<PathBuf, Error> {
        check(name)?;
        Ok(self.dir.join(name))
    }

    pub fn put(&self, name: &str, value: &str) -> Result<(), Error> {
        let path = self.path(name)?;
        if value.is_empty() {
            return Err(Error::Empty);
        }
        let mut file = OpenOptions::new();
        file.write(true).create(true).truncate(true).mode(0o600);
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&self.dir)
            .and_then(|()| file.open(&path))
            .and_then(|mut file| file.write_all(value.as_bytes()))
            .map_err(Error::io(&path))
    }

    pub fn get(&self, name: &str) -> Result<Option<String>, Error> {
        let path = self.path(name)?;
        match fs::read_to_string(&path) {
            Ok(value) => Ok(Some(value)),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
            Err(error) => Err(Error::io(&path)(error)),
        }
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

    /// Every `(name, value)`, sorted by name. A file whose name is not a
    /// legal secret name is not a secret and is skipped.
    pub fn all(&self) -> Result<Vec<(String, String)>, Error> {
        let listing = fs::read_dir(&self.dir).and_then(Iterator::collect::<Result<Vec<_>, _>>);
        let files = match listing {
            Ok(files) => files,
            Err(error) if error.kind() == ErrorKind::NotFound => Vec::new(),
            Err(error) => return Err(Error::io(&self.dir)(error)),
        };
        let mut secrets = Vec::new();
        for file in files {
            let name = file.file_name().to_string_lossy().into_owned();
            if check(&name).is_ok() {
                secrets.extend(self.get(&name)?.map(|value| (name, value)));
            }
        }
        secrets.sort();
        Ok(secrets)
    }
}

#[cfg(test)]
#[path = "store_tests.rs"]
mod tests;
