//! The password becomes the vault key: the one step that can open a vault.

use crate::crypt::{self, Secret};
use crate::resident::{Console, ask, say};
use crate::{Error, store};
use std::fs;
use std::io::ErrorKind;
use std::path::Path;

/// What the wrapped vault key is bound to.
const KEY_CONTEXT: &[u8] = b"scotoma vault key";

/// The password becomes the vault key, or does not.
pub(crate) fn admit(home: &Path, console: &mut Console, entropy: &Path) -> Result<Secret, Error> {
    let path = home.join("key");
    let stored = match fs::read(&path) {
        Ok(stored) => Some(stored),
        Err(error) if error.kind() == ErrorKind::NotFound => None,
        Err(error) => return Err(Error::io(&path)(error)),
    };
    (console.echo)(false);
    let password = ask(console, "password: ");
    let again = if stored.is_none() {
        ask(console, "\nagain: ")
    } else {
        password.clone()
    };
    (console.echo)(true);
    say(console, "\n");
    if password.is_empty() || password != again {
        return Err(Error::Password);
    }
    match stored {
        None => found(home, &password, entropy),
        Some(stored) => stored
            .split_first_chunk::<16>()
            .and_then(|(salt, blob)| {
                let wrap = crypt::stretch(&password, salt);
                wrap.and_then(|wrap| crypt::open(&wrap, KEY_CONTEXT, blob))
            })
            .and_then(|key| Secret::try_from(key).ok())
            .ok_or(Error::Password),
    }
}

/// A new vault: a random key, stored wrapped under the password.
fn found(home: &Path, password: &str, entropy: &Path) -> Result<Secret, Error> {
    let (salt, key, nonce) = crypt::random::<16>(entropy).and_then(|salt| {
        let key = crypt::random::<32>(entropy);
        key.and_then(|key| crypt::random(entropy).map(|nonce| (salt, key, nonce)))
    })?;
    crypt::stretch(password, &salt)
        .and_then(|wrap| crypt::seal(&wrap, nonce, KEY_CONTEXT, &key))
        .ok_or(Error::Sealed)
        .and_then(|blob| {
            let file = [salt.as_slice(), &blob].concat();
            store::write_private(home, "key", &file).map_err(Error::io(home))
        })
        .map(|()| key)
}
