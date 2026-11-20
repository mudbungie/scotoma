//! The cryptography, all of it: a password stretched into a key (Argon2id),
//! and authenticated encryption under a 256-bit key (XChaCha20-Poly1305).
//!
//! Symmetric only, so there is nothing here for a quantum computer to break
//! outright. Every function is total: a failure is `None`, never a panic.

use crate::Error;
use argon2::Argon2;
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce};
use std::fs::File;
use std::io::Read;
use std::path::Path;

pub(crate) type Secret = [u8; 32];
pub(crate) type Nonce = [u8; 24];
pub(crate) type Salt = [u8; 16];

/// `N` random bytes from `entropy` (in production, `/dev/urandom`).
pub(crate) fn random<const N: usize>(entropy: &Path) -> Result<[u8; N], Error> {
    let mut bytes = [0; N];
    File::open(entropy)
        .and_then(|mut file| file.read_exact(&mut bytes))
        .map(|()| bytes)
        .map_err(Error::io(entropy))
}

/// The key a password stands for, under this salt. Deliberately slow.
pub(crate) fn stretch(password: &str, salt: &Salt) -> Option<Secret> {
    let mut key = [0; 32];
    Argon2::default()
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .ok()
        .map(|()| key)
}

/// Encrypt `plain`, bound to `context`: the blob opens only under the same
/// key AND the same context. Returns `nonce || ciphertext || tag`.
pub(crate) fn seal(key: &Secret, nonce: Nonce, context: &[u8], plain: &[u8]) -> Option<Vec<u8>> {
    let message = Payload {
        msg: plain,
        aad: context,
    };
    XChaCha20Poly1305::new(Key::from_slice(key))
        .encrypt(XNonce::from_slice(&nonce), message)
        .ok()
        .map(|sealed| [nonce.as_slice(), &sealed].concat())
}

/// The inverse of [`seal`]; `None` for a wrong key, a wrong context, or a
/// blob that was altered or cut short.
pub(crate) fn open(key: &Secret, context: &[u8], blob: &[u8]) -> Option<Vec<u8>> {
    let (nonce, sealed) = blob.split_first_chunk::<24>()?;
    let message = Payload {
        msg: sealed,
        aad: context,
    };
    XChaCha20Poly1305::new(Key::from_slice(key))
        .decrypt(XNonce::from_slice(nonce), message)
        .ok()
}

#[cfg(test)]
#[path = "crypt_tests.rs"]
mod tests;
