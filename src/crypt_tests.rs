use super::*;
use crate::testing::Scratch;
use std::fs;

const KEY: Secret = [7; 32];

#[test]
fn what_is_sealed_opens_only_with_the_same_key_and_context() {
    let blob = seal(&KEY, [1; 24], b"name", b"value").unwrap();
    assert_eq!(blob.len(), 24 + 5 + 16);
    assert!(!blob.windows(5).any(|window| window == b"value"));
    assert_eq!(open(&KEY, b"name", &blob).unwrap(), b"value");
    assert_eq!(open(&[8; 32], b"name", &blob), None);
    assert_eq!(open(&KEY, b"other", &blob), None);
}

#[test]
fn an_altered_or_truncated_blob_does_not_open() {
    let mut blob = seal(&KEY, [1; 24], b"name", b"value").unwrap();
    assert_eq!(open(&KEY, b"name", &blob[..20]), None);
    blob[30] ^= 1;
    assert_eq!(open(&KEY, b"name", &blob), None);
}

#[test]
fn a_password_stretches_to_the_same_key_only_under_the_same_salt() {
    let key = stretch("correct horse", &[1; 16]).unwrap();
    assert_eq!(stretch("correct horse", &[1; 16]).unwrap(), key);
    assert_ne!(stretch("correct horse", &[2; 16]).unwrap(), key);
    assert_ne!(stretch("wrong horse", &[1; 16]).unwrap(), key);
}

#[test]
fn randomness_is_read_from_the_named_source() {
    let scratch = Scratch::new();
    let entropy = scratch.path.join("entropy");
    fs::write(&entropy, [9; 8]).unwrap();
    assert_eq!(random::<8>(&entropy).unwrap(), [9; 8]);
    assert!(matches!(random::<9>(&entropy), Err(Error::Io { .. })));
    let system = Path::new("/dev/urandom");
    assert_ne!(random::<16>(system).unwrap(), random::<16>(system).unwrap());
}
