use super::*;
use crate::testing::Scratch;
use std::os::unix::fs::PermissionsExt;

const NONCE: Nonce = [3; 24];

fn store(scratch: &Scratch) -> Store {
    Store {
        dir: scratch.path.join("secrets"),
        key: [7; 32],
    }
}

#[test]
fn names_are_a_conservative_alphabet() {
    for good in ["a", "A-b_c.9", &"n".repeat(128)] {
        assert!(check(good).is_ok(), "{good}");
    }
    for bad in ["", ".hidden", "a b", "a/b", "tab\t", "é", &"n".repeat(129)] {
        assert!(
            matches!(check(bad), Err(Error::Name(name)) if name == bad),
            "{bad}"
        );
    }
}

#[test]
fn put_get_drop_round_trip() {
    let scratch = Scratch::new();
    let store = store(&scratch);
    assert_eq!(store.get("k").unwrap(), None);
    store.put("k", "one", NONCE).unwrap();
    store.put("k", "v", NONCE).unwrap();
    assert_eq!(store.get("k").unwrap().as_deref(), Some("v"));
    store.drop("k").unwrap();
    assert!(matches!(store.drop("k"), Err(Error::Unknown(name)) if name == "k"));
}

#[test]
fn files_are_private_and_hold_no_plaintext() {
    let scratch = Scratch::new();
    let store = store(&scratch);
    store.put("k", "plaintext-value", NONCE).unwrap();
    let mode = |path: &PathBuf| fs::metadata(path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&store.dir), 0o700);
    assert_eq!(mode(&store.dir.join("k")), 0o600);
    let on_disk = fs::read(store.dir.join("k")).unwrap();
    assert!(!on_disk.windows(9).any(|window| window == b"plaintext"));
}

#[test]
fn a_secret_opens_only_under_its_own_key_and_name() {
    let scratch = Scratch::new();
    let store = store(&scratch);
    store.put("k", "v", NONCE).unwrap();
    let stranger = Store {
        key: [8; 32],
        ..store.clone()
    };
    assert!(matches!(stranger.get("k"), Err(Error::Sealed)));
    fs::copy(store.dir.join("k"), store.dir.join("j")).unwrap();
    assert!(matches!(store.get("j"), Err(Error::Sealed)));
    assert!(matches!(store.all(), Err(Error::Sealed)));
}

#[test]
fn bad_input_is_refused_before_the_disk_is_touched() {
    let scratch = Scratch::new();
    let store = store(&scratch);
    assert!(matches!(store.put("../k", "v", NONCE), Err(Error::Name(_))));
    assert!(matches!(store.get("../k"), Err(Error::Name(_))));
    assert!(matches!(store.drop("../k"), Err(Error::Name(_))));
    assert!(matches!(store.put("k", "", NONCE), Err(Error::Empty)));
    assert!(!store.dir.exists());
}

#[test]
fn listings_are_sorted_and_skip_strangers() {
    let scratch = Scratch::new();
    let store = store(&scratch);
    assert_eq!(store.all().unwrap(), []);
    store.put("b", "2", NONCE).unwrap();
    store.put("a", "1", NONCE).unwrap();
    fs::write(store.dir.join(".stranger"), "x").unwrap();
    assert_eq!(store.names().unwrap(), ["a", "b"]);
    let expected = [
        ("a".to_owned(), "1".to_owned()),
        ("b".to_owned(), "2".to_owned()),
    ];
    assert_eq!(store.all().unwrap(), expected);
}

#[test]
fn filesystem_failures_surface_as_io() {
    let scratch = Scratch::new();
    let store = store(&scratch);
    // A directory where a secret file should be.
    fs::create_dir_all(store.dir.join("k")).unwrap();
    assert!(matches!(store.put("k", "v", NONCE), Err(Error::Io { .. })));
    assert!(matches!(store.get("k"), Err(Error::Io { .. })));
    assert!(matches!(store.drop("k"), Err(Error::Io { .. })));
    assert!(matches!(store.all(), Err(Error::Io { .. })));
    // A file where the secrets directory should be.
    let blocked = Store {
        dir: scratch.path.join("file"),
        key: [7; 32],
    };
    fs::write(&blocked.dir, "x").unwrap();
    assert!(matches!(blocked.names(), Err(Error::Io { .. })));
    assert!(matches!(blocked.all(), Err(Error::Io { .. })));
}
