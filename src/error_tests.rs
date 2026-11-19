use super::*;
use std::error::Error as _;

#[test]
fn every_variant_says_what_went_wrong() {
    let io = Error::io("the/path")(io::Error::other("boom"));
    assert_eq!(io.to_string(), "\"the/path\": boom");
    assert!(io.source().is_some());
    assert!(format!("{io:?}").contains("Io"));
    let name = Error::Name("a b".into());
    assert_eq!(
        name.to_string(),
        "invalid name \"a b\": use 1-128 of A-Z a-z 0-9 . _ -"
    );
    assert!(name.source().is_none());
    assert_eq!(
        Error::Unknown("k".into()).to_string(),
        "no secret named \"k\""
    );
    assert_eq!(Error::Empty.to_string(), "a secret value may not be empty");
    let leak = Error::Leak("k".into()).to_string();
    assert_eq!(leak, "secret \"k\" found in outgoing content");
}
