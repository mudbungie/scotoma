use super::*;
use crate::testing::Scratch;

fn audit(scratch: &Scratch) -> Audit {
    Audit {
        path: scratch.path.join("audit.tsv"),
        actor: "tester".into(),
    }
}

fn act<'a>(event: &'a str, secret: &'a str, handle: &'a str) -> Act<'a> {
    Act {
        event,
        secret,
        handle,
        grant: "g1",
    }
}

#[test]
fn a_line_is_six_tab_separated_fields() {
    let scratch = Scratch::new();
    let audit = audit(&scratch);
    audit.record(act("set", "k", "-")).unwrap();
    let log = fs::read_to_string(&audit.path).unwrap();
    let fields: Vec<&str> = log.trim_end().split('\t').collect();
    assert!(fields[0].parse::<u64>().unwrap() > 0);
    assert_eq!(fields[1..], ["tester", "set", "k", "-", "g1"]);
    assert!(log.ends_with('\n'));
}

#[test]
fn issued_is_read_back_from_the_log_alone() {
    let scratch = Scratch::new();
    let audit = audit(&scratch);
    assert_eq!(audit.issued().unwrap(), []);
    audit.record(act("set", "k", "-")).unwrap();
    audit.record(act(ISSUE, "k", "h1")).unwrap();
    audit.record(act("use", "k", "h1")).unwrap();
    audit.record(act(ISSUE, "j", "h2")).unwrap();
    fs::write(
        &audit.path,
        fs::read_to_string(&audit.path).unwrap() + "torn line",
    )
    .unwrap();
    let expected = [
        ("h1".to_owned(), "k".to_owned()),
        ("h2".to_owned(), "j".to_owned()),
    ];
    assert_eq!(audit.issued().unwrap(), expected);
}

#[test]
fn an_unusable_log_is_an_error_not_silence() {
    let scratch = Scratch::new();
    let audit = audit(&scratch);
    fs::create_dir(&audit.path).unwrap();
    assert!(matches!(
        audit.record(act("set", "k", "-")),
        Err(Error::Io { .. })
    ));
    assert!(matches!(audit.issued(), Err(Error::Io { .. })));
}

#[test]
fn a_uuid_is_version_4() {
    assert_eq!(uuid([0xff; 16]), "ffffffff-ffff-4fff-bfff-ffffffffffff");
    assert_eq!(uuid([0; 16]), "00000000-0000-4000-8000-000000000000");
}
