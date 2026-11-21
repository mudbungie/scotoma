use super::*;
use crate::testing::Scratch;
use std::fs;

fn audit(scratch: &Scratch) -> Audit {
    Audit {
        path: scratch.path.join("audit.tsv"),
        actor: "tester".into(),
    }
}

fn act<'a>(event: &'a str, secret: &'a str, note: &'a str) -> Act<'a> {
    Act {
        event,
        secret,
        grant: "g1",
        note,
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
    assert_eq!(fields[1..], ["tester", "set", "k", "g1", "-"]);
    assert!(log.ends_with('\n'));
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
}

#[test]
fn a_uuid_is_version_4() {
    assert_eq!(uuid([0xff; 16]), "ffffffff-ffff-4fff-bfff-ffffffffffff");
    assert_eq!(uuid([0; 16]), "00000000-0000-4000-8000-000000000000");
}
