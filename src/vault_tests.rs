use super::*;
use crate::testing::Scratch;
use std::fs;

fn vault(scratch: &Scratch) -> Scotoma {
    Scotoma::open(&scratch.path, "tester").unwrap()
}

/// The log as `event secret handle` triples.
fn log(scratch: &Scratch) -> Vec<String> {
    let text = fs::read_to_string(scratch.path.join("audit.tsv")).unwrap();
    let tail = |line: &str| line.split('\t').skip(2).collect::<Vec<_>>().join(" ");
    text.lines().map(tail).collect()
}

/// Make every later log read and write fail.
fn break_log(scratch: &Scratch) {
    let path = scratch.path.join("audit.tsv");
    let _ = fs::remove_file(&path);
    fs::create_dir(&path).unwrap();
}

/// Make every later listing of the secrets fail.
fn break_store(scratch: &Scratch) {
    let path = scratch.path.join("secrets");
    let _ = fs::remove_dir_all(&path);
    fs::write(&path, "not a directory").unwrap();
}

#[test]
fn the_actor_must_be_a_name() {
    assert!(matches!(
        Scotoma::open("/nowhere", "two words"),
        Err(Error::Name(_))
    ));
}

#[test]
fn secrets_are_set_listed_and_removed_and_each_act_is_logged() {
    let scratch = Scratch::new();
    let vault = vault(&scratch);
    assert_eq!(vault.names().unwrap(), [""; 0]);
    vault.set("b", "2").unwrap();
    vault.set("a", "1").unwrap();
    assert_eq!(vault.names().unwrap(), ["a", "b"]);
    vault.remove("a").unwrap();
    assert_eq!(vault.names().unwrap(), ["b"]);
    assert_eq!(log(&scratch), ["set b -", "set a -", "remove a -"]);
    let line = fs::read_to_string(scratch.path.join("audit.tsv")).unwrap();
    assert_eq!(
        line.lines().next().unwrap().split('\t').nth(1),
        Some("tester")
    );
}

#[test]
fn a_handle_substitutes_in_any_process_and_each_use_is_logged() {
    let scratch = Scratch::new();
    let vault = vault(&scratch);
    vault.set("pw", "hunter2").unwrap();
    let handle = vault.issue("pw").unwrap();
    assert_eq!(handle.len(), 36);

    let later = Scotoma::open(&scratch.path, "executor").unwrap();
    let command = format!("curl -u admin:{handle} -H 'X: {handle}'");
    assert_eq!(
        later.substitute(&command).unwrap(),
        "curl -u admin:hunter2 -H 'X: hunter2'"
    );
    let used = format!("use pw {handle}");
    assert_eq!(
        log(&scratch),
        [
            "set pw -".to_owned(),
            format!("issue pw {handle}"),
            used.clone(),
            used
        ]
    );
}

#[test]
fn a_handle_follows_its_secret() {
    let scratch = Scratch::new();
    let vault = vault(&scratch);
    vault.set("pw", "old").unwrap();
    let handle = vault.issue("pw").unwrap();
    vault.set("pw", "new").unwrap();
    assert_eq!(vault.substitute(&handle).unwrap(), "new");
    vault.remove("pw").unwrap();
    assert_eq!(vault.substitute(&handle).unwrap(), handle);
}

#[test]
fn only_issued_handles_substitute() {
    let scratch = Scratch::new();
    let vault = vault(&scratch);
    vault.set("pw", "hunter2").unwrap();
    let stranger = "00000000-0000-4000-8000-000000000000";
    assert_eq!(vault.substitute(stranger).unwrap(), stranger);
    assert_eq!(vault.substitute("pw").unwrap(), "pw");
    assert!(matches!(vault.issue("absent"), Err(Error::Unknown(name)) if name == "absent"));
    assert!(matches!(vault.issue("not a name"), Err(Error::Name(_))));
}

#[test]
fn redaction_names_the_secret_and_logs_the_catch() {
    let scratch = Scratch::new();
    let vault = vault(&scratch);
    vault.set("pw", "hunter2").unwrap();
    vault.set("key", "line1\nsay \"hi\"").unwrap();
    assert_eq!(vault.redact("clean").unwrap(), "clean");
    assert_eq!(vault.redact("got hunter2!").unwrap(), "got [scotoma:pw]!");
    assert_eq!(vault.redact("line1\nsay \"hi\"").unwrap(), "[scotoma:key]");
    let body = r#"{"content":"line1\nsay \"hi\""}"#;
    assert_eq!(
        vault.redact(body).unwrap(),
        r#"{"content":"[scotoma:key]"}"#
    );
    assert_eq!(
        log(&scratch).split_off(2),
        ["redact pw -", "redact key -", "redact key -"]
    );
}

#[test]
fn a_guard_passes_clean_content_and_refuses_a_secret() {
    let scratch = Scratch::new();
    let vault = vault(&scratch);
    vault.set("pw", "hunter2").unwrap();
    vault.set("key", "say \"hi\"").unwrap();
    assert!(vault.check("nothing to see").is_ok());
    assert!(matches!(vault.check("it is hunter2"), Err(Error::Leak(name)) if name == "pw"));
    let body = r#"{"content":"say \"hi\""}"#;
    assert!(matches!(vault.check(body), Err(Error::Leak(name)) if name == "key"));
    assert_eq!(log(&scratch).split_off(2), ["leak pw -", "leak key -"]);

    let mut guard = vault.guard().unwrap();
    assert_eq!(guard.push(b"clean, then hun").unwrap(), b"clean, then ");
    assert!(matches!(guard.push(b"ter2 and more"), Err(Error::Leak(_))));
}

#[test]
fn json_escapes_as_the_serializers_do() {
    assert_eq!(json("plain"), "plain");
    assert_eq!(
        json("\"\\\n\r\t\u{8}\u{c}\u{1}é"),
        "\\\"\\\\\\n\\r\\t\\b\\f\\u0001é"
    );
}

#[test]
fn a_stream_catches_a_secret_split_across_chunks() {
    let scratch = Scratch::new();
    let vault = vault(&scratch);
    vault.set("pw", "hunter2").unwrap();
    let mut stream = vault.redactor().unwrap();
    let mut out = stream.push(b"it is hun").unwrap();
    assert_eq!(out, b"it is ");
    out.extend(stream.push(b"ter2 and hun").unwrap());
    out.extend(stream.finish().unwrap());
    assert_eq!(out, b"it is [scotoma:pw] and hun");
}

#[test]
fn nothing_is_released_when_the_log_cannot_be_written() {
    let scratch = Scratch::new();
    let vault = vault(&scratch);
    vault.set("pw", "hunter2").unwrap();
    let handle = vault.issue("pw").unwrap();
    let mut substituter = vault.substituter().unwrap();
    break_log(&scratch);
    assert!(matches!(
        substituter.push(handle.as_bytes()),
        Err(Error::Io { .. })
    ));
    assert!(matches!(vault.redact("hunter2"), Err(Error::Io { .. })));
    assert!(matches!(vault.check("hunter2"), Err(Error::Io { .. })));
    assert!(matches!(vault.substitute(&handle), Err(Error::Io { .. })));
    assert!(matches!(vault.issue("pw"), Err(Error::Io { .. })));
    assert!(matches!(vault.set("pw", "v"), Err(Error::Io { .. })));
    assert!(matches!(vault.remove("pw"), Err(Error::Io { .. })));
}

#[test]
fn a_broken_store_is_an_error_everywhere() {
    let scratch = Scratch::new();
    let vault = vault(&scratch);
    break_store(&scratch);
    assert!(matches!(vault.names(), Err(Error::Io { .. })));
    assert!(matches!(vault.substitute("x"), Err(Error::Io { .. })));
    assert!(matches!(vault.redact("x"), Err(Error::Io { .. })));
    assert!(matches!(vault.check("x"), Err(Error::Io { .. })));
    assert!(matches!(vault.set("bad name", "v"), Err(Error::Name(_))));
    assert!(matches!(vault.remove("absent"), Err(Error::Io { .. })));
}

#[test]
fn no_entropy_no_handle() {
    let scratch = Scratch::new();
    let vault = vault(&scratch);
    vault.set("pw", "hunter2").unwrap();
    let missing = scratch.path.join("no-entropy");
    assert!(matches!(vault.mint("pw", &missing), Err(Error::Io { .. })));
    assert_eq!(log(&scratch), ["set pw -"]);
}
