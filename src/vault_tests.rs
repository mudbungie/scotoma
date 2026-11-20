use super::*;
use crate::testing::Scratch;
use std::fs;

fn vault(scratch: &Scratch) -> Vault {
    Vault::new(&scratch.path, [7; 32], Path::new("/dev/urandom"))
        .acting("tester")
        .unwrap()
}

fn only(names: &[&str]) -> Grant {
    let names = names.iter().map(|&name| name.to_owned()).collect();
    Grant {
        id: "g1".into(),
        names,
        expires: u64::MAX,
    }
}

/// The log as `event secret handle grant` tails.
fn log(scratch: &Scratch) -> Vec<String> {
    let text = fs::read_to_string(scratch.path.join("audit.tsv")).unwrap();
    let tail = |line: &str| line.split('\t').skip(2).collect::<Vec<_>>().join(" ");
    text.lines().map(tail).collect()
}

/// One whole string through a flow.
fn pass(mut flow: Flow, text: &str) -> Result<String, Error> {
    let (bytes, _) = flow.feed(text.as_bytes(), true)?;
    Ok(String::from_utf8(bytes).unwrap())
}

fn break_log(scratch: &Scratch) {
    let path = scratch.path.join("audit.tsv");
    let _ = fs::remove_file(&path);
    fs::create_dir(&path).unwrap();
}

fn break_store(scratch: &Scratch) {
    let path = scratch.path.join("secrets");
    let _ = fs::remove_dir_all(&path);
    fs::write(&path, "not a directory").unwrap();
}

#[test]
fn the_actor_must_be_a_name() {
    let scratch = Scratch::new();
    assert!(matches!(
        vault(&scratch).acting("two words"),
        Err(Error::Name(_))
    ));
}

#[test]
fn each_act_is_logged_under_its_actor() {
    let scratch = Scratch::new();
    let vault = vault(&scratch);
    vault.set("b", "2").unwrap();
    vault.set("a", "1").unwrap();
    vault.remove("a").unwrap();
    assert_eq!(vault.store.names().unwrap(), ["b"]);
    assert_eq!(log(&scratch), ["set b - -", "set a - -", "remove a - -"]);
    let line = fs::read_to_string(scratch.path.join("audit.tsv")).unwrap();
    assert_eq!(
        line.lines().next().unwrap().split('\t').nth(1),
        Some("tester")
    );
}

#[test]
fn a_handle_substitutes_under_a_grant_and_each_use_is_logged() {
    let scratch = Scratch::new();
    let vault = vault(&scratch);
    vault.set("pw", "hunter2").unwrap();
    let handle = vault.issue("pw", &only(&["pw"])).unwrap();
    assert_eq!(handle.len(), 36);
    let command = format!("curl -u admin:{handle}");
    let flow = vault.substituter(only(&[])).unwrap();
    assert_eq!(pass(flow, &command).unwrap(), "curl -u admin:hunter2");
    let expected = [
        "set pw - -".to_owned(),
        format!("issue pw {handle} g1"),
        format!("use pw {handle} g1"),
    ];
    assert_eq!(log(&scratch), expected);
}

#[test]
fn a_handle_follows_its_secret() {
    let scratch = Scratch::new();
    let vault = vault(&scratch);
    vault.set("pw", "old").unwrap();
    let handle = vault.issue("pw", &Grant::none()).unwrap();
    vault.set("pw", "new").unwrap();
    assert_eq!(
        pass(vault.substituter(Grant::none()).unwrap(), &handle).unwrap(),
        "new"
    );
    vault.remove("pw").unwrap();
    assert_eq!(
        pass(vault.substituter(Grant::none()).unwrap(), &handle).unwrap(),
        handle
    );
}

#[test]
fn a_grant_reaches_only_the_secrets_it_names() {
    let scratch = Scratch::new();
    let vault = vault(&scratch);
    vault.set("pw", "hunter2").unwrap();
    vault.set("other", "swordfish").unwrap();
    let handle = vault.issue("pw", &Grant::none()).unwrap();
    assert!(matches!(
        vault.issue("pw", &only(&["other"])),
        Err(Error::Denied(_))
    ));
    let narrow = vault.substituter(only(&["other"])).unwrap();
    assert!(matches!(pass(narrow, &handle), Err(Error::Denied(why)) if why.contains("\"pw\"")));
    assert!(matches!(
        vault.issue("absent", &Grant::none()),
        Err(Error::Unknown(_))
    ));
    assert!(matches!(
        vault.issue("not a name", &Grant::none()),
        Err(Error::Name(_))
    ));
    let stranger = "00000000-0000-4000-8000-000000000000";
    assert_eq!(
        pass(vault.substituter(Grant::none()).unwrap(), stranger).unwrap(),
        stranger
    );
}

#[test]
fn redaction_names_the_secret_and_the_guard_refuses_it() {
    let scratch = Scratch::new();
    let vault = vault(&scratch);
    vault.set("pw", "hunter2").unwrap();
    vault.set("key", "say \"hi\"").unwrap();
    assert_eq!(
        pass(vault.redactor().unwrap(), "got hunter2!").unwrap(),
        "got [scotoma:pw]!"
    );
    let body = r#"{"content":"say \"hi\""}"#;
    assert_eq!(
        pass(vault.redactor().unwrap(), body).unwrap(),
        r#"{"content":"[scotoma:key]"}"#
    );
    assert_eq!(pass(vault.guard().unwrap(), "clean").unwrap(), "clean");
    let caught = pass(vault.guard().unwrap(), "it is hunter2");
    assert!(matches!(caught, Err(Error::Leak(name)) if name == "pw"));
    assert_eq!(
        log(&scratch).split_off(2),
        ["redact pw - -", "redact key - -", "leak pw - -"]
    );
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
fn a_flow_catches_a_secret_split_across_chunks() {
    let scratch = Scratch::new();
    let vault = vault(&scratch);
    vault.set("pw", "hunter2").unwrap();
    let mut flow = vault.redactor().unwrap();
    let mut out = flow.feed(b"it is hun", false).unwrap().0;
    assert_eq!(out, b"it is ");
    out.extend(flow.feed(b"ter2 and hun", false).unwrap().0);
    out.extend(flow.feed(b"", true).unwrap().0);
    assert_eq!(out, b"it is [scotoma:pw] and hun");
}

#[test]
fn an_armed_command_gets_the_value_and_its_output_gets_the_handle_back() {
    let scratch = Scratch::new();
    let vault = vault(&scratch);
    vault.set("pw", "hunter2").unwrap();
    vault.set("other", "swordfish").unwrap();
    let handle = vault.issue("pw", &Grant::none()).unwrap();
    let command = ["echo".to_owned(), format!("password is {handle}")];
    let (words, output) = vault.arm(&command, Grant::none()).unwrap();
    assert_eq!(words, ["echo", "password is hunter2"]);
    let shown = pass(output, "password is hunter2, not swordfish").unwrap();
    assert_eq!(shown, format!("password is {handle}, not [scotoma:other]"));
    assert!(matches!(
        vault.arm(&command, only(&["other"])),
        Err(Error::Denied(_))
    ));
}

#[test]
fn nothing_is_released_when_the_log_cannot_be_written() {
    let scratch = Scratch::new();
    let vault = vault(&scratch);
    vault.set("pw", "hunter2").unwrap();
    let handle = vault.issue("pw", &Grant::none()).unwrap();
    let substituter = vault.substituter(Grant::none()).unwrap();
    break_log(&scratch);
    assert!(matches!(pass(substituter, &handle), Err(Error::Io { .. })));
    assert!(matches!(
        vault.substituter(Grant::none()),
        Err(Error::Io { .. })
    ));
    assert!(matches!(
        vault.arm(&[handle], Grant::none()),
        Err(Error::Io { .. })
    ));
    assert!(matches!(
        vault.issue("pw", &Grant::none()),
        Err(Error::Io { .. })
    ));
    assert!(matches!(vault.set("pw", "v"), Err(Error::Io { .. })));
    assert!(matches!(vault.remove("pw"), Err(Error::Io { .. })));
}

#[test]
fn a_broken_store_is_an_error_everywhere() {
    let scratch = Scratch::new();
    let vault = vault(&scratch);
    break_store(&scratch);
    assert!(matches!(
        vault.substituter(Grant::none()),
        Err(Error::Io { .. })
    ));
    assert!(matches!(vault.redactor(), Err(Error::Io { .. })));
    assert!(matches!(vault.guard(), Err(Error::Io { .. })));
    assert!(matches!(
        vault.arm(&[], Grant::none()),
        Err(Error::Io { .. })
    ));
    assert!(matches!(vault.set("bad name", "v"), Err(Error::Name(_))));
    assert!(matches!(vault.remove("absent"), Err(Error::Io { .. })));
}

#[test]
fn no_entropy_no_secret_and_no_handle() {
    let scratch = Scratch::new();
    let vault = vault(&scratch);
    vault.set("pw", "hunter2").unwrap();
    let starved = Vault {
        entropy: scratch.path.join("no-entropy"),
        ..vault
    };
    assert!(matches!(starved.set("new", "v"), Err(Error::Io { .. })));
    assert!(matches!(
        starved.issue("pw", &Grant::none()),
        Err(Error::Io { .. })
    ));
    assert_eq!(log(&scratch), ["set pw - -"]);
}
