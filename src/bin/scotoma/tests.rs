//! The command line driven in-process, with fake streams and environment.

mod support;

use crate::cli::USAGE;
use std::fs;
use support::{Broken, Home, Outcome, drive, failed, run_with};

#[test]
fn anything_that_is_not_a_command_prints_usage() {
    let home = Home::unlocked("");
    for args in [
        &[][..],
        &["bogus"],
        &["set"],
        &["ls", "extra"],
        &["run"],
        &["grant"],
    ] {
        let usage = Outcome {
            code: 2,
            out: String::new(),
            err: USAGE.to_owned(),
        };
        assert_eq!(home.run(args, b""), usage, "{args:?}");
    }
    assert_eq!(run_with(&[], &["ls"], b"").code, 2);
}

#[test]
fn the_vault_is_found_through_the_environment() {
    let locked = |outcome: Outcome| failed(&outcome) && outcome.err.contains("scotoma unlock");
    assert!(locked(run_with(
        &[("XDG_DATA_HOME", "/nonexistent")],
        &["ls"],
        b""
    )));
    assert!(locked(run_with(&[("HOME", "/nonexistent")], &["ls"], b"")));
    assert!(locked(run_with(
        &[("SCOTOMA_HOME", "/nonexistent")],
        &["lock"],
        b""
    )));
    assert!(locked(run_with(
        &[("SCOTOMA_HOME", "/nonexistent")],
        &["redact"],
        b""
    )));
    assert!(locked(run_with(
        &[("SCOTOMA_HOME", "/nonexistent")],
        &["guard"],
        b""
    )));
}

#[test]
fn the_actor_is_named_by_the_environment() {
    let home = Home::unlocked("");
    let vault = ("SCOTOMA_HOME", home.dir.as_str());
    run_with(&[vault], &["set", "a"], b"1");
    run_with(&[vault, ("USER", "someone")], &["set", "a"], b"1");
    run_with(
        &[vault, ("USER", "someone"), ("SCOTOMA_ACTOR", "agent-7")],
        &["set", "a"],
        b"1",
    );
    let log = fs::read_to_string(home.path("audit.tsv")).unwrap();
    let actors: Vec<&str> = log
        .lines()
        .map(|line| line.split('\t').nth(1).unwrap())
        .collect();
    assert_eq!(actors, ["unknown", "someone", "agent-7"]);
    assert!(failed(&run_with(
        &[vault, ("SCOTOMA_ACTOR", "two words")],
        &["ls"],
        b""
    )));
}

#[test]
fn unlock_serves_until_lock_and_refuses_a_wrong_password() {
    let mut home = Home::unlocked("");
    assert_eq!(
        home.run(&["set", "pw"], b"hunter2\n"),
        Outcome {
            code: 0,
            out: String::new(),
            err: String::new()
        }
    );
    assert_eq!(home.lock(), 0);
    assert!(failed(&home.run(&["ls"], b"")));
    assert!(
        !fs::read(home.path("secrets/pw"))
            .unwrap()
            .windows(7)
            .any(|window| window == b"hunter2")
    );

    home.unlock("wrong\n");
    assert_eq!(home.lock(), 1);
    assert!(home.terminal.text().ends_with("scotoma: wrong password\n"));
    home.unlock("pw\n");
    assert_eq!(home.run(&["ls"], b"").out, "pw\n");
}

#[test]
fn a_grant_is_asked_for_and_lets_a_secret_be_used_but_not_seen() {
    let mut home = Home::unlocked("y\nn\n");
    home.run(&["set", "pw"], b"hunter2\n");
    assert!(failed(&home.run(&["issue", "pw"], b"")));
    assert!(failed(&home.run(&["sub"], b"x")));

    home.grant = home
        .run(&["grant", "1h", "pw"], b"")
        .out
        .trim_end()
        .to_owned();
    assert_eq!(home.grant.len(), 36);
    assert!(
        home.terminal
            .text()
            .contains("grant requested by unknown: pw for 1h")
    );
    // Holding a grant, the caller is answered by it: a narrower grant is
    // minted and nobody is asked.
    assert_eq!(home.run(&["grant", "1x,run"], b"").out.len(), 37);
    assert_eq!(home.terminal.text().matches("approve?").count(), 1);
    assert!(failed(&home.run(&["grant", "soon"], b"")));

    let handle = home.run(&["issue", "pw"], b"").out.trim_end().to_owned();
    let command = format!("curl -u admin:{handle}");
    assert_eq!(
        home.run(&["sub"], command.as_bytes()).out,
        "curl -u admin:hunter2"
    );
    let script = "test \"$1\" = hunter2 && echo \"password is $1\" && echo oops >&2 && exit 3";
    let ran = home.run(&["run", "sh", "-c", script, "sh", &handle], b"");
    assert_eq!(
        ran,
        Outcome {
            code: 3,
            out: format!("password is {handle}\n"),
            err: "oops\n".into()
        }
    );
}

#[test]
fn redact_rewrites_and_guard_refuses() {
    let home = Home::unlocked("");
    home.run(&["set", "pw"], b"hunter2");
    home.run(&["set", "short"], b"ab");
    home.run(&["set", "long"], b"abc");
    assert_eq!(
        home.run(&["redact"], b"saw hunter2\n").out,
        "saw [scotoma:pw]\n"
    );
    assert_eq!(home.run(&["guard"], b"clean\n").out, "clean\n");
    let caught = home.run(&["guard"], b"saw hunter2\n");
    assert!(
        failed(&caught) && caught.err.contains("\"pw\""),
        "{caught:?}"
    );
    // Decided only when the input ends.
    assert!(failed(&home.run(&["guard"], b"ab")));
    assert_eq!(home.run(&["rm", "pw"], b"").code, 0);
    assert_eq!(home.run(&["ls"], b"").out, "long\nshort\n");
}

#[test]
fn failures_exit_1_and_say_why() {
    let home = Home::unlocked("");
    assert!(failed(&home.run(&["rm", "absent"], b"")));
    assert!(failed(&home.run(&["set", "pw"], b"\xff")));
    assert!(failed(&home.run(&["set", "pw"], b"")));
    assert!(failed(&home.run(&["run", "true"], b"")));
}

#[test]
fn broken_streams_are_failures() {
    let mut home = Home::unlocked("y\ny\n");
    home.run(&["set", "pw"], b"hunter2");
    home.grant = home.run(&["grant", "1h"], b"").out.trim_end().to_owned();
    let env = home.env();
    let cases: [&[&str]; 6] = [
        &["ls"],
        &["issue", "pw"],
        &["grant", "1h"],
        &["sub"],
        &["redact"],
        &["run", "echo", "hi"],
    ];
    for args in cases {
        let (code, err) = drive(&env, args, &mut &b"text"[..], &mut Broken);
        assert!(
            code == 1 && err.starts_with("scotoma: \"output\""),
            "{args:?}: {err}"
        );
    }
    let (code, err) = drive(&env, &["redact"], &mut Broken, &mut Vec::new());
    assert!(code == 1 && err.starts_with("scotoma: \"input\""), "{err}");
}
