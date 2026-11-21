use super::*;
use crate::testing::{Scratch, Unlocked};
use std::fs;
use std::io;
use std::os::unix::net::UnixListener;
use std::thread;

/// A writer that fails.
struct Broken;

impl Write for Broken {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("broken"))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Run a command through `client`; returns `(code, stdout, stderr)`.
fn run(client: &Scotoma, command: &[&str]) -> Result<(u8, String, String), Error> {
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = client.run(command, crate::testing::none(), &mut out, &mut err)?;
    let text = |bytes: Vec<u8>| String::from_utf8(bytes).unwrap();
    Ok((code, text(out), text(err)))
}

/// A socket where something accepts one call, says `first`, and hangs up.
fn impostor(first: Option<&'static [u8]>) -> (Scratch, Scotoma) {
    let scratch = Scratch::new();
    let listener = UnixListener::bind(scratch.path.join("socket")).unwrap();
    thread::spawn(move || {
        let (conn, _) = listener.accept().unwrap();
        wire::recv(&conn).unwrap();
        first.map(|body| wire::send(&conn, wire::OK, body));
    });
    let client = Scotoma::open(&scratch.path, "tester").unwrap();
    (scratch, client)
}

#[test]
fn a_locked_vault_answers_nothing() {
    let scratch = Scratch::new();
    assert!(matches!(
        Scotoma::open(&scratch.path, "two words"),
        Err(Error::Name(_))
    ));
    let client = Scotoma::open(&scratch.path, "tester").unwrap();
    assert!(matches!(client.set("pw", "v"), Err(Error::Locked)));
    assert!(matches!(client.names(), Err(Error::Locked)));
    assert!(matches!(client.pending(), Err(Error::Locked)));
    assert!(matches!(client.substitute("x"), Err(Error::Locked)));
    assert!(matches!(client.redact("x"), Err(Error::Locked)));
    assert!(matches!(client.check("x"), Err(Error::Locked)));
    assert!(matches!(run(&client, &["true"]), Err(Error::Locked)));
}

#[test]
fn secrets_are_set_listed_and_removed() {
    let unlocked = Unlocked::new("");
    let client = unlocked.client();
    assert_eq!(client.names().unwrap(), [""; 0]);
    unlocked.root().set("b", "2").unwrap();
    unlocked.root().set("a", "1").unwrap();
    assert_eq!(client.names().unwrap(), ["a", "b"]);
    unlocked.root().remove("a").unwrap();
    assert_eq!(client.names().unwrap(), ["b"]);
    assert!(matches!(unlocked.root().remove("a"), Err(Error::Unknown(name)) if name == "a"));
    assert!(matches!(unlocked.root().set("b", ""), Err(Error::Empty)));
    assert_eq!(unlocked.log(), ["set b", "set a", "remove a"]);
}

#[test]
fn a_placeholder_substitutes_for_a_caller_that_holds_a_grant() {
    let unlocked = Unlocked::new("y\ny\n");
    unlocked.root().set("pw", "hunter2").unwrap();
    unlocked.root().set("other", "swordfish").unwrap();
    let client = unlocked.granted(&["pw"]);
    let handle = "[scotoma:pw]".to_owned();
    let command = format!("curl -u admin:{handle} -H 'X: {handle}'");
    assert_eq!(
        client.substitute(&command).unwrap(),
        "curl -u admin:hunter2 -H 'X: hunter2'"
    );
    assert_eq!(unlocked.log().split_off(4), ["use pw", "use pw"]);

    assert!(matches!(
        client.substitute("[scotoma:other]"),
        Err(Error::Denied(_))
    ));
    let narrow = unlocked.granted(&["other"]);
    assert!(
        matches!(narrow.substitute(&handle), Err(Error::Denied(why)) if why.contains("\"pw\""))
    );
}

#[test]
fn redaction_rewrites_and_the_guard_refuses() {
    let unlocked = Unlocked::new("");
    let client = unlocked.client();
    unlocked.root().set("pw", "hunter2").unwrap();
    assert_eq!(client.redact("got hunter2!").unwrap(), "got [scotoma:pw]!");
    assert!(client.check("nothing to see").is_ok());
    assert!(matches!(client.check("it is hunter2"), Err(Error::Leak(name)) if name == "pw"));

    let mut guard = client.guard().unwrap();
    assert_eq!(guard.push(b"clean, then hun").unwrap(), b"clean, then ");
    assert!(matches!(guard.push(b"ter2 and more"), Err(Error::Leak(_))));
    assert_eq!(
        unlocked.log().split_off(1),
        ["redact pw", "leak pw", "leak pw"]
    );
}

#[test]
fn a_match_decided_only_at_the_end_is_still_caught() {
    let unlocked = Unlocked::new("");
    let client = unlocked.client();
    unlocked.root().set("short", "ab").unwrap();
    unlocked.root().set("long", "abc").unwrap();
    assert_eq!(client.redact("ab").unwrap(), "[scotoma:short]");
    assert!(matches!(client.check("ab"), Err(Error::Leak(name)) if name == "short"));
}

#[test]
fn the_resident_process_runs_the_command_and_hands_back_the_placeholder() {
    let unlocked = Unlocked::new("y\n");
    unlocked.root().set("pw", "hunter2").unwrap();
    unlocked.root().set("other", "swordfish").unwrap();
    let client = unlocked.granted(&[]);
    let handle = "[scotoma:pw]".to_owned();
    let script = "test \"$1\" = hunter2 && echo \"out $1\" && echo \"err $1 swordfish\" >&2";
    let ran = run(&client, &["sh", "-c", script, "sh", &handle]).unwrap();
    assert_eq!(
        ran,
        (
            0,
            format!("out {handle}\n"),
            format!("err {handle} [scotoma:other]\n")
        )
    );
    // Stdout and stderr are relayed side by side: their order is not fixed.
    let mut acts = unlocked.log().split_off(2);
    acts.sort();
    assert_eq!(acts, ["redact other", "redact pw", "redact pw", "use pw"]);
}

#[test]
fn a_command_runs_where_its_caller_stands_and_exits_as_itself() {
    let unlocked = Unlocked::new("y\n");
    let client = unlocked.granted(&[]);
    let here = std::env::current_dir().unwrap();
    let path = std::env::var("PATH").unwrap();
    let ran = run(&client, &["sh", "-c", "pwd; echo \"$PATH\""]).unwrap();
    assert_eq!(ran.1, format!("{}\n{path}\n", here.display()));
    assert_eq!(run(&client, &["sh", "-c", "exit 7"]).unwrap().0, 7);
    assert_eq!(run(&client, &["sh", "-c", "kill -9 $$"]).unwrap().0, 1);
    let missing = run(&client, &["/nonexistent/program"])
        .unwrap_err()
        .to_string();
    assert!(missing.contains("/nonexistent/program"), "{missing}");
}

#[test]
fn output_is_withheld_when_its_redaction_cannot_be_logged() {
    let unlocked = Unlocked::new("y\n");
    unlocked.root().set("pw", "hunter2").unwrap();
    let client = unlocked.granted(&[]);
    let log = unlocked.scratch.path.join("audit.tsv");
    let script = format!("rm {0} && mkdir {0} && echo hunter2", log.display());
    assert!(matches!(
        run(&client, &["sh", "-c", &script]),
        Err(Error::Io { .. })
    ));
    fs::remove_dir(&log).unwrap();
    assert!(matches!(run(&client, &["true"]), Ok((0, _, _))));
}

#[test]
fn a_caller_that_stops_listening_stops_the_command() {
    let unlocked = Unlocked::new("y\n");
    let client = unlocked.granted(&[]);
    let cwd = std::env::current_dir().unwrap();
    let args: [&[u8]; 3] = [cwd.as_os_str().as_bytes(), b"", b"yes"];
    drop(client.begin("run", &args).unwrap());
    let (mut out, mut err) = (Broken, Vec::new());
    let deaf = client.run(&["echo", "hi"], crate::testing::none(), &mut out, &mut err);
    assert!(matches!(deaf, Err(Error::Io { context, .. }) if context == "\"output\""));
    let deaf = client.run(
        &["sh", "-c", "echo hi >&2"],
        crate::testing::none(),
        &mut err,
        &mut out,
    );
    assert!(matches!(deaf, Err(Error::Io { .. })));
    // The resident process only ends once `yes` has: this returning is the test.
    unlocked.end().unwrap();
}

#[test]
fn a_resident_process_that_hangs_up_is_an_error() {
    let (_scratch, client) = impostor(None);
    assert!(matches!(client.names(), Err(Error::Io { .. })));
    let (_scratch, client) = impostor(None);
    assert!(matches!(run(&client, &["true"]), Err(Error::Io { .. })));
    let (_scratch, client) = impostor(Some(b""));
    assert!(matches!(client.redact("text"), Err(Error::Io { .. })));
}

#[test]
fn a_vault_that_cannot_be_read_fails_every_operation() {
    let unlocked = Unlocked::new("y\n");
    let client = unlocked.granted(&[]);
    let secrets = unlocked.scratch.path.join("secrets");
    fs::write(&secrets, "not a directory").unwrap();
    assert!(matches!(client.substitute("x"), Err(Error::Io { .. })));
    assert!(matches!(client.redact("x"), Err(Error::Io { .. })));
    assert!(matches!(client.check("x"), Err(Error::Io { .. })));
    assert!(matches!(run(&client, &["true"]), Err(Error::Io { .. })));
}

#[test]
fn the_callers_input_is_the_commands_input() {
    let unlocked = Unlocked::new("");
    let client = unlocked.granted(&[]);
    client.set("pw", "hunter2").unwrap();
    let typed = std::io::Cursor::new(b"it is hunter2\n".to_vec());
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = client.run(&["cat"], Box::new(typed), &mut out, &mut err);
    assert!(matches!(code, Ok(0)));
    assert_eq!(out, b"it is [scotoma:pw]\n");
    // Input nobody reads harms nothing.
    let ignored = std::io::Cursor::new(vec![b'x'; 1 << 17]);
    let code = client.run(&["true"], Box::new(ignored), &mut out, &mut err);
    assert!(matches!(code, Ok(0)));
}

#[test]
fn a_caller_that_goes_away_takes_the_command_and_its_children_with_it() {
    let unlocked = Unlocked::new("");
    let client = unlocked.granted(&[]);
    let mark = unlocked.scratch.path.join("pids");
    let script = format!("sleep 60 & echo $$ $! > {}; wait", mark.display());
    let cwd = std::env::current_dir().unwrap();
    let path = wire::pack(&[b"PATH=/usr/bin:/bin"]);
    let args: [&[u8]; 5] = [
        cwd.as_os_str().as_bytes(),
        &path,
        b"sh",
        b"-c",
        script.as_bytes(),
    ];
    let conn = client.begin("run", &args).unwrap();
    let alive = |pid: &str| {
        let probe = std::process::Command::new("kill")
            .args(["-0", pid])
            .output();
        probe.unwrap().status.success()
    };
    let pids = loop {
        let written = std::fs::read_to_string(&mark).unwrap_or_default();
        if written.ends_with('\n') {
            break written;
        }
        std::thread::sleep(std::time::Duration::from_millis(2));
    };
    let pids: Vec<&str> = pids.split_whitespace().collect();
    assert!(pids.len() == 2 && pids.iter().all(|pid| alive(pid)));
    drop(conn);
    while pids.iter().any(|pid| alive(pid)) {
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
    assert!(matches!(run(&client, &["true"]), Ok((0, _, _))));
}
