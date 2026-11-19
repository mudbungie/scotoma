//! The command line driven in-process, with fake streams and environment.

use crate::cli::{self, Streams, USAGE};
use std::fs;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

static NEXT: AtomicU32 = AtomicU32::new(0);

/// A vault directory that removes itself.
struct Home(PathBuf);

impl Home {
    fn new() -> Self {
        let unique = format!(
            "scotoma-cli-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        let path = std::env::temp_dir().join(unique);
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    /// Run a command line against this vault.
    fn run(&self, args: &[&str], input: &[u8]) -> Outcome {
        let home = self.0.to_string_lossy().into_owned();
        run_with(&[("SCOTOMA_HOME", &home)], args, input)
    }

    fn secret(&self, name: &str, value: &str) {
        assert_eq!(self.run(&["set", name], value.as_bytes()).code, 0);
    }

    fn handle(&self, name: &str) -> String {
        self.run(&["issue", name], b"").out.trim_end().to_owned()
    }

    fn break_log(&self) {
        let _ = fs::remove_file(self.0.join("audit.tsv"));
        fs::create_dir(self.0.join("audit.tsv")).unwrap();
    }

    fn break_store(&self) {
        let _ = fs::remove_dir_all(self.0.join("secrets"));
        fs::write(self.0.join("secrets"), "not a directory").unwrap();
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[derive(Debug, PartialEq)]
struct Outcome {
    code: u8,
    out: String,
    err: String,
}

fn run_with(env: &[(&str, &str)], args: &[&str], mut input: &[u8]) -> Outcome {
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = drive(env, args, &mut input, &mut out);
    let text = |bytes: Vec<u8>| String::from_utf8(bytes).unwrap();
    Outcome {
        code: code.0,
        out: text(out),
        err: text(std::mem::take(&mut err)) + &code.1,
    }
}

/// The exit code and stderr of one run, with the caller's stdin and stdout.
fn drive(
    env: &[(&str, &str)],
    args: &[&str],
    input: &mut dyn Read,
    out: &mut (dyn Write + Send),
) -> (u8, String) {
    let args: Vec<String> = args.iter().map(|&arg| arg.to_owned()).collect();
    let env = |key: &str| {
        env.iter()
            .find(|(name, _)| *name == key)
            .map(|(_, value)| (*value).to_owned())
    };
    let mut err = Vec::new();
    let code = cli::run(
        &args,
        &env,
        Streams {
            input,
            out,
            err: &mut err,
        },
    );
    (code, String::from_utf8(err).unwrap())
}

/// A stream that fails every read, write and flush.
struct Broken;

impl Read for Broken {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other("broken"))
    }
}

impl Write for Broken {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("broken"))
    }

    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::other("broken"))
    }
}

fn failed(outcome: &Outcome) -> bool {
    outcome.code == 1 && outcome.out.is_empty() && outcome.err.starts_with("scotoma: ")
}

#[test]
fn anything_that_is_not_a_command_prints_usage() {
    let home = Home::new();
    for args in [&[][..], &["bogus"], &["set"], &["ls", "extra"], &["run"]] {
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
    let data = Home::new();
    let dir = data.0.to_string_lossy().into_owned();
    assert_eq!(
        run_with(&[("XDG_DATA_HOME", &dir)], &["set", "a"], b"1").code,
        0
    );
    assert!(data.0.join("scotoma/secrets/a").exists());
    assert_eq!(run_with(&[("HOME", &dir)], &["set", "b"], b"2").code, 0);
    assert!(data.0.join(".local/share/scotoma/secrets/b").exists());
}

#[test]
fn the_actor_is_named_by_the_environment() {
    let home = Home::new();
    let dir = home.0.to_string_lossy().into_owned();
    let vault = ("SCOTOMA_HOME", dir.as_str());
    run_with(&[vault], &["set", "a"], b"1");
    run_with(&[vault, ("USER", "someone")], &["set", "a"], b"1");
    run_with(
        &[vault, ("USER", "someone"), ("SCOTOMA_ACTOR", "agent-7")],
        &["set", "a"],
        b"1",
    );
    let log = fs::read_to_string(home.0.join("audit.tsv")).unwrap();
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
fn a_secret_goes_in_by_stdin_and_comes_out_only_through_a_handle() {
    let home = Home::new();
    assert_eq!(
        home.run(&["set", "pw"], b"hunter2\n"),
        Outcome {
            code: 0,
            out: String::new(),
            err: String::new()
        }
    );
    assert_eq!(home.run(&["ls"], b"").out, "pw\n");
    let handle = home.handle("pw");
    assert_eq!(handle.len(), 36);
    let command = format!("curl -u admin:{handle}");
    assert_eq!(
        home.run(&["sub"], command.as_bytes()).out,
        "curl -u admin:hunter2"
    );
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
    assert_eq!(home.run(&["rm", "pw"], b"").code, 0);
    assert_eq!(home.run(&["ls"], b"").out, "");
}

#[test]
fn run_substitutes_arguments_and_redacts_both_streams() {
    let home = Home::new();
    home.secret("pw", "hunter2");
    let handle = home.handle("pw");
    let script = "test \"$1\" = hunter2 && echo \"out $1\" && echo \"err $1\" >&2";
    let outcome = home.run(&["run", "sh", "-c", script, "sh", &handle], b"");
    let expected = Outcome {
        code: 0,
        out: "out [scotoma:pw]\n".into(),
        err: "err [scotoma:pw]\n".into(),
    };
    assert_eq!(outcome, expected);
}

#[test]
fn run_exits_as_the_command_did() {
    let home = Home::new();
    assert_eq!(home.run(&["run", "sh", "-c", "exit 7"], b"").code, 7);
    assert_eq!(home.run(&["run", "sh", "-c", "kill -9 $$"], b"").code, 1);
    let missing = home.run(&["run", "/nonexistent/program"], b"");
    assert!(
        failed(&missing) && missing.err.contains("/nonexistent/program"),
        "{missing:?}"
    );
}

#[test]
fn failures_exit_1_and_say_why() {
    let home = Home::new();
    assert!(failed(&home.run(&["rm", "absent"], b"")));
    assert!(failed(&home.run(&["issue", "absent"], b"")));
    assert!(failed(&home.run(&["set", "pw"], b"\xff")));
    assert!(failed(&home.run(&["set", "pw"], b"")));
    home.secret("pw", "hunter2");
    home.break_log();
    assert!(failed(&home.run(&["sub"], b"x")));
    assert!(failed(&home.run(&["redact"], b"hunter2")));
    assert!(failed(&home.run(&["run", "true"], b"")));
    home.break_store();
    assert!(failed(&home.run(&["ls"], b"")));
    assert!(failed(&home.run(&["redact"], b"x")));
    assert!(failed(&home.run(&["guard"], b"x")));
    assert!(failed(&home.run(&["run", "true"], b"")));
}

#[test]
fn a_match_decided_only_at_the_end_still_needs_the_log() {
    let home = Home::new();
    home.secret("short", "ab");
    home.secret("long", "abc");
    assert_eq!(home.run(&["redact"], b"ab").out, "[scotoma:short]");
    home.break_log();
    assert!(failed(&home.run(&["redact"], b"ab")));
}

#[test]
fn broken_streams_are_failures() {
    let home = Home::new();
    home.secret("pw", "hunter2");
    let dir = home.0.to_string_lossy().into_owned();
    let env = [("SCOTOMA_HOME", dir.as_str())];
    let cases: [&[&str]; 5] = [
        &["ls"],
        &["issue", "pw"],
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
