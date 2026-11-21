use super::*;
use crate::testing::{Scratch, Unlocked};
use std::os::unix::fs::PermissionsExt;

const SYSTEM: &str = "/dev/urandom";

/// Unlock `scratch` with `typed` on the console and report how it ended.
fn attempt(scratch: Scratch, typed: &str) -> (Scratch, Result<(), Error>) {
    let mut unlocked = Unlocked::start(scratch, typed, Path::new(SYSTEM));
    let ended = unlocked.stop().unwrap();
    (unlocked.into_scratch(), ended)
}

/// Send raw fields as a request and return the reply.
fn raw(unlocked: &Unlocked, fields: &[&[u8]]) -> Result<Vec<u8>, Error> {
    let conn = UnixStream::connect(unlocked.scratch.path.join("socket")).unwrap();
    wire::send(&conn, wire::ASK, &wire::pack(fields)).unwrap();
    let (tag, body) = wire::recv(&conn).unwrap();
    wire::outcome(tag, body)
}

#[test]
fn a_vault_is_founded_once_and_reopens_only_with_its_password() {
    let (scratch, founded) = attempt(Scratch::new(), "correct\ncorrect\n");
    founded.unwrap();
    let key = scratch.path.join("key");
    assert_eq!(
        fs::metadata(&key).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(fs::read(&key).unwrap().len(), 16 + 24 + 32 + 16);
    assert!(!scratch.path.join("socket").exists());

    let (scratch, wrong) = attempt(scratch, "incorrect\n");
    assert!(matches!(wrong, Err(Error::Password)));
    let (scratch, right) = attempt(scratch, "correct\n");
    right.unwrap();

    fs::write(&key, b"short").unwrap();
    assert!(matches!(
        attempt(scratch, "correct\n").1,
        Err(Error::Password)
    ));
}

#[test]
fn a_password_must_be_typed_twice_alike_and_not_empty() {
    let (scratch, mistyped) = attempt(Scratch::new(), "one\ntwo\n");
    assert!(matches!(mistyped, Err(Error::Password)));
    assert!(matches!(attempt(scratch, "").1, Err(Error::Password)));
}

#[test]
fn secrets_outlive_the_resident_process() {
    let unlocked = Unlocked::new("");
    unlocked.root().set("pw", "hunter2").unwrap();
    unlocked.client().lock().unwrap();
    assert!(matches!(unlocked.client().names(), Err(Error::Locked)));
    let scratch = unlocked.into_scratch();
    let again = Unlocked::start(scratch, "pw\n", Path::new(SYSTEM));
    assert_eq!(again.client().redact("hunter2").unwrap(), "[scotoma:pw]");
    assert!(
        again
            .console
            .text()
            .starts_with("password: \napprover token: ")
    );
}

#[test]
fn founding_needs_a_writable_home_and_entropy() {
    let scratch = Scratch::new();
    fs::create_dir(scratch.path.join("key")).unwrap();
    assert!(matches!(
        attempt(scratch, "pw\npw\n").1,
        Err(Error::Io { .. })
    ));

    let scratch = Scratch::new();
    std::os::unix::fs::symlink("/nonexistent/key", scratch.path.join("key")).unwrap();
    assert!(matches!(
        attempt(scratch, "pw\npw\n").1,
        Err(Error::Io { .. })
    ));

    let scratch = Scratch::new();
    let starved = scratch.path.join("no-entropy");
    let mut unlocked = Unlocked::start(scratch, "pw\npw\n", &starved);
    assert!(matches!(unlocked.stop().unwrap(), Err(Error::Io { .. })));

    // An existing vault opens without entropy, but cannot mint its approver token.
    let (scratch, founded) = attempt(Scratch::new(), "pw\npw\n");
    founded.unwrap();
    let starved = scratch.path.join("no-entropy");
    let mut unlocked = Unlocked::start(scratch, "pw\n", &starved);
    assert!(matches!(unlocked.stop().unwrap(), Err(Error::Io { .. })));
}

#[test]
fn one_resident_process_per_vault_and_a_dead_ones_socket_is_cleared() {
    let unlocked = Unlocked::new("");
    let second = serve_once(&unlocked.scratch.path, "pw\n");
    assert!(matches!(second, Err(Error::Io { .. })));
    unlocked.client().names().unwrap();

    let scratch = Scratch::new();
    drop(UnixListener::bind(scratch.path.join("socket")).unwrap());
    let revived = Unlocked::start(scratch, "pw\npw\n", Path::new(SYSTEM));
    revived.client().names().unwrap();
    revived.end().unwrap();
}

fn serve_once(home: &Path, typed: &str) -> Result<(), Error> {
    let console = Console {
        input: Box::new(std::io::Cursor::new(typed.to_owned())),
        output: Box::new(Vec::new()),
        echo: |_| (),
    };
    unlock(home, console)
}

#[test]
fn a_request_that_is_not_one_is_refused() {
    let unlocked = Unlocked::new("");
    let refused = |fields: &[&[u8]]| raw(&unlocked, fields).unwrap_err().to_string();
    assert_eq!(refused(&[b"tester", b""]), "denied: malformed request");
    assert_eq!(
        refused(&[b"tester", b"", b"dance"]),
        "denied: unknown request"
    );
    assert_eq!(
        refused(&[b"tester", b"", b"run", b"/", b""]),
        "denied: unknown request"
    );
    assert!(refused(&[b"two words", b"", b"ls"]).starts_with("invalid name"));

    // Not even a field list: the connection is simply closed.
    let conn = UnixStream::connect(unlocked.scratch.path.join("socket")).unwrap();
    wire::send(&conn, wire::ASK, b"\0\0\0\0\x09short").unwrap();
    assert!(wire::recv(&conn).is_err());
    assert_eq!(raw(&unlocked, &[b"tester", b"", b"ls"]).unwrap(), b"");
}

#[test]
fn a_caller_that_walks_away_mid_stream_harms_nothing() {
    let unlocked = Unlocked::new("");
    let client = unlocked.client();
    unlocked.root().set("pw", "hunter2").unwrap();
    drop(client.redactor().unwrap());
    let mut stream = client.redactor().unwrap();
    assert_eq!(
        stream.push(b"hunter2 and hun").unwrap(),
        b"[scotoma:pw] and "
    );
    drop(stream);
    assert_eq!(client.redact("hunter2").unwrap(), "[scotoma:pw]");
    unlocked.end().unwrap();
}
