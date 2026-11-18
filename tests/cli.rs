//! The real binary, end to end: real arguments, environment and pipes.

use std::fs;
use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn a_secret_reaches_the_command_and_never_the_reader() {
    let home = std::env::temp_dir().join(format!("scotoma-e2e-{}", std::process::id()));
    let scotoma = |args: &[&str], input: &str| {
        let mut child = Command::new(env!("CARGO_BIN_EXE_scotoma"))
            .args(args)
            .env("SCOTOMA_HOME", &home)
            .env("SCOTOMA_ACTOR", "end-to-end")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        (
            output.status.code(),
            String::from_utf8_lossy(&output.stdout).into_owned(),
        )
    };

    assert_eq!(
        scotoma(&["set", "pw"], "hunter2\n"),
        (Some(0), String::new())
    );
    let handle = scotoma(&["issue", "pw"], "").1.trim_end().to_owned();

    let script = "test \"$1\" = hunter2 && echo \"the password is $1\"";
    let ran = scotoma(&["run", "sh", "-c", script, "sh", &handle], "");
    assert_eq!(ran, (Some(0), "the password is [scotoma:pw]\n".to_owned()));

    let log = fs::read_to_string(home.join("audit.tsv")).unwrap();
    let events: Vec<&str> = log
        .lines()
        .map(|line| line.split('\t').nth(2).unwrap())
        .collect();
    assert_eq!(events, ["set", "issue", "use", "redact"]);
    assert!(
        log.lines()
            .all(|line| line.split('\t').nth(1) == Some("end-to-end"))
    );

    assert_eq!(scotoma(&[], "").0, Some(2));
    fs::remove_dir_all(&home).unwrap();
}
