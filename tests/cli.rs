//! The real binary, end to end: real processes, environment, pipes and socket.

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

#[test]
fn a_secret_reaches_the_command_and_never_the_reader() {
    let home = std::env::temp_dir().join(format!("scotoma-e2e-{}", std::process::id()));
    let scotoma = |grant: &str| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_scotoma"));
        command
            .env("SCOTOMA_HOME", &home)
            .env("SCOTOMA_ACTOR", "end-to-end");
        command
            .env("SCOTOMA_GRANT", grant)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped());
        command
    };
    let run = |grant: &str, args: &[&str], input: &str| {
        let mut child = scotoma(grant).args(args).spawn().unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        (
            output.status.code(),
            String::from_utf8_lossy(&output.stdout)
                .trim_end()
                .to_owned(),
        )
    };

    // The user's terminal: the password twice, then one approval.
    let mut resident = scotoma("")
        .arg("unlock")
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    resident
        .stdin
        .take()
        .unwrap()
        .write_all(b"pw\npw\ny\n")
        .unwrap();
    let mut terminal = BufReader::new(resident.stderr.take().unwrap()).lines();
    let ready = terminal.find(|line| line.as_ref().unwrap().contains("unlocked"));
    assert!(ready.is_some());

    assert_eq!(
        run("", &["set", "pw"], "hunter2\n"),
        (Some(0), String::new())
    );
    let handle = "[scotoma:pw]";
    assert_eq!(run("", &["run", "echo", handle], "").0, Some(1));
    let grant = run("", &["grant", "15m", "pw"], "").1;

    let script = "test \"$1\" = hunter2 && echo \"the password is $1\"";
    let ran = run(&grant, &["run", "sh", "-c", script, "sh", handle], "");
    assert_eq!(ran, (Some(0), format!("the password is {handle}")));
    assert_eq!(run("", &["guard"], "about to send hunter2").0, Some(1));

    let log = fs::read_to_string(home.join("audit.tsv")).unwrap();
    let events: Vec<&str> = log
        .lines()
        .map(|line| line.split('\t').nth(2).unwrap())
        .collect();
    assert_eq!(events, ["set", "grant", "use", "redact", "leak"]);
    assert!(
        log.lines()
            .all(|line| line.split('\t').nth(1) == Some("end-to-end"))
    );
    assert!(!log.contains("hunter2") && !log.contains(&grant));

    assert_eq!(run("", &["lock"], "").0, Some(0));
    assert_eq!(resident.wait().unwrap().code(), Some(0));
    assert_eq!(run("", &[], "").0, Some(2));
    fs::remove_dir_all(&home).unwrap();
}
