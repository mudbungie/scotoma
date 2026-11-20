//! Fake streams, and a vault unlocked on a thread.

use crate::cli::{self, Streams};
use std::fs;
use std::io::{self, BufRead, Cursor, Read, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

pub(super) static NEXT: AtomicU32 = AtomicU32::new(0);

#[derive(Debug, PartialEq)]
pub(super) struct Outcome {
    pub(super) code: u8,
    pub(super) out: String,
    pub(super) err: String,
}

/// A stream that fails every read, write and flush.
pub(super) struct Broken;

impl Read for Broken {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other("broken"))
    }
}

impl BufRead for Broken {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        Err(io::Error::other("broken"))
    }

    fn consume(&mut self, _: usize) {}
}

impl Write for Broken {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("broken"))
    }

    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::other("broken"))
    }
}

/// A buffer two threads can share: the unlock terminal, watched by the test.
#[derive(Clone, Default)]
pub(super) struct Shared(Arc<Mutex<Vec<u8>>>);

impl Shared {
    pub(super) fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

impl Write for Shared {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// One run with the caller's streams: the exit code and stderr.
pub(super) fn drive(
    env: &[(&str, &str)],
    args: &[&str],
    input: &mut (dyn BufRead + Send),
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

pub(super) fn run_with(env: &[(&str, &str)], args: &[&str], mut input: &[u8]) -> Outcome {
    let mut out = Vec::new();
    let (code, err) = drive(env, args, &mut input, &mut out);
    Outcome {
        code,
        out: String::from_utf8(out).unwrap(),
        err,
    }
}

pub(super) fn failed(outcome: &Outcome) -> bool {
    outcome.code == 1 && outcome.out.is_empty() && outcome.err.starts_with("scotoma: ")
}

/// A vault directory, and the `scotoma unlock` serving it on a thread.
pub(super) struct Home {
    pub(super) dir: String,
    pub(super) terminal: Shared,
    pub(super) grant: String,
    unlock: Option<JoinHandle<u8>>,
}

impl Home {
    /// A new vault unlocked with password `pw`; `answers` is what gets typed
    /// at the unlock terminal afterwards.
    pub(super) fn unlocked(answers: &str) -> Self {
        let unique = format!(
            "scotoma-cli-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        let dir = std::env::temp_dir()
            .join(unique)
            .to_string_lossy()
            .into_owned();
        let mut home = Self {
            dir,
            terminal: Shared::default(),
            grant: String::new(),
            unlock: None,
        };
        home.unlock(&format!("pw\npw\n{answers}"));
        home
    }

    pub(super) fn unlock(&mut self, typed: &str) {
        let (dir, mut terminal, typed) =
            (self.dir.clone(), self.terminal.clone(), typed.to_owned());
        let sessions = |terminal: &Shared| terminal.text().matches("unlocked").count();
        let before = sessions(&self.terminal);
        let unlock = thread::spawn(move || {
            let args = ["unlock".to_owned()];
            let env = |key: &str| (key == "SCOTOMA_HOME").then(|| dir.clone());
            let (mut input, mut out) = (Cursor::new(typed), Vec::new());
            cli::run(
                &args,
                &env,
                Streams {
                    input: &mut input,
                    out: &mut out,
                    err: &mut terminal,
                },
            )
        });
        while !unlock.is_finished() && sessions(&self.terminal) == before {
            thread::sleep(Duration::from_millis(2));
        }
        self.unlock = Some(unlock);
    }

    pub(super) fn env(&self) -> [(&str, &str); 2] {
        [("SCOTOMA_HOME", &self.dir), ("SCOTOMA_GRANT", &self.grant)]
    }

    pub(super) fn run(&self, args: &[&str], input: &[u8]) -> Outcome {
        run_with(&self.env(), args, input)
    }

    /// Lock, and return the exit code of `scotoma unlock`.
    pub(super) fn lock(&mut self) -> u8 {
        self.run(&["lock"], b"");
        self.unlock
            .take()
            .map_or(0, |unlock| unlock.join().unwrap())
    }

    pub(super) fn path(&self, file: &str) -> PathBuf {
        PathBuf::from(&self.dir).join(file)
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        self.lock();
        let _ = fs::remove_dir_all(&self.dir);
    }
}
