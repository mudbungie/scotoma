//! Test support: a scratch directory, and a vault unlocked on a thread.

use crate::resident::{Console, serve};
use crate::{Error, Scotoma};
use std::fs;
use std::io::{self, Cursor, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

static NEXT: AtomicU32 = AtomicU32::new(0);

/// A directory that removes itself.
pub(crate) struct Scratch {
    pub path: PathBuf,
}

impl Scratch {
    pub fn new() -> Self {
        let unique = format!(
            "scotoma-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        let path = std::env::temp_dir().join(unique);
        fs::create_dir_all(&path).unwrap();
        Self { path }
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// Everything the resident process wrote to its console.
#[derive(Clone, Default)]
pub(crate) struct Shared(Arc<Mutex<Vec<u8>>>);

impl Shared {
    pub fn text(&self) -> String {
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

/// A resident process on a thread, locked again when dropped.
pub(crate) struct Unlocked {
    pub scratch: Scratch,
    pub console: Shared,
    thread: Option<JoinHandle<Result<(), Error>>>,
}

impl Unlocked {
    /// A new vault, password `pw`. `answers` is what the person at the
    /// console will type, one line per grant request.
    pub fn new(answers: &str) -> Self {
        Self::start(
            Scratch::new(),
            &format!("pw\npw\n{answers}"),
            Path::new("/dev/urandom"),
        )
    }

    /// Run the resident process over `scratch` with `typed` as the whole
    /// console input, and wait until it serves or gives up.
    pub fn start(scratch: Scratch, typed: &str, entropy: &Path) -> Self {
        let (home, entropy, console) =
            (scratch.path.clone(), entropy.to_owned(), Shared::default());
        let (mut input, mut output) = (Cursor::new(typed.to_owned()), console.clone());
        let thread = thread::spawn(move || {
            let console = Console {
                input: &mut input,
                output: &mut output,
                echo: |_| (),
            };
            serve(&home, console, &entropy)
        });
        while !thread.is_finished() && !console.text().contains("unlocked") {
            thread::sleep(Duration::from_millis(2));
        }
        Self {
            scratch,
            console,
            thread: Some(thread),
        }
    }

    pub fn client(&self) -> Scotoma {
        Scotoma::open(&self.scratch.path, "tester").unwrap()
    }

    /// A client holding a one-hour grant over `names` (none means all). The
    /// console must have a `y` waiting.
    pub fn granted(&self, names: &[&str]) -> Scotoma {
        let client = self.client();
        let token = client.grant("1h", names).unwrap();
        client.with_grant(&token)
    }

    /// The log as `event secret` pairs.
    pub fn log(&self) -> Vec<String> {
        let text = fs::read_to_string(self.scratch.path.join("audit.tsv")).unwrap();
        let pair = |line: &str| {
            line.split('\t')
                .skip(2)
                .take(2)
                .collect::<Vec<_>>()
                .join(" ")
        };
        text.lines().map(pair).collect()
    }

    /// Lock, and return how the resident process ended.
    pub fn end(mut self) -> Result<(), Error> {
        self.stop().unwrap()
    }

    /// The vault's directory, to unlock again.
    pub fn into_scratch(mut self) -> Scratch {
        self.stop();
        let empty = Scratch {
            path: PathBuf::new(),
        };
        std::mem::replace(&mut self.scratch, empty)
    }

    pub fn stop(&mut self) -> Option<Result<(), Error>> {
        let thread = self.thread.take()?;
        let _ = UnixStream::connect(self.scratch.path.join("socket")).map(|_| self.client().lock());
        Some(thread.join().unwrap())
    }
}

impl Drop for Unlocked {
    fn drop(&mut self) {
        self.stop();
    }
}
