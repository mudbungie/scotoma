//! Running a command inside the resident process: the secret goes into the
//! child's arguments and nowhere else, and never crosses the socket. The
//! caller's input is the command's input, and a caller that goes away takes
//! the command with it.

use crate::grant::Grant;
use crate::vault::{Flow, Vault};
use crate::{Error, wire};
use std::ffi::OsStr;
use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::process::{ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, PoisonError};
use std::thread;

/// Where the caller stands: the command runs there, not where the resident
/// process happens to be.
pub(crate) struct Place<'a> {
    pub cwd: &'a [u8],
    /// A packed list of `NAME=value`.
    pub env: &'a [u8],
}

/// Run `command` with its placeholders substituted, relaying its redacted stdout
/// and stderr to `conn` as they flow. Returns the exit code as one byte.
pub(crate) fn run(
    vault: &Vault,
    grant: Grant,
    command: &[&str],
    place: &Place,
    conn: &UnixStream,
) -> Result<Vec<u8>, Error> {
    let words: Vec<String> = command.iter().map(|&word| word.to_owned()).collect();
    let (words, flow) = vault.arm(&words, grant)?;
    // Named as the caller wrote it: an error must not echo a substituted secret.
    let name = command.first().copied().unwrap_or_default();
    let vars = wire::unpack(place.env).unwrap_or_default();
    let vars = vars.iter().map(|var| {
        let mut halves = var.splitn(2, |&byte| byte == b'=');
        let half = |bytes: Option<&[u8]>| OsStr::from_bytes(bytes.unwrap_or_default()).to_owned();
        (half(halves.next()), half(halves.next()))
    });
    let mut words = words.into_iter();
    let mut child = Command::new(words.next().unwrap_or_default())
        .args(words)
        .env_clear()
        .envs(vars)
        .current_dir(OsStr::from_bytes(place.cwd))
        // Its own group, so that it can be stopped with everything it started.
        .process_group(0)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(Error::io(name))?;
    let (stdin, stdout, stderr) = (child.stdin.take(), child.stdout.take(), child.stderr.take());
    let (mut out_flow, mut err_flow) = (flow.clone(), flow);
    let (mut relayed_out, mut relayed_err) = (Ok(()), Ok(()));
    let (line, group, over) = (Mutex::new(conn), child.id(), AtomicBool::new(false));
    let mut status = Ok(None);
    thread::scope(|scope| {
        scope.spawn(|| feed(conn, stdin, group, &over));
        thread::scope(|relays| {
            relays.spawn(|| {
                relayed_err =
                    stderr.map_or(Ok(()), |pipe| relay(pipe, &mut err_flow, wire::ERR, &line));
            });
            relayed_out =
                stdout.map_or(Ok(()), |pipe| relay(pipe, &mut out_flow, wire::OUT, &line));
        });
        status = child.wait().map(Some).map_err(Error::io(name));
        // The command is over: nothing is left to stop, and the caller has
        // nothing more to say that anyone will read.
        over.store(true, Ordering::SeqCst);
        let _ = conn.shutdown(Shutdown::Read);
    });
    let code = |status: std::process::ExitStatus| status.code();
    let byte = |status: Option<_>| {
        status
            .and_then(code)
            .and_then(|code| u8::try_from(code).ok())
    };
    relayed_out
        .and(relayed_err)
        .and(status)
        .map(|status| vec![byte(status).unwrap_or(1)])
}

/// The caller's side of the conversation while the command runs: its input
/// is the command's, the end of its input is the end of the command's, and
/// if it goes away the command and everything it started are killed.
fn feed(conn: &UnixStream, mut stdin: Option<ChildStdin>, group: u32, over: &AtomicBool) {
    loop {
        match wire::recv(conn) {
            Ok((wire::IN, bytes)) => {
                let _ = stdin.as_mut().map(|pipe| pipe.write_all(&bytes));
            }
            Ok(_) => stdin = None,
            Err(_) => {
                if !over.load(Ordering::SeqCst) {
                    // The process group, by its negative id: no dependency
                    // and no `unsafe` reaches killpg otherwise.
                    let group = format!("-{group}");
                    let _ = Command::new("kill").args(["-KILL", &group]).status();
                }
                return;
            }
        }
    }
}

/// Copy one of the child's pipes to the caller, redacted. Returning early
/// drops the pipe, which stops a child that is still writing.
fn relay(
    mut pipe: impl Read,
    flow: &mut Flow,
    tag: u8,
    line: &Mutex<&UnixStream>,
) -> Result<(), Error> {
    let mut buffer = vec![0; 1 << 16];
    loop {
        let read = pipe.read(&mut buffer).unwrap_or(0);
        let chunk = buffer.get(..read).unwrap_or_default();
        let (bytes, _) = flow.feed(chunk, chunk.is_empty())?;
        let conn = line.lock().unwrap_or_else(PoisonError::into_inner);
        wire::send(*conn, tag, &bytes).map_err(Error::io("socket"))?;
        drop(conn);
        if chunk.is_empty() {
            return Ok(());
        }
    }
}
