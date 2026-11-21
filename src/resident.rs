//! The resident process: the one place the vault key lives.
//!
//! `unlock` turns a password into the key, then serves the vault on a socket
//! until told to lock. The key is never written anywhere and is gone when
//! this returns. Its console is the user's side of authorization: a grant is
//! minted only when the person at the console says yes.

use crate::audit::{self, Act};
use crate::crypt;
use crate::grant::{self, Grant};
use crate::vault::{Flow, Vault};
use crate::{Error, admit, exec, store, wire};
use std::fs;
use std::io::{BufRead, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, PoisonError};
use std::thread;

const ENTROPY: &str = "/dev/urandom";
/// Where the resident process talks to the user.
pub struct Console<'a> {
    /// The password, then one line per grant request (`y` approves).
    pub input: &'a mut (dyn BufRead + Send),
    /// Prompts and requests.
    pub output: &'a mut (dyn Write + Send),
    /// Called with `false` before the password is read and `true` after, so
    /// a terminal can stop echoing.
    pub echo: fn(bool),
}

/// Unlock the vault at `home` and serve it until it is locked. A vault that
/// does not exist yet is created, with the password asked twice.
pub fn unlock(home: &Path, console: Console) -> Result<(), Error> {
    serve(home, console, Path::new(ENTROPY))
}

pub(crate) fn serve(home: &Path, mut console: Console, entropy: &Path) -> Result<(), Error> {
    let key = admit::admit(home, &mut console, entropy)?;
    let socket = home.join("socket");
    // A socket nobody answers is debris from a resident process that died.
    if UnixStream::connect(&socket).is_err() {
        let _ = fs::remove_file(&socket);
    }
    let listener = UnixListener::bind(&socket).map_err(Error::io(&socket))?;
    say(
        &mut console,
        "unlocked. Grant requests are asked here; `scotoma lock` ends this.\n",
    );
    let resident = Resident {
        vault: Vault::new(home, key, entropy),
        grants: Mutex::new(Vec::new()),
        console: Mutex::new(console),
        stop: AtomicBool::new(false),
        socket: socket.clone(),
    };
    let resident = &resident;
    thread::scope(|scope| {
        let calls = listener.incoming().map_while(Result::ok);
        for conn in calls.take_while(|_| !resident.stop.load(Ordering::SeqCst)) {
            scope.spawn(move || resident.converse(&conn));
        }
    });
    let _ = fs::remove_file(&socket);
    Ok(())
}

pub(crate) fn say(console: &mut Console, text: &str) {
    let _ = console.output.write_all(text.as_bytes());
    let _ = console.output.flush();
}

pub(crate) fn ask(console: &mut Console, prompt: &str) -> String {
    say(console, prompt);
    let mut line = String::new();
    let _ = console.input.read_line(&mut line);
    line.trim_end_matches(['\r', '\n']).to_owned()
}

struct Resident<'a> {
    vault: Vault,
    /// `(token, grant)`: memory only, gone at lock.
    grants: Mutex<Vec<(String, Grant)>>,
    console: Mutex<Console<'a>>,
    stop: AtomicBool,
    socket: PathBuf,
}

fn denied<T>(why: &str) -> Result<T, Error> {
    Err(Error::Denied(why.to_owned()))
}

impl Resident<'_> {
    /// One connection: one request, answered.
    fn converse(&self, conn: &UnixStream) {
        let request = wire::recv(conn)
            .ok()
            .and_then(|(_, body)| wire::unpack(&body));
        let Some(fields) = request else { return };
        let fields: Vec<&[u8]> = fields.iter().map(Vec::as_slice).collect();
        let (tag, body) = match self.dispatch(&fields, conn) {
            Ok(body) => (wire::OK, body),
            Err(error) => {
                let (tag, text) = wire::refusal(&error);
                (tag, text.into_bytes())
            }
        };
        let _ = wire::send(conn, tag, &body);
    }

    fn dispatch(&self, fields: &[&[u8]], conn: &UnixStream) -> Result<Vec<u8>, Error> {
        let text = |bytes: &&[u8]| String::from_utf8_lossy(bytes).into_owned();
        let [actor, token, op, args @ ..] = fields else {
            return denied("malformed request");
        };
        let vault = self.vault.acting(&text(actor))?;
        let (token, words) = (text(token), args.iter().map(text).collect::<Vec<_>>());
        let words: Vec<&str> = words.iter().map(String::as_str).collect();
        let done = |()| Vec::new();
        match (*op, words.as_slice()) {
            (b"set", [name, value]) => vault.set(name, value).map(done),
            (b"rm", [name]) => vault.remove(name).map(done),
            (b"ls", []) => vault
                .store
                .names()
                .map(|names| names.join("\n").into_bytes()),
            (b"grant", [limits, names @ ..]) => self.approve(&vault, &token, limits, names),
            (b"lock", []) => {
                self.stop.store(true, Ordering::SeqCst);
                // Wake the accept loop so it sees the flag, then take the
                // socket's name away: by the time the caller hears back, the
                // vault is locked to everyone.
                drop(UnixStream::connect(&self.socket));
                let _ = fs::remove_file(&self.socket);
                Ok(Vec::new())
            }
            (b"sub", []) => match self.grant(&token)? {
                grant if grant.reveals() => stream(conn, vault.substituter(grant)?),
                _ => denied("this grant only runs commands: use `scotoma run`"),
            },
            (b"redact", []) => stream(conn, vault.redactor()?),
            (b"guard", []) => stream(conn, vault.guard()?),
            (b"run", [_, _, command @ ..]) if !command.is_empty() => {
                let (cwd, env) = (args.first().copied(), args.get(1).copied());
                let place = exec::Place {
                    cwd: cwd.unwrap_or_default(),
                    env: env.unwrap_or_default(),
                };
                exec::run(&vault, self.grant(&token)?, command, &place, conn)
            }
            _ => denied("unknown request"),
        }
    }

    /// The live grant a token stands for.
    fn grant(&self, token: &str) -> Result<Grant, Error> {
        let grants = self.grants.lock().unwrap_or_else(PoisonError::into_inner);
        match grants.iter().find(|(held, _)| held == token) {
            Some((_, grant)) if grant.live() => Ok(grant.clone()),
            Some(_) => denied("the grant has expired or is used up"),
            None => denied("no grant: ask for one with `scotoma grant`"),
        }
    }

    /// Mint a grant and return its token. Whoever presents a grant is
    /// answered by it: the new grant is bound by that one. Whoever presents
    /// none is answered by the person at the console.
    fn approve(
        &self,
        vault: &Vault,
        token: &str,
        terms: &str,
        names: &[&str],
    ) -> Result<Vec<u8>, Error> {
        let Some(limits) = grant::limits(terms) else {
            return denied(
                "not a limit: join a duration (30s, 15m, 1h, 2d), a count of uses (3x) \
                 and `run` with commas",
            );
        };
        for name in names {
            store::check(name)?;
        }
        let scope = if names.is_empty() {
            vec!["*"]
        } else {
            names.to_vec()
        };
        let parent = if token.is_empty() {
            self.consent(&vault.audit.actor, &scope.join(", "), terms)?;
            None
        } else {
            Some(self.grant(token)?)
        };
        let (id, token) = crypt::random::<32>(&vault.entropy).map(|bytes| {
            let (id, token) = bytes.split_at(16);
            let uuid = |half: &[u8]| audit::uuid(<[u8; 16]>::try_from(half).unwrap_or_default());
            (uuid(id), uuid(token))
        })?;
        let from = parent.as_ref().map_or("-", |parent| parent.id.as_str());
        for secret in scope {
            vault.audit.record(Act {
                event: "grant",
                secret,
                grant: &id,
                note: from,
            })?;
        }
        let names = names.iter().map(|&name| name.to_owned()).collect();
        let grant = Grant::mint(id, names, &limits, parent);
        let mut grants = self.grants.lock().unwrap_or_else(PoisonError::into_inner);
        grants.push((token.clone(), grant));
        Ok(token.into_bytes())
    }

    /// Ask the person at the console; only `y` is yes.
    fn consent(&self, actor: &str, what: &str, terms: &str) -> Result<(), Error> {
        let limits = grant::describe(terms);
        let question = format!("grant requested by {actor}: {what} for {limits}\napprove? [y/N] ");
        let mut console = self.console.lock().unwrap_or_else(PoisonError::into_inner);
        let answer = ask(&mut console, &question);
        drop(console);
        if answer == "y" {
            Ok(())
        } else {
            denied("refused at the console")
        }
    }
}

/// A stream operation: acknowledge, then one reply per chunk until the end.
fn stream(conn: &UnixStream, mut flow: Flow) -> Result<Vec<u8>, Error> {
    let _ = wire::send(conn, wire::OK, b"");
    loop {
        let (tag, chunk) = wire::recv(conn).map_err(Error::io("socket"))?;
        let (bytes, _) = flow.feed(&chunk, tag == wire::END)?;
        if tag == wire::END {
            return Ok(bytes);
        }
        let _ = wire::send(conn, wire::OK, &bytes);
    }
}

#[cfg(test)]
#[path = "resident_tests.rs"]
mod tests;
