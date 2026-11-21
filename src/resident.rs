//! The resident process: the one place the vault key lives.
//!
//! `unlock` turns a password into the key, then serves the vault on a socket
//! until told to lock. The key is never written anywhere and is gone when
//! this returns. Who may use what is decided at the desk (`desk.rs`).

use crate::audit::{self, Act};
use crate::desk::{Desk, ROOT, Request, Verdict};
use crate::grant::{self, Grant};
use crate::vault::{Flow, Vault};
use crate::{Error, admit, crypt, exec, store, wire};
use std::fs;
use std::io::{BufRead, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

const ENTROPY: &str = "/dev/urandom";

/// Where the resident process talks to the user.
pub struct Console {
    /// The password, then one line per grant request (`y` approves).
    pub input: Box<dyn BufRead + Send>,
    /// Prompts, the approver token, and requests.
    pub output: Box<dyn Write + Send>,
    /// Called with `false` before the password is read and `true` after, so
    /// a terminal can stop echoing.
    pub echo: fn(bool),
}

/// Unlock the vault at `home` and serve it until it is locked. A vault that
/// does not exist yet is created, with the password asked twice.
///
/// Once unlocked, the console is shown the approver token: the grant every
/// other grant descends from. Whoever presents it ([`crate::Scotoma::with_grant`])
/// may store and remove secrets, answer grant requests and end grants.
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
    let token = crypt::random(entropy).map(audit::uuid)?;
    let listener = UnixListener::bind(&socket).map_err(Error::io(&socket))?;
    let desk = Arc::new(Desk::new(console.output, token.clone()));
    desk.say(&format!(
        "approver token: {token}\n\
         unlocked. Grant requests are asked here; `scotoma lock` ends this.\n"
    ));
    let (seat, input) = (Arc::clone(&desk), console.input);
    // Detached: a console that is never typed at must not hold up locking.
    thread::spawn(move || seat.listen(input));
    let resident = Resident {
        vault: Vault::new(home, key, entropy),
        desk,
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

struct Resident {
    vault: Vault,
    desk: Arc<Desk>,
    stop: AtomicBool,
    socket: PathBuf,
}

fn denied<T>(why: &str) -> Result<T, Error> {
    Err(Error::Denied(why.to_owned()))
}

/// The approver's grant, or nothing.
fn root(held: Result<Grant, Error>) -> Result<Grant, Error> {
    match held? {
        grant if grant.id == ROOT => Ok(grant),
        _ => denied("only the approver may do that: present the approver token"),
    }
}

impl Resident {
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
        let (claimed, token) = (text(actor), text(token));
        store::check(&claimed)?;
        let held = self.desk.grant(&token);
        // A grant fixes who its holder is; without one, the caller's word stands.
        let fixed = held.as_ref().ok().map(|grant| grant.actor.as_str());
        let name = fixed.filter(|fixed| !fixed.is_empty());
        let vault = self.vault.acting(name.unwrap_or(&claimed));
        let words: Vec<String> = args.iter().map(text).collect();
        let words: Vec<&str> = words.iter().map(String::as_str).collect();
        let done = |()| Vec::new();
        match (*op, words.as_slice()) {
            (b"set", [name, value]) => vault.set(name, value, &held?).map(done),
            (b"rm", [name]) => vault.remove(name, &held?).map(done),
            (b"ls", []) => vault
                .store
                .names()
                .map(|names| names.join("\n").into_bytes()),
            (b"grant", [limits, reason, names @ ..]) => {
                let parent = if token.is_empty() { None } else { Some(held?) };
                let asked = Request {
                    id: String::new(),
                    actor: claimed,
                    names: names.iter().map(|&name| name.to_owned()).collect(),
                    limits: (*limits).to_owned(),
                    reason: reason.replace(char::is_control, " ").trim().to_owned(),
                };
                self.request(&vault, asked, parent, conn)
            }
            (b"pending", []) => root(held).map(|_| {
                let lines = self.desk.pending().into_iter().map(|asked| {
                    let names = asked.names.join(",");
                    let fields = [asked.id, asked.actor, names, asked.limits, asked.reason];
                    wire::pack(&fields.iter().map(String::as_bytes).collect::<Vec<_>>())
                });
                let lines: Vec<Vec<u8>> = lines.collect();
                wire::pack(&lines.iter().map(Vec::as_slice).collect::<Vec<_>>())
            }),
            (b"decide", [id, answer @ ("yes" | "no")]) => {
                let verdict = Verdict {
                    yes: *answer == "yes",
                    by: root(held)?,
                    actor: vault.audit.actor.clone(),
                };
                let ended = self.desk.decide(id, verdict)?;
                ended.map_or(Ok(()), |grant| {
                    vault.audit.record(Act {
                        event: "revoke",
                        secret: &grant.names.join(","),
                        grant: &grant.id,
                        note: "-",
                    })
                })?;
                Ok(Vec::new())
            }
            (b"lock", []) => {
                self.stop.store(true, Ordering::SeqCst);
                self.desk.close();
                // Wake the accept loop so it sees the flag, then take the
                // socket's name away: by the time the caller hears back, the
                // vault is locked to everyone.
                drop(UnixStream::connect(&self.socket));
                let _ = fs::remove_file(&self.socket);
                Ok(Vec::new())
            }
            (b"sub", []) => match held? {
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
                exec::run(&vault, held?, command, &place, conn)
            }
            _ => denied("unknown request"),
        }
    }

    /// A grant is asked for. Whoever presents a grant is answered by it at
    /// once: the new grant is bound by that one. Whoever presents none waits
    /// for an approver. Every request and its outcome is logged.
    fn request(
        &self,
        vault: &Vault,
        mut asked: Request,
        parent: Option<Grant>,
        conn: &UnixStream,
    ) -> Result<Vec<u8>, Error> {
        let Some(limits) = grant::limits(&asked.limits) else {
            return denied(
                "not a limit: join a duration (30s, 15m, 1h, 2d), a count of uses (3x) \
                 and `run` with commas",
            );
        };
        asked.names.iter().try_for_each(|name| store::check(name))?;
        if asked.names.is_empty() || asked.reason.is_empty() {
            return denied("a grant request names its secrets and gives a reason");
        }
        let (id, token) = crypt::random::<32>(&vault.entropy).map(|bytes| {
            let (id, token) = bytes.split_at(16);
            let uuid = |half: &[u8]| audit::uuid(<[u8; 16]>::try_from(half).unwrap_or_default());
            (uuid(id), uuid(token))
        })?;
        asked.id = id;
        let (what, their) = (asked.names.join(","), vault.audit.by(&asked.actor));
        let line = |event, note| Act {
            event,
            secret: &what,
            grant: &asked.id,
            note,
        };
        let terms = format!("{} {}", asked.limits, asked.reason);
        their.record(line("request", &terms))?;
        let verdict = match parent {
            None => self.desk.ask(asked.clone(), conn),
            Some(by) => Some(Verdict {
                yes: true,
                by,
                actor: vault.audit.actor.clone(),
            }),
        };
        let Some(verdict) = verdict else {
            let _ = their.record(line("abandon", "-"));
            return denied("the request was abandoned");
        };
        let event = if verdict.yes { "grant" } else { "refuse" };
        let from = format!("from {}", verdict.by.id);
        vault.audit.by(&verdict.actor).record(line(event, &from))?;
        if !verdict.yes {
            return denied("refused");
        }
        let grant = Grant::mint(&asked, &limits, verdict.by);
        self.desk.hold(token.clone(), grant);
        Ok(token.into_bytes())
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
