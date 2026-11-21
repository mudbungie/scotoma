//! The desk: where grants are asked for, decided and held.
//!
//! A request waits here until someone with the authority answers it: the
//! person at the console, or an approver on the socket. Both are the same
//! seat. Everything is memory only and gone at lock.

use crate::Error;
use crate::grant::Grant;
use std::io::{BufRead, Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::atomic::Ordering;
use std::sync::{Condvar, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

/// The id of the grant the approver holds: every other grant descends from it.
pub(crate) const ROOT: &str = "root";
/// How often a waiting request checks that its caller is still there.
const TICK: Duration = Duration::from_millis(50);

/// A grant someone is waiting for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// The id the grant will have; what [`crate::Scotoma::decide`] takes.
    pub id: String,
    /// Who asks. The grant's uses are logged under this name.
    pub actor: String,
    /// The secrets asked for.
    pub names: Vec<String>,
    /// The limits asked for, as written: `1h`, `15m,3x,run`.
    pub limits: String,
    /// Why, in the asker's words.
    pub reason: String,
}

/// An answer: whether, under which grant's authority, and in whose name.
#[derive(Debug, Clone)]
pub(crate) struct Verdict {
    pub yes: bool,
    pub by: Grant,
    pub actor: String,
}

struct State {
    /// `(token, grant)`.
    grants: Vec<(String, Grant)>,
    asked: Vec<(Request, Option<Verdict>)>,
    output: Box<dyn Write + Send>,
    closed: bool,
}

pub(crate) struct Desk {
    state: Mutex<State>,
    bell: Condvar,
    root: Grant,
}

fn denied<T>(why: &str) -> Result<T, Error> {
    Err(Error::Denied(why.to_owned()))
}

impl Desk {
    /// A desk whose approver holds `token`.
    pub fn new(output: Box<dyn Write + Send>, token: String) -> Self {
        let root = Grant {
            id: ROOT.to_owned(),
            ..Grant::none()
        };
        let state = State {
            grants: vec![(token, root.clone())],
            asked: Vec::new(),
            output,
            closed: false,
        };
        Self {
            state: Mutex::new(state),
            bell: Condvar::new(),
            root,
        }
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn say(&self, text: &str) {
        let mut state = self.state();
        let _ = state.output.write_all(text.as_bytes());
        let _ = state.output.flush();
    }

    /// Lock up: everyone waiting here is released.
    pub fn close(&self) {
        self.state().closed = true;
        self.bell.notify_all();
    }

    pub fn hold(&self, token: String, grant: Grant) {
        self.state().grants.push((token, grant));
    }

    /// The live grant a token stands for.
    pub fn grant(&self, token: &str) -> Result<Grant, Error> {
        let state = self.state();
        match state.grants.iter().find(|(held, _)| held == token) {
            Some((_, grant)) if grant.live() => Ok(grant.clone()),
            Some(_) => denied("the grant has expired, is used up or was revoked"),
            None => denied("no grant: ask for one with `scotoma grant`"),
        }
    }

    /// Put a request to the approvers and wait. `None` means nobody will be
    /// answered: the caller hung up, or the vault was locked.
    pub fn ask(&self, request: Request, conn: &UnixStream) -> Option<Verdict> {
        let (id, names) = (request.id.clone(), request.names.join(", "));
        let limits = crate::grant::describe(&request.limits);
        let (actor, reason) = (&request.actor, &request.reason);
        let question = format!(
            "grant requested by {actor}: {names} for {limits}\nreason: {reason}\napprove? [y/N] "
        );
        self.say(&question);
        let mut state = self.state();
        state.asked.push((request, None));
        self.bell.notify_all();
        loop {
            let mine =
                |(asked, verdict): &(Request, Option<Verdict>)| asked.id == id && verdict.is_some();
            if state.asked.iter().any(mine) || state.closed || hung_up(conn) {
                let (mine, rest) = std::mem::take(&mut state.asked)
                    .into_iter()
                    .partition(|(asked, _)| asked.id == id);
                state.asked = rest;
                let mine: Vec<_> = mine;
                return mine.into_iter().find_map(|(_, verdict)| verdict);
            }
            let waited = self.bell.wait_timeout(state, TICK);
            state = waited.unwrap_or_else(PoisonError::into_inner).0;
        }
    }

    /// The requests nobody has answered. Waits until there is one, or the
    /// vault is locked.
    pub fn pending(&self) -> Vec<Request> {
        let mut state = self.state();
        loop {
            let open = open(&state);
            if state.closed || !open.is_empty() {
                return open;
            }
            state = self
                .bell
                .wait(state)
                .unwrap_or_else(PoisonError::into_inner);
        }
    }

    /// Answer an open request; or, with a no, end a live grant, which is
    /// then returned.
    pub fn decide(&self, id: &str, verdict: Verdict) -> Result<Option<Grant>, Error> {
        let mut state = self.state();
        let open = |(asked, verdict): &&mut (Request, Option<Verdict>)| {
            asked.id == id && verdict.is_none()
        };
        if let Some((_, slot)) = state.asked.iter_mut().find(open) {
            *slot = Some(verdict);
            self.bell.notify_all();
            return Ok(None);
        }
        let live = |(_, grant): &&(String, Grant)| grant.id == id && id != ROOT && grant.live();
        match state.grants.iter().find(live) {
            Some((_, grant)) if !verdict.yes => {
                grant.left.store(0, Ordering::SeqCst);
                Ok(Some(grant.clone()))
            }
            _ => denied("no open request and no live grant to end has that id"),
        }
    }

    /// The console's side: each line typed answers the oldest open request,
    /// and only `y` is yes. Ends when the vault locks or the console closes;
    /// requests are then left to the approvers on the socket.
    pub fn listen(&self, mut input: Box<dyn BufRead + Send>) {
        while !self.pending().is_empty() {
            let mut line = String::new();
            if input.read_line(&mut line).unwrap_or(0) == 0 {
                return;
            }
            // Not `pending`: a line typed for a request someone else has
            // answered must not wait here and answer the next one.
            let oldest = open(&self.state()).into_iter().next();
            let verdict = Verdict {
                yes: line.trim_end_matches(['\r', '\n']) == "y",
                by: self.root.clone(),
                actor: "console".to_owned(),
            };
            let _ = oldest.map(|asked| self.decide(&asked.id, verdict));
        }
    }
}

fn open(state: &State) -> Vec<Request> {
    let open = state.asked.iter().filter(|(_, verdict)| verdict.is_none());
    open.map(|(asked, _)| asked.clone()).collect()
}

/// Whether the other end of `conn` has gone away.
fn hung_up(mut conn: &UnixStream) -> bool {
    let _ = conn.set_nonblocking(true);
    let gone = matches!(conn.read(&mut [0]), Ok(0));
    let _ = conn.set_nonblocking(false);
    gone
}

#[cfg(test)]
#[path = "desk_tests.rs"]
mod tests;
