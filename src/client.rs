//! The public surface: a client of the resident process.
//!
//! Nothing here holds a key or reads the vault's files. Every call is one
//! conversation over the vault's socket.

use crate::{Error, store, wire};
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

/// A connection to an unlocked vault.
///
/// Opening touches nothing. Calls fail with [`Error::Locked`] until someone
/// runs [`crate::unlock`] (`scotoma unlock`) on the same directory.
#[derive(Debug, Clone)]
pub struct Scotoma {
    socket: PathBuf,
    actor: String,
    grant: String,
}

impl Scotoma {
    /// `actor` is who the log will say did it; it obeys the name alphabet.
    pub fn open(home: impl Into<PathBuf>, actor: &str) -> Result<Self, Error> {
        store::check(actor)?;
        let socket = home.into().join("socket");
        Ok(Self {
            socket,
            actor: actor.to_owned(),
            grant: String::new(),
        })
    }

    /// Present a grant token (from [`Self::grant`]) with every call. Issuing
    /// a handle, substituting and running need one.
    #[must_use]
    pub fn with_grant(mut self, token: &str) -> Self {
        token.clone_into(&mut self.grant);
        self
    }

    /// Start a conversation: connect and send the request.
    fn begin(&self, op: &str, args: &[&[u8]]) -> Result<UnixStream, Error> {
        let conn = UnixStream::connect(&self.socket).map_err(|_| Error::Locked)?;
        let mut fields = vec![self.actor.as_bytes(), self.grant.as_bytes(), op.as_bytes()];
        fields.extend(args);
        let _ = wire::send(&conn, wire::ASK, &wire::pack(&fields));
        Ok(conn)
    }

    /// A whole conversation with one textual answer.
    fn ask(&self, op: &str, args: &[&str]) -> Result<String, Error> {
        let args: Vec<&[u8]> = args.iter().map(|arg| arg.as_bytes()).collect();
        let conn = self.begin(op, &args)?;
        reply(&conn).map(|body| String::from_utf8_lossy(&body).into_owned())
    }

    /// Store `value` under `name`, replacing any previous value.
    pub fn set(&self, name: &str, value: &str) -> Result<(), Error> {
        self.ask("set", &[name, value]).map(drop)
    }

    /// Delete a secret. Its handles stop substituting.
    pub fn remove(&self, name: &str) -> Result<(), Error> {
        self.ask("rm", &[name]).map(drop)
    }

    /// The names of the stored secrets, sorted. Names are not secret.
    pub fn names(&self) -> Result<Vec<String>, Error> {
        let names = self.ask("ls", &[])?;
        Ok(names.lines().map(str::to_owned).collect())
    }

    /// Ask the user for a grant over `names` (none means every secret) for
    /// `duration` (`30s`, `15m`, `1h`, `2d`). Blocks until the person at the
    /// resident process's console answers. Returns the grant's token.
    pub fn grant(&self, duration: &str, names: &[&str]) -> Result<String, Error> {
        self.ask("grant", &[&[duration], names].concat())
    }

    /// Mint a handle for a secret: a random UUID that is safe to show a
    /// model. It stands for the secret's current value for as long as the
    /// secret exists. Needs a grant that covers the secret.
    pub fn issue(&self, name: &str) -> Result<String, Error> {
        self.ask("issue", &[name])
    }

    /// End the resident process. The key and every grant are gone.
    pub fn lock(&self) -> Result<(), Error> {
        self.ask("lock", &[]).map(drop)
    }

    fn stream(&self, op: &str) -> Result<Stream, Error> {
        let conn = self.begin(op, &[])?;
        reply(&conn)?;
        Ok(Stream { conn })
    }

    /// A stream that replaces every issued handle with its secret's value.
    /// Needs a grant; a handle whose secret the grant does not cover is an
    /// error. **Its output carries secrets**: send it to the thing that
    /// executes, never to a model, a log or a transcript. Prefer
    /// [`Self::run`], where the value never reaches the caller at all.
    pub fn substituter(&self) -> Result<Stream, Error> {
        self.stream("sub")
    }

    /// A stream that replaces every stored secret value with
    /// `[scotoma:NAME]`. The value is matched as stored and as it appears
    /// inside a JSON string.
    pub fn redactor(&self) -> Result<Stream, Error> {
        self.stream("redact")
    }

    /// A stream that passes clean content through unchanged and fails with
    /// [`Error::Leak`] at the first stored secret value. Put it in front of
    /// anything that sends content to a model: a hit means do not send.
    /// Bytes ahead of the hit, which hold no secret, may already have passed.
    pub fn guard(&self) -> Result<Stream, Error> {
        self.stream("guard")
    }

    /// [`Self::substituter`] over one whole string.
    pub fn substitute(&self, text: &str) -> Result<String, Error> {
        self.substituter()?.whole(text)
    }

    /// [`Self::redactor`] over one whole string.
    pub fn redact(&self, text: &str) -> Result<String, Error> {
        self.redactor()?.whole(text)
    }

    /// [`Self::guard`] over one whole string: `Ok` means it may be sent.
    pub fn check(&self, text: &str) -> Result<(), Error> {
        self.guard()?.whole(text).map(drop)
    }

    /// Have the resident process run `command`, in this process's directory
    /// and environment, with every handle in it replaced by its secret. The
    /// value never reaches the caller: output arrives already redacted, a
    /// value that went in through a handle coming back as that handle.
    /// Returns the command's exit code (1 if it had none). Needs a grant.
    pub fn run(
        &self,
        command: &[&str],
        out: &mut dyn Write,
        err: &mut dyn Write,
    ) -> Result<u8, Error> {
        let cwd = std::env::current_dir().unwrap_or_default();
        let vars = std::env::vars_os()
            .map(|(name, value)| [name.as_bytes(), b"=", value.as_bytes()].concat());
        let vars: Vec<Vec<u8>> = vars.collect();
        let env = wire::pack(&vars.iter().map(Vec::as_slice).collect::<Vec<_>>());
        let mut args = vec![cwd.as_os_str().as_bytes(), &env];
        args.extend(command.iter().map(|word| word.as_bytes()));
        let conn = self.begin("run", &args)?;
        loop {
            let (tag, body) = wire::recv(&conn).map_err(Error::io("resident"))?;
            match tag {
                wire::OUT => out.write_all(&body).map_err(Error::io("output"))?,
                wire::ERR => err.write_all(&body).map_err(Error::io("output"))?,
                _ => {
                    return wire::outcome(tag, body).map(|code| code.first().copied().unwrap_or(1));
                }
            }
        }
    }
}

/// The resident process's answer to the last thing sent.
fn reply(conn: &UnixStream) -> Result<Vec<u8>, Error> {
    let (tag, body) = wire::recv(conn).map_err(Error::io("resident"))?;
    wire::outcome(tag, body)
}

/// A streaming pass over bytes, from [`Scotoma::substituter`],
/// [`Scotoma::redactor`] or [`Scotoma::guard`]. A match may straddle chunks:
/// bytes that could still begin one are held back until [`Stream::finish`].
#[derive(Debug)]
pub struct Stream {
    conn: UnixStream,
}

impl Stream {
    /// Feed a chunk; get back the bytes that are now decided.
    pub fn push(&mut self, chunk: &[u8]) -> Result<Vec<u8>, Error> {
        let mut decided = Vec::new();
        for piece in chunk.chunks(wire::LIMIT / 2) {
            let _ = wire::send(&self.conn, wire::OK, piece);
            decided.extend(reply(&self.conn)?);
        }
        Ok(decided)
    }

    /// The input has ended: get back whatever was held. The stream is spent.
    pub fn finish(&mut self) -> Result<Vec<u8>, Error> {
        let _ = wire::send(&self.conn, wire::END, b"");
        reply(&self.conn)
    }

    fn whole(mut self, text: &str) -> Result<String, Error> {
        let mut bytes = self.push(text.as_bytes())?;
        bytes.extend(self.finish()?);
        // Whole UTF-8 strings replaced inside a UTF-8 string: still UTF-8.
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }
}

#[cfg(test)]
#[path = "client_tests.rs"]
mod tests;
