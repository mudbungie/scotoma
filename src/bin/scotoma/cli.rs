//! The command line, written against the library's public surface only.

use crate::exec;
use scotoma::{Error, Scotoma, Stream};
use std::io::{Read, Write};
use std::path::PathBuf;

pub const USAGE: &str = "\
usage: scotoma COMMAND

  set NAME          store the secret read from stdin (one trailing newline dropped)
  rm NAME           delete a secret
  ls                list secret names
  issue NAME        print a new handle for a secret
  sub               copy stdin to stdout, each handle replaced by its secret
  redact            copy stdin to stdout, each secret value replaced by [scotoma:NAME]
  run CMD [ARG...]  run CMD with handles in its arguments replaced by their
                    secrets, and its stdout and stderr redacted

environment:
  SCOTOMA_HOME      the vault directory (default: $XDG_DATA_HOME/scotoma,
                    else $HOME/.local/share/scotoma)
  SCOTOMA_ACTOR     who the usage log says did it (default: $USER)

exit: 0 done, 1 failed, 2 usage; `run` exits as CMD did.
";

pub struct Streams<'a> {
    pub input: &'a mut dyn Read,
    pub out: &'a mut (dyn Write + Send),
    pub err: &'a mut (dyn Write + Send),
}

pub type Env<'a> = &'a dyn Fn(&str) -> Option<String>;

/// Run one command line; the return value is the process exit code.
pub fn run(args: &[String], env: Env, mut streams: Streams) -> u8 {
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match dispatch(&args, env, &mut streams) {
        Ok(Some(code)) => code,
        Ok(None) => {
            let _ = streams.err.write_all(USAGE.as_bytes());
            2
        }
        Err(error) => {
            let _ = writeln!(streams.err, "scotoma: {error}");
            1
        }
    }
}

/// `Ok(None)` means the arguments were not a command.
fn dispatch(args: &[&str], env: Env, streams: &mut Streams) -> Result<Option<u8>, Error> {
    let Some(home) = home(env) else {
        return Ok(None);
    };
    let actor = env("SCOTOMA_ACTOR").or_else(|| env("USER"));
    let vault = Scotoma::open(home, actor.as_deref().unwrap_or("unknown"))?;
    match args {
        ["set", name] => {
            let mut value = String::new();
            streams
                .input
                .read_to_string(&mut value)
                .map_err(Error::io("stdin"))?;
            vault.set(name, value.strip_suffix('\n').unwrap_or(&value))?;
        }
        ["rm", name] => vault.remove(name)?,
        ["ls"] => {
            let listed = |all: String, name: &String| all + name + "\n";
            let names = vault.names()?.iter().fold(String::new(), listed);
            write(streams.out, names.as_bytes())?;
        }
        ["issue", name] => write(streams.out, format!("{}\n", vault.issue(name)?).as_bytes())?,
        ["sub"] => pump(streams.input, &mut vault.substituter()?, streams.out)?,
        ["redact"] => pump(streams.input, &mut vault.redactor()?, streams.out)?,
        ["run", command @ ..] if !command.is_empty() => {
            return exec::run(&vault, command, streams.out, streams.err).map(Some);
        }
        _ => return Ok(None),
    }
    Ok(Some(0))
}

fn home(env: Env) -> Option<PathBuf> {
    let data = || env("XDG_DATA_HOME").map(PathBuf::from);
    let fallback = || env("HOME").map(|home| PathBuf::from(home).join(".local/share"));
    env("SCOTOMA_HOME")
        .map(PathBuf::from)
        .or_else(|| data().or_else(fallback).map(|data| data.join("scotoma")))
}

fn write(out: &mut dyn Write, bytes: &[u8]) -> Result<(), Error> {
    out.write_all(bytes)
        .and_then(|()| out.flush())
        .map_err(Error::io("output"))
}

/// Copy `input` to `out` through `stream`, flushing per chunk: what is
/// decided is delivered, not buffered until the end.
pub fn pump(input: &mut dyn Read, stream: &mut Stream, out: &mut dyn Write) -> Result<(), Error> {
    let mut buffer = vec![0; 1 << 16];
    loop {
        let read = input.read(&mut buffer).map_err(Error::io("input"))?;
        let chunk = buffer.get(..read).unwrap_or_default();
        let bytes = if chunk.is_empty() {
            stream.finish()?
        } else {
            stream.push(chunk)?
        };
        write(out, &bytes)?;
        if chunk.is_empty() {
            return Ok(());
        }
    }
}
