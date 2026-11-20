//! The command line, written against the library's public surface only.

use scotoma::{Console, Error, Scotoma, Stream};
use std::io::{BufRead, Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};

pub const USAGE: &str = "\
usage: scotoma COMMAND

  unlock            read the vault password and serve the vault from this
                    terminal until it is locked; a vault that does not exist
                    is created. Grant requests are approved here.
  lock              end the unlocked session; the key and all grants are gone

  grant LIMITS [NAME...]
                    ask the person at the unlock terminal to let the caller
                    use the named secrets (none: all); prints a token to put
                    in SCOTOMA_GRANT. LIMITS joins with commas any of:
                      30s, 15m, 1h, 2d   how long it lasts
                      3x                 how many commands or streams may
                                         use a secret
                      run                `run` only: `sub` is refused
                    as in `1h`, `1x,run` or `15m,3x`. With SCOTOMA_GRANT set
                    nobody is asked: the new grant is minted from that one
                    and can do nothing that one cannot. Hand it to a subagent.

  set NAME          store the secret read from stdin (one trailing newline dropped)
  rm NAME           delete a secret
  ls                list secret names

  issue NAME        print a new handle for a secret                    [grant]
  run CMD [ARG...]  run CMD with each handle in its arguments replaced by
                    its secret; in its output the secret reads as the
                    handle again                                       [grant]
  sub               copy stdin to stdout, each handle replaced by its
                    secret                                             [grant]
  redact            copy stdin to stdout, each secret value replaced by [scotoma:NAME]
  guard             copy stdin to stdout; fail at the first secret value

environment:
  SCOTOMA_HOME      the vault directory (default: $XDG_DATA_HOME/scotoma,
                    else $HOME/.local/share/scotoma)
  SCOTOMA_ACTOR     who the usage log says did it (default: $USER)
  SCOTOMA_GRANT     the grant token for commands marked [grant]

exit: 0 done, 1 failed, 2 usage; `run` exits as CMD did.
";

pub struct Streams<'a> {
    pub input: &'a mut (dyn BufRead + Send),
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
    let vault = Scotoma::open(&home, actor.as_deref().unwrap_or("unknown"))?;
    let vault = vault.with_grant(&env("SCOTOMA_GRANT").unwrap_or_default());
    match args {
        ["unlock"] => {
            let console = Console {
                input: streams.input,
                output: streams.err,
                echo,
            };
            scotoma::unlock(&home, console)?;
        }
        ["lock"] => vault.lock()?,
        ["grant", limits, names @ ..] => {
            write(
                streams.out,
                format!("{}\n", vault.grant(limits, names)?).as_bytes(),
            )?;
        }
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
        ["guard"] => pump(streams.input, &mut vault.guard()?, streams.out)?,
        ["run", command @ ..] if !command.is_empty() => {
            return vault.run(command, streams.out, streams.err).map(Some);
        }
        _ => return Ok(None),
    }
    Ok(Some(0))
}

/// Stop or resume the terminal's echo, for the password. Off a terminal
/// `stty` fails and nothing changes, which is right.
fn echo(on: bool) {
    let mode = if on { "echo" } else { "-echo" };
    let _ = Command::new("stty")
        .arg(mode)
        .stderr(Stdio::null())
        .status();
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
fn pump(input: &mut dyn Read, stream: &mut Stream, out: &mut dyn Write) -> Result<(), Error> {
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
