//! `scotoma run`: the secret goes into the child's arguments and nowhere else.

use crate::cli::pump;
use scotoma::{Error, Scotoma};
use std::io::Write;
use std::process::{Command, Stdio};
use std::thread;

type Sink<'a> = &'a mut (dyn Write + Send);

/// Run `command` with its handles substituted and both output streams
/// redacted as they flow. Returns the child's exit code (1 if it had none).
pub fn run(vault: &Scotoma, command: &[&str], out: Sink, err: Sink) -> Result<u8, Error> {
    let mut out_stream = vault.redactor()?;
    let mut err_stream = out_stream.clone();
    let argv = command.iter().map(|word| vault.substitute(word));
    let mut argv = argv.collect::<Result<Vec<String>, Error>>()?.into_iter();
    // Named as the caller wrote it: an error must not echo a substituted secret.
    let name = command.first().copied().unwrap_or_default();
    let mut child = Command::new(argv.next().unwrap_or_default())
        .args(argv)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(Error::io(name))?;
    let (stdout, stderr) = (child.stdout.take(), child.stderr.take());
    let (mut copied_out, mut copied_err) = (Ok(()), Ok(()));
    thread::scope(|scope| {
        scope.spawn(|| {
            copied_err = stderr.map_or(Ok(()), |mut pipe| pump(&mut pipe, &mut err_stream, err));
        });
        copied_out = stdout.map_or(Ok(()), |mut pipe| pump(&mut pipe, &mut out_stream, out));
    });
    let status = child.wait().map_err(Error::io(name));
    let code =
        |status: std::process::ExitStatus| status.code().and_then(|code| u8::try_from(code).ok());
    copied_out
        .and(copied_err)
        .and(status)
        .map(|status| code(status).unwrap_or(1))
}
