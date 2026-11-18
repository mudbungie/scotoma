//! The process edge: real arguments, environment and streams, nothing else.

mod cli;
mod exec;
#[cfg(test)]
mod tests;

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let env = |key: &str| std::env::var(key).ok();
    let streams = cli::Streams {
        input: &mut std::io::stdin().lock(),
        out: &mut std::io::stdout(),
        err: &mut std::io::stderr(),
    };
    ExitCode::from(cli::run(&args, &env, streams))
}
