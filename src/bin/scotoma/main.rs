//! The process edge: real arguments, environment and streams, nothing else.

mod cli;
#[cfg(test)]
mod tests;

use std::io::BufReader;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let env = |key: &str| std::env::var(key).ok();
    let console = scotoma::Console {
        input: Box::new(BufReader::new(std::io::stdin())),
        output: Box::new(std::io::stderr()),
        echo: cli::echo,
    };
    let streams = cli::Streams {
        input: &mut BufReader::new(std::io::stdin()),
        out: &mut std::io::stdout(),
        err: &mut std::io::stderr(),
    };
    ExitCode::from(cli::run(&args, &env, console, streams))
}
