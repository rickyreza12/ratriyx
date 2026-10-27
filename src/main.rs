macro_rules! say {
    ($($arg:tt)*) => {{
        use std::io::Write as _;
        let _ = writeln!(std::io::stdout(), $($arg)*);
    }};
}

macro_rules! show {
    ($($arg:tt)*) => {{
        use std::io::Write as _;
        let _ = write!(std::io::stdout(), $($arg)*);
    }};
}

mod application;
mod domain;
mod infrastructure;
mod interface;

use domain::error::Result;
use interface::cli::Command;
use std::env;
use std::io::IsTerminal;

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let code = match execute(&args) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("ratriyx: {err}");
            err.exit_code()
        }
    };
    std::process::exit(code);
}

fn execute(args: &[String]) -> Result<i32> {
    // Cargo cannot run a post-install hook. Offer setup only when a person
    // launches bare `ratriyx` in an interactive terminal; all scripted calls
    // keep the existing non-interactive behavior.
    if args.is_empty() && std::io::stdin().is_terminal() && std::io::stdout().is_terminal() {
        infrastructure::platform::require_supported(&infrastructure::platform::detect())?;
        return application::commands::first_run();
    }
    match interface::cli::parse(args)? {
        Command::Help => {
            show!("{}", interface::cli::HELP);
            Ok(0)
        }
        Command::Version => {
            say!("ratriyx {}", env!("CARGO_PKG_VERSION"));
            Ok(0)
        }
        command => {
            infrastructure::platform::require_supported(&infrastructure::platform::detect())?;
            application::commands::dispatch(command)
        }
    }
}
