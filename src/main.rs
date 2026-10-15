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
