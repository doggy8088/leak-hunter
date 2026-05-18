use anyhow::Result;
use clap::Parser;
use leak_hunter::cli::{run, Cli};

fn main() -> Result<()> {
    let cli = Cli::parse();
    let code = run(cli)?;
    std::process::exit(code);
}
