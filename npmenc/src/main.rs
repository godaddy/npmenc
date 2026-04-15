#![allow(clippy::print_stderr, clippy::print_stdout)]

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, ValueEnum};
use enclaveapp_app_adapter::ResolveMode;
use npmenc_core::cli_common::{CliVariant, Commands, CommonCliOptions};
use npmenc_core::CommandKind;

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ResolveModeArg {
    Auto,
    PathOnly,
    CommandV,
}

impl From<ResolveModeArg> for ResolveMode {
    fn from(value: ResolveModeArg) -> Self {
        match value {
            ResolveModeArg::Auto => Self::Auto,
            ResolveModeArg::PathOnly => Self::PathOnly,
            ResolveModeArg::CommandV => Self::CommandV,
        }
    }
}

#[derive(Debug, Parser)]
#[command(name = "npmenc", version, about = "Secure wrapper for npm")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    #[arg(long)]
    userconfig: Option<PathBuf>,

    #[arg(long)]
    shell: Option<PathBuf>,

    #[arg(long, value_enum, default_value_t = ResolveModeArg::Auto)]
    resolve_mode: ResolveModeArg,

    #[arg(long = "npm-bin")]
    npm_bin: Option<PathBuf>,

    #[arg(long)]
    dry_run: bool,

    #[arg(long)]
    print_effective_config: bool,

    #[arg(long)]
    strict: bool,

    #[arg(long)]
    allow_unscoped_auth: bool,

    #[arg(long)]
    auto_install: bool,

    #[arg(last = true)]
    args: Vec<String>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let variant = CliVariant {
        command_kind: CommandKind::Npm,
        display_name: "npmenc",
    };
    let options = CommonCliOptions {
        command: cli.command,
        userconfig: cli.userconfig,
        shell: cli.shell,
        resolve_mode: cli.resolve_mode.into(),
        explicit_bin: cli.npm_bin,
        dry_run: cli.dry_run,
        print_effective_config: cli.print_effective_config,
        strict: cli.strict,
        allow_unscoped_auth: cli.allow_unscoped_auth,
        auto_install: cli.auto_install,
        args: cli.args,
    };
    match npmenc_core::cli_common::run_cli(&variant, options) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}
