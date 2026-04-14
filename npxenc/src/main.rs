#![allow(clippy::print_stderr, clippy::print_stdout)]

use std::path::PathBuf;
use std::process::ExitCode;
use std::{io, io::IsTerminal};

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use enclaveapp_app_adapter::{
    run, EncryptedFileSecretStore, JsonFileBindingStore, ReadOnlyEncryptedFileSecretStore,
    ResolveMode, SecretStore,
};
use npmenc_core::{
    acquire_secret_from_token_source, default_registry_binding, delete_binding_label,
    install_userconfig, list_binding_rows, normalize_cli_token_source_spec,
    normalize_registry_url_to_auth_key, prepare_wrapped_invocation,
    prepare_wrapped_invocation_read_only, store_binding_secret, token_provider_is_valid_name,
    token_source_display_for_spec, token_source_supports_direct_acquisition, uninstall_userconfig,
    CommandKind, RegistryBinding, WrapperInvocation,
};

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
#[command(name = "npxenc", version, about = "Secure wrapper for npx")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    #[arg(long)]
    userconfig: Option<PathBuf>,

    #[arg(long)]
    shell: Option<PathBuf>,

    #[arg(long, value_enum, default_value_t = ResolveModeArg::Auto)]
    resolve_mode: ResolveModeArg,

    #[arg(long = "npx-bin")]
    npx_bin: Option<PathBuf>,

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

#[derive(Debug, Subcommand)]
enum Commands {
    Install(InstallArgs),
    Uninstall(UninstallArgs),
    #[command(visible_alias = "credential")]
    Token {
        #[command(subcommand)]
        command: TokenCommands,
    },
    Registry {
        #[command(subcommand)]
        command: RegistryCommands,
    },
}

#[derive(Debug, Subcommand)]
enum TokenCommands {
    Set(TokenSetArgs),
    Add(TokenSetArgs),
    List,
    #[command(visible_alias = "remove")]
    Delete(TokenDeleteArgs),
}

#[derive(Debug, Subcommand)]
enum RegistryCommands {
    Add(TokenSetArgs),
    SetDefault(TokenSetArgs),
    List,
    #[command(visible_alias = "delete")]
    Remove(TokenDeleteArgs),
}

#[derive(Debug, Parser)]
struct TokenSetArgs {
    #[arg(long)]
    label: Option<String>,

    #[arg(long)]
    url: Option<String>,

    #[arg(
        long,
        conflicts_with_all = ["token_command", "token_provider", "token_handle"]
    )]
    token_source: Option<String>,

    #[arg(long, conflicts_with = "token_source")]
    token_command: Option<String>,

    #[arg(long, conflicts_with = "token_source")]
    token_provider: Option<String>,

    #[arg(long, requires = "token_provider", conflicts_with = "token_source")]
    token_handle: Option<String>,

    #[arg(long, conflicts_with = "secret_stdin")]
    secret: Option<String>,

    #[arg(long)]
    secret_stdin: bool,
}

#[derive(Debug, Parser)]
struct TokenDeleteArgs {
    #[arg(long)]
    label: Option<String>,
}

#[derive(Debug, Parser)]
struct InstallArgs {}

#[derive(Debug, Parser)]
struct UninstallArgs {
    #[arg(long)]
    purge: bool,

    #[arg(long, conflicts_with = "purge")]
    keep_secrets: bool,
}

fn main() -> ExitCode {
    match run_main() {
        Ok(code) => code,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run_main() -> Result<ExitCode> {
    let cli = Cli::parse();

    if let Some(command) = cli.command {
        run_command(command, cli.userconfig.as_deref(), cli.allow_unscoped_auth)?;
        return Ok(ExitCode::SUCCESS);
    }

    let invocation = WrapperInvocation {
        userconfig_override: cli.userconfig,
        resolve_mode: cli.resolve_mode.into(),
        shell: cli.shell,
        explicit_bin: cli.npx_bin,
        strict: cli.strict,
        allow_unscoped_auth: cli.allow_unscoped_auth,
        args: cli.args,
    };
    let inspection_only = cli.dry_run || cli.print_effective_config;
    let binding_store = JsonFileBindingStore::for_app("npmenc")?;
    let prepared = if inspection_only {
        let secret_store = ReadOnlyEncryptedFileSecretStore::for_app("npmenc")?;
        prepare_for_execution(
            CommandKind::Npx,
            invocation,
            false,
            cli.allow_unscoped_auth,
            false,
            &binding_store,
            &secret_store,
        )?
    } else {
        let secret_store = EncryptedFileSecretStore::for_app("npmenc")?;
        prepare_for_execution(
            CommandKind::Npx,
            invocation,
            cli.auto_install,
            cli.allow_unscoped_auth,
            true,
            &binding_store,
            &secret_store,
        )?
    };

    if cli.dry_run {
        println!("program: {}", prepared.launch.program.path.display());
        if !prepared.launch.program.fixed_args.is_empty() {
            println!(
                "program_fixed_args: {}",
                prepared.launch.program.fixed_args.join(" ")
            );
        }
        println!("strategy: {:?}", prepared.launch.program.strategy);
        println!("mode: {:?}", prepared.mode);
        println!(
            "effective_config: {}",
            prepared.effective_config_path.display()
        );
        println!("effective_config_contents:");
        print!("{}", prepared.effective_config_contents);
        if !prepared.effective_config_contents.ends_with('\n') {
            println!();
        }
        for warning in &prepared.warnings {
            eprintln!("warning: {warning}");
        }
        for (key, value) in &prepared.launch.env_overrides {
            if key.starts_with("NPM_TOKEN") {
                println!("env {key}=<redacted>");
            } else {
                println!("env {key}={value}");
            }
        }
        return Ok(ExitCode::SUCCESS);
    }

    if cli.print_effective_config {
        println!("{}", prepared.effective_config_path.display());
        return Ok(ExitCode::SUCCESS);
    }

    for warning in &prepared.warnings {
        eprintln!("warning: {warning}");
    }

    let status = run(&prepared.launch)?;
    Ok(exit_code_from_status(status))
}

fn exit_code_from_status(status: std::process::ExitStatus) -> ExitCode {
    let code = status.code().unwrap_or(1);
    if code == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(code as u8)
    }
}

fn run_command(
    command: Commands,
    userconfig: Option<&std::path::Path>,
    allow_unscoped_auth: bool,
) -> Result<()> {
    match command {
        Commands::Install(_args) => {
            let binding_store = JsonFileBindingStore::for_app("npmenc")?;
            let secret_store = EncryptedFileSecretStore::for_app("npmenc")?;
            let report = install_userconfig(
                userconfig,
                allow_unscoped_auth,
                &binding_store,
                &secret_store,
            )?;
            println!(
                "installed {} imported binding(s), activated {} managed binding(s) in {}",
                report.imported_labels.len(),
                report.active_labels.len(),
                report.path.display()
            );
            for warning in report.warnings {
                eprintln!("warning: {warning}");
            }
            Ok(())
        }
        Commands::Uninstall(args) => {
            let binding_store = JsonFileBindingStore::for_app("npmenc")?;
            let secret_store = EncryptedFileSecretStore::for_app("npmenc")?;
            let purge = args.purge || !args.keep_secrets;
            let report = uninstall_userconfig(userconfig, purge, &binding_store, &secret_store)?;
            if report.restored_labels.is_empty() && report.removed_labels.is_empty() {
                println!("updated 0 binding(s) in {}", report.path.display());
            } else {
                println!(
                    "restored {} binding(s), removed {} binding(s) in {}",
                    report.restored_labels.len(),
                    report.removed_labels.len(),
                    report.path.display()
                );
            }
            if report.purged {
                println!("purged managed bindings and secrets");
            }
            Ok(())
        }
        Commands::Token {
            command: token_command,
        } => run_token_command(token_command),
        Commands::Registry {
            command: registry_command,
        } => run_registry_command(registry_command),
    }
}

fn prepare_for_execution<S>(
    command_kind: CommandKind,
    invocation: WrapperInvocation,
    auto_install: bool,
    allow_unscoped_auth: bool,
    allow_prompt: bool,
    binding_store: &JsonFileBindingStore,
    secret_store: &S,
) -> Result<npmenc_core::PreparedInvocation>
where
    S: SecretStore,
{
    let mut prepared = if allow_prompt {
        prepare_wrapped_invocation(
            command_kind,
            invocation.clone(),
            binding_store,
            secret_store,
        )?
    } else {
        prepare_wrapped_invocation_read_only(
            command_kind,
            invocation.clone(),
            binding_store,
            secret_store,
        )?
    };
    if prepared.mode != npmenc_core::WrapperMode::TransientFallback {
        return Ok(prepared);
    }

    if auto_install || (allow_prompt && should_offer_install()?) {
        let report = install_userconfig(
            invocation.userconfig_override.as_deref(),
            allow_unscoped_auth,
            binding_store,
            secret_store,
        )?;
        eprintln!(
            "info: install activated {} managed binding(s) for continued execution",
            report.active_labels.len()
        );
        for warning in report.warnings {
            eprintln!("warning: {warning}");
        }
        prepared =
            prepare_wrapped_invocation(command_kind, invocation, binding_store, secret_store)?;
    }

    Ok(prepared)
}

fn should_offer_install() -> Result<bool> {
    if !io::stdin().is_terminal() || !io::stderr().is_terminal() {
        return Ok(false);
    }

    eprint!("npxenc detected unmanaged token material in .npmrc. Run install and continue? [y/N] ");
    let mut response = String::new();
    io::stdin().read_line(&mut response)?;
    let accepted = matches!(response.trim().to_ascii_lowercase().as_str(), "y" | "yes");
    Ok(accepted)
}

fn run_token_command(command: TokenCommands) -> Result<()> {
    match command {
        TokenCommands::Set(args) | TokenCommands::Add(args) => {
            upsert_binding_from_args(&args, false)
        }
        TokenCommands::List => list_bindings(),
        TokenCommands::Delete(args) => delete_binding(args),
    }
}

fn run_registry_command(command: RegistryCommands) -> Result<()> {
    match command {
        RegistryCommands::Add(args) => upsert_binding_from_args(&args, false),
        RegistryCommands::SetDefault(args) => upsert_binding_from_args(&args, true),
        RegistryCommands::List => list_bindings(),
        RegistryCommands::Remove(args) => delete_binding(args),
    }
}

fn upsert_binding_from_args(args: &TokenSetArgs, force_default_label: bool) -> Result<()> {
    let binding_store = JsonFileBindingStore::for_app("npmenc")?;
    let secret_store = EncryptedFileSecretStore::for_app("npmenc")?;
    let binding = if force_default_label {
        binding_from_default_args(args)?
    } else {
        binding_from_set_args(args)?
    };
    let secret = read_secret(&binding, args)?;
    let token_source = token_source_spec_from_args(args)?;
    let stored = store_binding_secret(
        Some(&binding.label),
        Some(&binding.registry_url),
        &secret,
        token_source.as_deref(),
        &binding_store,
        &secret_store,
    )?;
    println!(
        "stored binding `{}` for {}",
        stored.label, stored.registry_url
    );
    Ok(())
}

fn list_bindings() -> Result<()> {
    let binding_store = JsonFileBindingStore::for_app("npmenc")?;
    let secret_store = EncryptedFileSecretStore::for_app("npmenc")?;
    for row in list_binding_rows(&binding_store, &secret_store)? {
        let token_source = row.token_source_display.unwrap_or_else(|| "-".to_string());
        println!(
            "{}\t{}\t{}\t{}",
            row.label, row.target, row.secret_env_var, token_source
        );
    }
    Ok(())
}

fn delete_binding(args: TokenDeleteArgs) -> Result<()> {
    let binding_store = JsonFileBindingStore::for_app("npmenc")?;
    let secret_store = EncryptedFileSecretStore::for_app("npmenc")?;
    let label = args.label.unwrap_or_else(|| "default".to_string());
    if delete_binding_label(&label, &binding_store, &secret_store)? {
        println!("deleted binding `{label}`");
    } else {
        println!("no binding found for `{label}`");
    }
    Ok(())
}

fn binding_from_set_args(args: &TokenSetArgs) -> Result<RegistryBinding> {
    let label = args.label.clone().unwrap_or_else(|| "default".to_string());
    if label == "default"
        && args.url.as_deref().is_some_and(|url| {
            normalize_registry_url_to_auth_key(url)
                != normalize_registry_url_to_auth_key("https://registry.npmjs.org/")
        })
    {
        return Err(anyhow::anyhow!(
            "the `default` binding is reserved for https://registry.npmjs.org/"
        ));
    }
    let binding = if label == "default" && args.url.is_none() {
        default_registry_binding()
    } else {
        let url = args
            .url
            .clone()
            .unwrap_or_else(|| "https://registry.npmjs.org/".to_string());
        RegistryBinding::new(label, url)
    };
    Ok(binding)
}

fn binding_from_default_args(args: &TokenSetArgs) -> Result<RegistryBinding> {
    if args.url.as_deref().is_some_and(|url| {
        normalize_registry_url_to_auth_key(url)
            != normalize_registry_url_to_auth_key("https://registry.npmjs.org/")
    }) {
        return Err(anyhow::anyhow!(
            "the `default` binding is reserved for https://registry.npmjs.org/"
        ));
    }
    let normalized = TokenSetArgs {
        label: Some("default".to_string()),
        url: args.url.clone(),
        token_source: args.token_source.clone(),
        token_command: args.token_command.clone(),
        token_provider: args.token_provider.clone(),
        token_handle: args.token_handle.clone(),
        secret: args.secret.clone(),
        secret_stdin: args.secret_stdin,
    };
    if normalized.url.is_none() {
        return Ok(default_registry_binding());
    }
    binding_from_set_args(&normalized)
}

fn read_secret(binding: &RegistryBinding, args: &TokenSetArgs) -> Result<String> {
    if let Some(secret) = &args.secret {
        return validate_non_empty_secret(binding, secret.clone());
    }

    if args.secret_stdin {
        let mut secret = String::new();
        io::stdin().read_line(&mut secret)?;
        return validate_non_empty_secret(
            binding,
            secret.trim_end_matches(['\r', '\n']).to_string(),
        );
    }

    if let Some(token_source) = token_source_spec_from_args(args)? {
        if !token_source_supports_direct_acquisition(&token_source)? {
            let display = token_source_display_for_spec(&token_source)?;
            return Err(anyhow::anyhow!(
                "token source `{display}` is metadata only; specify --secret or --secret-stdin alongside it"
            ));
        }
        return acquire_secret_from_token_source(&token_source);
    }

    Err(anyhow::anyhow!(
        "specify --secret, --secret-stdin, or --token-source for binding `{}`",
        binding.label
    ))
}

fn token_source_spec_from_args(args: &TokenSetArgs) -> Result<Option<String>> {
    if let Some(token_source) = &args.token_source {
        return Ok(Some(normalize_cli_token_source_spec(token_source)?));
    }
    if let Some(token_command) = &args.token_command {
        if token_command.trim().is_empty() {
            return Err(anyhow::anyhow!("--token-command cannot be empty"));
        }
        return Ok(Some(format!("command:{token_command}")));
    }
    if let Some(token_provider) = &args.token_provider {
        if token_provider.trim().is_empty() {
            return Err(anyhow::anyhow!("--token-provider cannot be empty"));
        }
        if !token_provider_is_valid_name(token_provider) {
            return Err(anyhow::anyhow!(
                "`--token-provider {token_provider}` is not a valid provider name"
            ));
        }
        return Ok(Some(match &args.token_handle {
            Some(handle) => format!("provider:{token_provider}:{handle}"),
            None => format!("provider:{token_provider}"),
        }));
    }
    Ok(None)
}

fn validate_non_empty_secret(binding: &RegistryBinding, secret: String) -> Result<String> {
    if secret.is_empty() {
        return Err(anyhow::anyhow!(
            "binding `{}` cannot use an empty secret",
            binding.label
        ));
    }

    Ok(secret)
}
