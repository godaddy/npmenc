#![allow(clippy::print_stderr, clippy::print_stdout)]

use std::path::PathBuf;
use std::process::ExitCode;
use std::{io, io::IsTerminal};

use anyhow::Result;
use clap::{Parser, Subcommand};
use enclaveapp_app_adapter::{
    run, EncryptedFileSecretStore, JsonFileBindingStore, ReadOnlyEncryptedFileSecretStore,
    ResolveMode, SecretStore,
};

use crate::{
    acquire_secret_from_token_source, default_registry_binding, delete_binding_label,
    install_userconfig, list_binding_rows, normalize_cli_token_source_spec,
    normalize_registry_url_to_auth_key, prepare_wrapped_invocation,
    prepare_wrapped_invocation_read_only, store_binding_secret, token_provider_is_valid_name,
    token_source_display_for_spec, token_source_supports_direct_acquisition, uninstall_userconfig,
    CommandKind, RegistryBinding, WrapperInvocation,
};

/// Parameters that differ between npmenc and npxenc.
#[derive(Debug, Clone)]
pub struct CliVariant {
    pub command_kind: CommandKind,
    pub display_name: &'static str,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
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
    /// Any subcommand we don't recognize is forwarded verbatim to npm/npx,
    /// including its `--help`. So `npmenc whoami --help` shows
    /// `npm whoami --help`, and `npmenc add lodash` runs `npm add lodash`,
    /// without needing a `--` separator. The reserved npmenc subcommands
    /// above (install, uninstall, token, registry) shadow npm's same-named
    /// subcommands; route them to npm explicitly with a `--` separator,
    /// e.g. `npmenc -- install lodash`.
    #[command(external_subcommand)]
    External(Vec<String>),
}

#[derive(Debug, Subcommand)]
pub enum TokenCommands {
    Set(TokenSetArgs),
    Add(TokenSetArgs),
    List,
    #[command(visible_alias = "remove")]
    Delete(TokenDeleteArgs),
}

#[derive(Debug, Subcommand)]
pub enum RegistryCommands {
    Add(TokenSetArgs),
    SetDefault(TokenSetArgs),
    List,
    #[command(visible_alias = "delete")]
    Remove(TokenDeleteArgs),
}

#[derive(Debug, Parser)]
pub struct TokenSetArgs {
    #[arg(long)]
    pub label: Option<String>,

    #[arg(long)]
    pub url: Option<String>,

    #[arg(
        long,
        conflicts_with_all = ["token_command", "token_provider", "token_handle"]
    )]
    pub token_source: Option<String>,

    #[arg(long, conflicts_with = "token_source")]
    pub token_command: Option<String>,

    #[arg(long, conflicts_with = "token_source")]
    pub token_provider: Option<String>,

    #[arg(long, requires = "token_provider", conflicts_with = "token_source")]
    pub token_handle: Option<String>,

    #[arg(
        long,
        conflicts_with = "secret_stdin",
        help = "Token value (WARNING: visible in process listings; prefer --secret-stdin)"
    )]
    pub secret: Option<String>,

    #[arg(long)]
    pub secret_stdin: bool,
}

#[derive(Debug, Parser)]
pub struct TokenDeleteArgs {
    #[arg(long)]
    pub label: Option<String>,
}

#[derive(Debug, Parser)]
pub struct InstallArgs {}

#[derive(Debug, Parser)]
pub struct UninstallArgs {
    #[arg(long)]
    pub purge: bool,

    #[arg(long, conflicts_with = "purge")]
    pub keep_secrets: bool,
}

/// Common CLI options shared between npmenc and npxenc.
///
/// The binary-specific struct should embed this and add its own
/// `--npm-bin` / `--npx-bin` field.
#[derive(Debug)]
pub struct CommonCliOptions {
    pub command: Option<Commands>,
    pub userconfig: Option<PathBuf>,
    pub shell: Option<PathBuf>,
    pub resolve_mode: ResolveMode,
    pub explicit_bin: Option<PathBuf>,
    pub dry_run: bool,
    pub print_effective_config: bool,
    pub strict: bool,
    pub allow_unscoped_auth: bool,
    pub auto_install: bool,
    /// When set, only inject `NPM_TOKEN*` into the child process for npm
    /// subcommands that actually authenticate to the registry (publish,
    /// whoami, access, token, etc.). Subcommands that merely consume
    /// already-fetched packages (`version`, `run-script`, `init`, …) run
    /// without the token. Reduces the Type-2 env-var exposure window at
    /// the cost of breaking private-registry reads on `install` — opt-in
    /// only, never default. Always injects for npxenc.
    pub publish_only: bool,
}

pub fn run_cli(variant: &CliVariant, cli: CommonCliOptions) -> Result<ExitCode> {
    // Anything that wasn't one of npmenc's reserved subcommands lands in
    // Commands::External — including the explicit `--` bypass form
    // (e.g. `npmenc -- install lodash` parses to External(["install",
    // "lodash"]). When no subcommand is given we still run the wrapper
    // (e.g. `npmenc` with just options prints npm's help via the wrapped
    // execution path).
    let pass_through_args: Vec<String> = match cli.command {
        Some(Commands::External(args)) => args,
        Some(other) => {
            run_command(other, cli.userconfig.as_deref(), cli.allow_unscoped_auth)?;
            return Ok(ExitCode::SUCCESS);
        }
        None => Vec::new(),
    };

    let publish_only_active = cli.publish_only
        && !subcommand_needs_registry_auth(variant.command_kind, &pass_through_args);

    let invocation = WrapperInvocation {
        userconfig_override: cli.userconfig,
        resolve_mode: cli.resolve_mode,
        shell: cli.shell,
        explicit_bin: cli.explicit_bin,
        strict: cli.strict,
        allow_unscoped_auth: cli.allow_unscoped_auth,
        args: pass_through_args,
    };
    let inspection_only = cli.dry_run || cli.print_effective_config;
    let binding_store = JsonFileBindingStore::for_app("npmenc")?;
    let mut prepared = if inspection_only {
        let secret_store = ReadOnlyEncryptedFileSecretStore::for_app("npmenc")?;
        prepare_for_execution(
            variant,
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
            variant,
            invocation,
            cli.auto_install,
            cli.allow_unscoped_auth,
            true,
            &binding_store,
            &secret_store,
        )?
    };

    if publish_only_active {
        strip_token_env_overrides(&mut prepared.launch.env_overrides);
    }

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

    let status = run(prepared.launch)?;
    Ok(exit_code_from_status(status))
}

pub fn exit_code_from_status(status: std::process::ExitStatus) -> ExitCode {
    let code = status.code().unwrap_or(1);
    if code == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(code as u8)
    }
}

/// npm subcommands that actually authenticate to the registry.
///
/// Limited to commands where npm sends the auth token to the registry:
/// publishing / unpublishing / deprecating packages, managing access,
/// owners, teams, dist-tags, user profile / tokens / hooks / org state,
/// and explicit auth flows (`adduser`, `login`, etc.). Commands that
/// merely consume fetched tarballs (`version`, `run-script`, `init`,
/// `audit`, `ci`, `install` against a public registry) are excluded —
/// `--publish-only` is about cutting the token's exposure window when it
/// isn't needed, at the cost of breaking private-registry reads.
const NPM_REGISTRY_AUTH_SUBCOMMANDS: &[&str] = &[
    "publish",
    "unpublish",
    "deprecate",
    "undeprecate",
    "access",
    "owner",
    "team",
    "dist-tag",
    "dist-tags",
    "whoami",
    "profile",
    "token",
    "hook",
    "hooks",
    "org",
    "adduser",
    "add-user",
    "login",
    "signup",
    "logout",
    "star",
    "unstar",
    "stars",
];

/// npm subcommands that do NOT authenticate to the registry.
///
/// Only used as a positive signal that a given arg really is the
/// subcommand. If the first positional we encounter is in neither list,
/// we can't tell whether it's a subcommand or a flag value — default to
/// "needs auth" so we don't accidentally strip the token for something
/// that really does need it.
const NPM_NON_AUTH_SUBCOMMANDS: &[&str] = &[
    "install",
    "i",
    "in",
    "ins",
    "inst",
    "insta",
    "instal",
    "isntall",
    "isnt",
    "add",
    "ci",
    "clean-install",
    "clean-install-test",
    "cit",
    "install-ci-test",
    "install-test",
    "it",
    "uninstall",
    "un",
    "unlink",
    "remove",
    "rm",
    "r",
    "update",
    "up",
    "upgrade",
    "udpate",
    "version",
    "verison",
    "run",
    "run-script",
    "rum",
    "urn",
    "test",
    "tst",
    "t",
    "start",
    "stop",
    "restart",
    "init",
    "create",
    "innit",
    "pack",
    "list",
    "ls",
    "la",
    "ll",
    "outdated",
    "audit",
    "fund",
    "explain",
    "why",
    "prune",
    "dedupe",
    "ddp",
    "find-dupes",
    "rebuild",
    "rb",
    "view",
    "v",
    "info",
    "show",
    "search",
    "find",
    "s",
    "se",
    "help",
    "help-search",
    "docs",
    "home",
    "repo",
    "bugs",
    "config",
    "c",
    "set",
    "get",
    "cache",
    "exec",
    "x",
    "shrinkwrap",
    "completion",
    "doctor",
    "ping",
    "edit",
    "diff",
    "sbom",
    "query",
    "q",
    "root",
    "prefix",
    "bin",
    "birthday",
    "link",
    "ln",
    "pkg",
    "sample",
];

fn subcommand_needs_registry_auth(kind: CommandKind, args: &[String]) -> bool {
    match kind {
        // npx invokes package code that may itself auth to the registry.
        // We cannot introspect what the package will do, so always inject.
        CommandKind::Npx => true,
        CommandKind::Npm => {
            // Walk left to right. The first positional that matches a
            // known auth-requiring subcommand wins (inject). The first
            // that matches a known non-auth subcommand wins (strip).
            // Unknown positionals are treated as flag values and skipped
            // — we default to "needs auth" if nothing is recognized, so
            // a user mis-using --publish-only with custom/plugin
            // subcommands still gets working tokens.
            for arg in args {
                if arg.starts_with('-') {
                    continue;
                }
                let s = arg.as_str();
                if NPM_REGISTRY_AUTH_SUBCOMMANDS.contains(&s) {
                    return true;
                }
                if NPM_NON_AUTH_SUBCOMMANDS.contains(&s) {
                    return false;
                }
            }
            true
        }
    }
}

fn strip_token_env_overrides(env: &mut std::collections::BTreeMap<String, String>) {
    env.retain(|key, _| !key.starts_with("NPM_TOKEN"));
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
        Commands::External(_) => unreachable!(
            "External is intercepted in run_cli and routed to the pass-through wrapper path"
        ),
    }
}

fn prepare_for_execution<S>(
    variant: &CliVariant,
    invocation: WrapperInvocation,
    auto_install: bool,
    allow_unscoped_auth: bool,
    allow_prompt: bool,
    binding_store: &JsonFileBindingStore,
    secret_store: &S,
) -> Result<crate::PreparedInvocation>
where
    S: SecretStore,
{
    let command_kind = variant.command_kind;
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
    if prepared.mode != crate::WrapperMode::TransientFallback {
        return Ok(prepared);
    }

    if auto_install || (allow_prompt && should_offer_install(variant)?) {
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

fn should_offer_install(variant: &CliVariant) -> Result<bool> {
    if !io::stdin().is_terminal() || !io::stderr().is_terminal() {
        return Ok(false);
    }

    eprint!(
        "{} detected unmanaged token material in .npmrc. Run install and continue? [y/N] ",
        variant.display_name
    );
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal test wrapper around the shared `Commands` enum so we can
    /// exercise clap's parsing of the curated subcommands and the
    /// `External` pass-through variant without depending on the binary
    /// crates' full Cli struct.
    #[derive(Debug, Parser)]
    #[command(no_binary_name = true)]
    struct TestCli {
        #[command(subcommand)]
        command: Option<Commands>,
    }

    fn parse_test(args: &[&str]) -> TestCli {
        TestCli::try_parse_from(args).expect("clap parse succeeded")
    }

    fn external_args_of(cli: TestCli) -> Vec<String> {
        if let Some(Commands::External(args)) = cli.command {
            args
        } else {
            Vec::new()
        }
    }

    #[test]
    fn external_subcommand_captures_unknown_first_positional() {
        let args = external_args_of(parse_test(&["whoami"]));
        assert_eq!(args, vec!["whoami".to_string()]);
    }

    #[test]
    fn external_subcommand_captures_trailing_flags() {
        // `npmenc whoami --json --help` — every token after the unknown
        // subcommand name gets captured, including --help and any flags.
        // clap stops parsing as parent options once the external variant
        // is matched.
        let args = external_args_of(parse_test(&["whoami", "--json", "--help"]));
        assert_eq!(
            args,
            vec![
                "whoami".to_string(),
                "--json".to_string(),
                "--help".to_string()
            ]
        );
    }

    #[test]
    fn double_dash_separator_routes_through_external() {
        // `npmenc -- install lodash` — the `--` bypass for reserved
        // subcommand names. clap treats the tokens after `--` as the
        // start of an external subcommand, so `install` (which is a
        // reserved npmenc subcommand otherwise) reaches npm verbatim.
        let args = external_args_of(parse_test(&["--", "install", "lodash"]));
        assert_eq!(args, vec!["install".to_string(), "lodash".to_string()]);
    }

    #[test]
    fn reserved_install_subcommand_still_matches_curated_path() {
        let cli = parse_test(&["install"]);
        assert!(matches!(cli.command, Some(Commands::Install(_))));
    }

    #[test]
    fn reserved_token_subcommand_still_matches_curated_path() {
        let cli = parse_test(&["token", "list"]);
        assert!(matches!(
            cli.command,
            Some(Commands::Token {
                command: TokenCommands::List
            })
        ));
    }

    #[test]
    fn reserved_subcommand_with_extra_positional_does_not_silently_pass_through() {
        // `npmenc install lodash` is ambiguous: `install` is reserved by
        // npmenc as a no-arg setup command, but most users typing it mean
        // `npm install lodash`. Rather than guessing, clap surfaces the
        // collision as an error so users learn to use `--` to bypass.
        let result = TestCli::try_parse_from(["install", "lodash"]);
        assert!(result.is_err(), "expected clap error, got: {result:?}");
    }

    #[test]
    fn no_subcommand_is_none_not_external() {
        // Bare `npmenc` (no subcommand, no args) yields command = None,
        // which falls through to the wrapped-execution path with empty
        // args (so npm prints its own help).
        let cli = parse_test(&[]);
        assert!(cli.command.is_none());
    }

    #[test]
    fn cli_variant_npm_has_correct_fields() {
        let variant = CliVariant {
            command_kind: CommandKind::Npm,
            display_name: "npmenc",
        };
        assert_eq!(variant.command_kind, CommandKind::Npm);
        assert_eq!(variant.display_name, "npmenc");
        assert_eq!(variant.command_kind.executable_name(), "npm");
    }

    #[test]
    fn cli_variant_npx_has_correct_fields() {
        let variant = CliVariant {
            command_kind: CommandKind::Npx,
            display_name: "npxenc",
        };
        assert_eq!(variant.command_kind, CommandKind::Npx);
        assert_eq!(variant.display_name, "npxenc");
        assert_eq!(variant.command_kind.executable_name(), "npx");
    }

    #[test]
    fn cli_variant_clone() {
        let variant = CliVariant {
            command_kind: CommandKind::Npm,
            display_name: "npmenc",
        };
        let cloned = variant.clone();
        assert_eq!(variant.command_kind, cloned.command_kind);
        assert_eq!(variant.display_name, cloned.display_name);
    }

    #[test]
    fn cli_variant_debug_impl() {
        let variant = CliVariant {
            command_kind: CommandKind::Npm,
            display_name: "npmenc",
        };
        let debug = format!("{variant:?}");
        assert!(debug.contains("Npm"));
        assert!(debug.contains("npmenc"));
    }

    #[test]
    fn exit_code_from_status_zero_is_success() {
        use std::process::Command;
        let status = Command::new("true").status().expect("run true");
        let code = exit_code_from_status(status);
        assert_eq!(code, ExitCode::SUCCESS);
    }

    #[test]
    fn exit_code_from_status_nonzero_is_failure() {
        use std::process::Command;
        let status = Command::new("false").status().expect("run false");
        let code = exit_code_from_status(status);
        assert_ne!(code, ExitCode::SUCCESS);
    }

    #[test]
    fn needs_auth_publish_commands() {
        let cases = [
            "publish",
            "unpublish",
            "deprecate",
            "whoami",
            "access",
            "owner",
            "team",
            "dist-tag",
            "token",
            "adduser",
            "login",
            "logout",
            "profile",
            "hook",
            "org",
            "star",
        ];
        for cmd in cases {
            assert!(
                subcommand_needs_registry_auth(CommandKind::Npm, &[cmd.to_string()]),
                "{cmd} should require auth"
            );
        }
    }

    #[test]
    fn needs_auth_skips_non_publish_commands() {
        let cases = [
            "install",
            "i",
            "ci",
            "version",
            "run-script",
            "run",
            "test",
            "init",
            "audit",
            "rebuild",
            "pack",
            "ls",
            "prune",
        ];
        for cmd in cases {
            assert!(
                !subcommand_needs_registry_auth(CommandKind::Npm, &[cmd.to_string()]),
                "{cmd} should NOT require auth"
            );
        }
    }

    #[test]
    fn needs_auth_skips_flag_value_that_isnt_a_subcommand() {
        // The scanner walks past flag values that aren't known
        // subcommands and lands on the real subcommand.
        let args = vec![
            "--registry".to_string(),
            "https://example.com".to_string(),
            "publish".to_string(),
        ];
        assert!(subcommand_needs_registry_auth(CommandKind::Npm, &args));
    }

    #[test]
    fn needs_auth_ambiguous_flag_value_collides_with_subcommand_name() {
        // When a flag value (`info` in `--loglevel info`) happens to
        // match a known non-auth subcommand name, we cannot tell it apart
        // from the real subcommand. This is a known limitation of the
        // positional-only heuristic. The first match wins, so `info`
        // takes precedence over the later `publish`. Users who want
        // --publish-only to behave correctly with such flags must use
        // the `--flag=value` form instead of `--flag value`.
        let args = vec![
            "--loglevel".to_string(),
            "info".to_string(),
            "publish".to_string(),
        ];
        // `info` is a known alias for `view` (non-auth), so we return
        // false here — documenting the heuristic's limit.
        assert!(!subcommand_needs_registry_auth(CommandKind::Npm, &args));

        // The `=` form removes the ambiguity.
        let args = vec!["--loglevel=info".to_string(), "publish".to_string()];
        assert!(subcommand_needs_registry_auth(CommandKind::Npm, &args));
    }

    #[test]
    fn needs_auth_no_subcommand_defaults_to_true() {
        // Unknown / empty args default to injecting — safer than
        // silently breaking whatever the user runs with a misconfigured
        // --publish-only flag.
        assert!(subcommand_needs_registry_auth(CommandKind::Npm, &[]));
        assert!(subcommand_needs_registry_auth(
            CommandKind::Npm,
            &["--help".to_string()]
        ));
    }

    #[test]
    fn needs_auth_unknown_subcommand_defaults_to_true() {
        // A custom npm plugin or typo doesn't match either list. Default
        // to auth=true so the token is injected. --publish-only is not
        // supposed to break user workflows; it narrows exposure when we
        // can be sure.
        assert!(subcommand_needs_registry_auth(
            CommandKind::Npm,
            &["custom-plugin-command".to_string()]
        ));
    }

    #[test]
    fn npx_always_needs_auth() {
        assert!(subcommand_needs_registry_auth(CommandKind::Npx, &[]));
        assert!(subcommand_needs_registry_auth(
            CommandKind::Npx,
            &["create-react-app".to_string()]
        ));
    }

    #[test]
    fn strip_token_env_overrides_removes_only_npm_token_prefix() {
        let mut env = std::collections::BTreeMap::new();
        env.insert("NPM_TOKEN".to_string(), "a".to_string());
        env.insert("NPM_TOKEN_DEFAULT".to_string(), "b".to_string());
        env.insert("NPM_TOKEN_MY_ORG".to_string(), "c".to_string());
        env.insert("OTHER_VAR".to_string(), "d".to_string());
        env.insert("NPMENC_CONFIG_DIR".to_string(), "e".to_string());

        strip_token_env_overrides(&mut env);

        assert_eq!(env.len(), 2);
        assert_eq!(env.get("OTHER_VAR").map(String::as_str), Some("d"));
        assert_eq!(env.get("NPMENC_CONFIG_DIR").map(String::as_str), Some("e"));
    }
}
