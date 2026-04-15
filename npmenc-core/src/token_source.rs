#![cfg_attr(test, allow(clippy::unwrap_used))]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{anyhow, Result};
use enclaveapp_app_adapter::{
    resolve_program, BindingId, BindingRecord, ResolveMode, ResolveOptions, SecretStore,
    REDACTED_PLACEHOLDER,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::common::restore_previous_secret;

const TOKEN_PROVIDER_KEY: &str = "token_provider";
const TOKEN_HANDLE_KEY: &str = "token_handle";
const TOKEN_DISPLAY_KEY: &str = "token_display";
const LEGACY_TOKEN_SOURCE_KEY: &str = "token_source";
const COMMAND_TOKEN_PROVIDER: &str = "command";
const COMMAND_PREFIX: &str = "command:";
const PROVIDER_PREFIX: &str = "provider:";
const TOKEN_SOURCE_PREPARED_MARKER: &str = "prepared";

#[derive(Debug, Clone, PartialEq, Eq)]
struct TokenSourceCommand {
    program: PathBuf,
    args: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TokenSourceSpec {
    Command {
        canonical: String,
        handle: String,
        display: String,
    },
    Provider {
        provider: String,
        handle: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum BindingTokenSource {
    Command {
        command: String,
        prepared: bool,
        needs_persist: bool,
    },
    Provider {
        provider: String,
        handle: Option<String>,
        adapter: Option<StoredProviderAdapterState>,
        needs_persist: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TokenSourceReadMode {
    Normal,
    Inspection,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenSourceArtifactsSnapshot {
    pub state: Option<String>,
    pub prepared: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StagedBindingSecret {
    pub secret: String,
    pub token_source_artifacts: Option<TokenSourceArtifactsSnapshot>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PendingManagedSecretUpdate {
    pub id: BindingId,
    pub secret: String,
    pub token_source_artifacts: Option<TokenSourceArtifactsSnapshot>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TokenSourceMetadataUpdate {
    provider: String,
    display: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TokenSourceUpdate {
    metadata: TokenSourceMetadataUpdate,
    artifacts: TokenSourceArtifactsSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum StoredTokenSourceState {
    Command {
        canonical: String,
    },
    Provider {
        provider: String,
        #[serde(default)]
        handle: Option<String>,
        #[serde(default)]
        adapter: Option<StoredProviderAdapterState>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "adapter", rename_all = "snake_case")]
enum StoredProviderAdapterState {
    SsoJwt {
        canonical_command: String,
        server: Option<String>,
        environment: Option<String>,
    },
    GenericCommand {
        provider: String,
        canonical_command: String,
        handle: Option<String>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuntimeProviderAdapter {
    SsoJwt,
}

struct RuntimeProviderAdapterOps {
    prepare: fn(&str, Option<&str>) -> Result<Option<StoredProviderAdapterState>>,
    acquire: fn(&StoredProviderAdapterState) -> Result<String>,
}

const SSO_JWT_PROVIDER_ADAPTER_OPS: RuntimeProviderAdapterOps = RuntimeProviderAdapterOps {
    prepare: prepare_sso_jwt_provider_state,
    acquire: acquire_secret_from_sso_jwt_adapter,
};

const GENERIC_PROVIDER_ADAPTER_OPS: RuntimeProviderAdapterOps = RuntimeProviderAdapterOps {
    prepare: prepare_generic_provider_state,
    acquire: acquire_secret_from_generic_provider_adapter,
};

pub fn canonicalize_token_source(spec: &str) -> Result<String> {
    match parse_token_source_spec(spec)? {
        TokenSourceSpec::Command { canonical, .. } => Ok(canonical),
        TokenSourceSpec::Provider { provider, handle } => {
            Ok(provider_display(&provider, handle.as_deref()))
        }
    }
}

pub fn canonicalize_binding_token_source<S>(
    record: &mut BindingRecord,
    secret_store: &S,
) -> Result<bool>
where
    S: SecretStore,
{
    let Some(spec) = token_source_command(record, secret_store)? else {
        return Ok(false);
    };
    let previous_display = token_source_display(record)?;
    prepare_token_source_metadata(record, &spec, secret_store)?;
    Ok(previous_display != token_source_display(record)?)
}

pub fn acquire_secret_from_token_source(spec: &str) -> Result<String> {
    match parse_token_source_spec(spec)? {
        TokenSourceSpec::Command { canonical, .. } => acquire_secret_from_command_spec(&canonical),
        TokenSourceSpec::Provider { provider, handle } => {
            let adapter = prepare_provider_adapter_state(&provider, handle.as_deref())?
                .ok_or_else(|| {
                    anyhow!("token provider `{provider}` is not supported for direct acquisition")
                })?;
            acquire_secret_from_provider_adapter(&adapter)
        }
    }
}

pub fn acquire_secret_from_binding_token_source<S>(
    record: &BindingRecord,
    secret_store: &S,
) -> Result<Option<String>>
where
    S: SecretStore,
{
    let Some(staged) = acquire_secret_from_binding_token_source_staged(record, secret_store)?
    else {
        return Ok(None);
    };
    if let Some(artifacts) = &staged.token_source_artifacts {
        apply_token_source_artifacts(&record.id, artifacts, secret_store)?;
    }
    Ok(Some(staged.secret))
}

pub(crate) fn acquire_secret_from_binding_token_source_staged<S>(
    record: &BindingRecord,
    secret_store: &S,
) -> Result<Option<StagedBindingSecret>>
where
    S: SecretStore,
{
    let Some(spec) = binding_token_source(record, secret_store)? else {
        return Ok(None);
    };
    let staged = match spec {
        BindingTokenSource::Command {
            command,
            needs_persist,
            ..
        } => {
            let secret = acquire_secret_from_command_spec(&command)?;
            let token_source_artifacts = if needs_persist {
                Some(prepared_command_artifacts(&canonicalize_command_spec(
                    &command,
                )?))
            } else {
                None
            };
            StagedBindingSecret {
                secret,
                token_source_artifacts,
            }
        }
        BindingTokenSource::Provider {
            provider,
            handle,
            adapter,
            needs_persist,
        } => {
            let adapter = match adapter {
                Some(adapter) => adapter,
                None => prepare_provider_adapter_state(&provider, handle.as_deref())?.ok_or_else(
                    || {
                        anyhow!(
                            "token provider `{provider}` is not supported for direct acquisition"
                        )
                    },
                )?,
            };
            StagedBindingSecret {
                secret: acquire_secret_from_provider_adapter(&adapter)?,
                token_source_artifacts: needs_persist
                    .then(|| prepared_provider_artifacts(&provider, handle.as_deref(), &adapter)),
            }
        }
    };
    Ok(Some(staged))
}

pub fn set_token_source_metadata<S>(
    record: &mut BindingRecord,
    spec: &str,
    secret_store: &S,
) -> Result<()>
where
    S: SecretStore,
{
    let update = build_token_source_update(spec)?;
    apply_token_source_artifacts(&record.id, &update.artifacts, secret_store)?;
    apply_token_source_metadata_update(record, &update.metadata);
    Ok(())
}

pub fn clear_token_source_metadata(record: &mut BindingRecord) {
    record.metadata.remove(TOKEN_PROVIDER_KEY);
    record.metadata.remove(TOKEN_HANDLE_KEY);
    record.metadata.remove(TOKEN_DISPLAY_KEY);
    record.metadata.remove(LEGACY_TOKEN_SOURCE_KEY);
}

pub fn has_token_source_metadata(record: &BindingRecord) -> bool {
    record.metadata.contains_key(TOKEN_PROVIDER_KEY)
        || record.metadata.contains_key(LEGACY_TOKEN_SOURCE_KEY)
}

pub fn token_source_command<S>(record: &BindingRecord, secret_store: &S) -> Result<Option<String>>
where
    S: SecretStore,
{
    match binding_token_source(record, secret_store)? {
        Some(BindingTokenSource::Command { command, .. }) => Ok(Some(command)),
        Some(BindingTokenSource::Provider { .. }) | None => Ok(None),
    }
}

pub fn token_source_display(record: &BindingRecord) -> Result<Option<String>> {
    if let Some(display) = record.metadata.get(TOKEN_DISPLAY_KEY) {
        return Ok(Some(display.clone()));
    }
    if let Some(provider) = record.metadata.get(TOKEN_PROVIDER_KEY) {
        return Ok(Some(provider.clone()));
    }
    let Some(spec) = record.metadata.get(LEGACY_TOKEN_SOURCE_KEY) else {
        return Ok(None);
    };
    Ok(Some(display_legacy_token_source_spec(spec)?))
}

pub fn token_source_display_for_listing<S>(
    record: &BindingRecord,
    secret_store: &S,
) -> Result<Option<String>>
where
    S: SecretStore,
{
    match binding_token_source(record, secret_store)? {
        Some(BindingTokenSource::Command { command, .. }) => {
            let tokens =
                shlex::split(&command).ok_or_else(|| anyhow!("invalid token source command"))?;
            let token = tokens
                .first()
                .ok_or_else(|| anyhow!("token source command is empty"))?;
            let name = Path::new(token)
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("command");
            Ok(Some(format!("command:{name}#{}", command_handle(&command))))
        }
        Some(BindingTokenSource::Provider {
            provider, handle, ..
        }) => Ok(Some(provider_display(&provider, handle.as_deref()))),
        None => Ok(None),
    }
}

pub fn token_source_display_for_spec(spec: &str) -> Result<String> {
    display_token_source_spec(spec)
}

pub fn normalize_cli_token_source_spec(spec: &str) -> Result<String> {
    if spec.trim().is_empty() {
        return Err(anyhow!("--token-source cannot be empty"));
    }
    if spec.starts_with(COMMAND_PREFIX) || spec.starts_with(PROVIDER_PREFIX) {
        return Ok(spec.to_string());
    }

    let tokens = shlex::split(spec).ok_or_else(|| anyhow!("invalid token source: {spec}"))?;
    let token = tokens
        .first()
        .ok_or_else(|| anyhow!("token source command is empty"))?;
    if tokens.len() == 1 && !looks_like_path(token) {
        return Err(anyhow!(
            "ambiguous bare token source `{spec}`; use --token-command, --token-provider, or an explicit `command:...` / `provider:...` token source"
        ));
    }
    Ok(spec.to_string())
}

pub fn token_source_supports_direct_acquisition(spec: &str) -> Result<bool> {
    Ok(match classify_token_source_spec(spec)? {
        TokenSourceKind::Command { .. } => true,
        TokenSourceKind::Provider { provider, handle } => {
            prepare_provider_adapter_state(&provider, handle.as_deref())?.is_some()
        }
    })
}

pub fn token_provider_is_supported(provider: &str) -> bool {
    token_provider_is_valid_name(provider) && provider_supports_direct_acquisition(provider)
}

pub fn token_provider_is_valid_name(provider: &str) -> bool {
    is_valid_provider_name(provider)
}

pub fn token_source_is_reacquirable<S>(record: &BindingRecord, secret_store: &S) -> Result<bool>
where
    S: SecretStore,
{
    token_source_is_reacquirable_with_mode(record, secret_store, TokenSourceReadMode::Normal)
}

pub fn token_source_is_reacquirable_for_inspection<S>(
    record: &BindingRecord,
    secret_store: &S,
) -> Result<bool>
where
    S: SecretStore,
{
    token_source_is_reacquirable_with_mode(record, secret_store, TokenSourceReadMode::Inspection)
}

fn token_source_is_reacquirable_with_mode<S>(
    record: &BindingRecord,
    secret_store: &S,
    read_mode: TokenSourceReadMode,
) -> Result<bool>
where
    S: SecretStore,
{
    let token_source = binding_token_source_with_mode(record, secret_store, read_mode)?;
    Ok(match token_source {
        Some(BindingTokenSource::Command {
            command, prepared, ..
        }) => prepared || resolve_token_source_command(&command).is_ok(),
        Some(BindingTokenSource::Provider {
            provider,
            handle,
            adapter,
            ..
        }) => match adapter {
            Some(_) => true,
            None if read_mode == TokenSourceReadMode::Inspection => {
                has_prepared_token_source_state(&record.id, secret_store)?
            }
            None => prepare_provider_adapter_state(&provider, handle.as_deref())
                .map(|prepared| prepared.is_some())
                .unwrap_or(false),
        },
        None => false,
    })
}

pub fn clear_token_source_state<S>(binding_id: &BindingId, secret_store: &S) -> Result<()>
where
    S: SecretStore,
{
    apply_token_source_artifacts(
        binding_id,
        &TokenSourceArtifactsSnapshot {
            state: None,
            prepared: false,
        },
        secret_store,
    )
}

pub fn snapshot_token_source_state<S>(
    binding_id: &BindingId,
    secret_store: &S,
) -> Result<Option<String>>
where
    S: SecretStore,
{
    secret_store
        .get(&token_source_state_id(binding_id))
        .map_err(Into::into)
}

pub fn snapshot_token_source_artifacts<S>(
    binding_id: &BindingId,
    secret_store: &S,
) -> Result<TokenSourceArtifactsSnapshot>
where
    S: SecretStore,
{
    Ok(TokenSourceArtifactsSnapshot {
        state: snapshot_token_source_state(binding_id, secret_store)?,
        prepared: has_prepared_token_source_state(binding_id, secret_store)?,
    })
}

pub fn restore_token_source_state<S>(
    binding_id: &BindingId,
    previous_state: Option<&str>,
    secret_store: &S,
) -> Result<()>
where
    S: SecretStore,
{
    match previous_state {
        Some(state) => secret_store.set(&token_source_state_id(binding_id), state)?,
        None => {
            let _ = secret_store.delete(&token_source_state_id(binding_id))?;
        }
    }
    Ok(())
}

pub fn restore_token_source_artifacts<S>(
    binding_id: &BindingId,
    previous_state: &TokenSourceArtifactsSnapshot,
    secret_store: &S,
) -> Result<()>
where
    S: SecretStore,
{
    apply_token_source_artifacts(binding_id, previous_state, secret_store)
}

pub(crate) fn apply_pending_secret_updates<S>(
    updates: &[PendingManagedSecretUpdate],
    secret_store: &S,
) -> Result<()>
where
    S: SecretStore,
{
    let previous_secrets = updates
        .iter()
        .map(|update| Ok((update.id.clone(), secret_store.get(&update.id)?)))
        .collect::<Result<Vec<_>>>()?;
    let previous_token_source_states = updates
        .iter()
        .map(|update| {
            Ok((
                update.id.clone(),
                snapshot_token_source_artifacts(&update.id, secret_store)?,
            ))
        })
        .collect::<Result<Vec<_>>>()?;

    for update in updates {
        if let Err(error) = apply_pending_secret_update(update, secret_store) {
            for (id, secret) in &previous_secrets {
                restore_previous_secret(secret_store, id, secret.as_deref())?;
            }
            for (id, token_source_state) in &previous_token_source_states {
                restore_token_source_artifacts(id, token_source_state, secret_store)?;
            }
            return Err(error);
        }
    }

    Ok(())
}

fn binding_token_source<S>(
    record: &BindingRecord,
    secret_store: &S,
) -> Result<Option<BindingTokenSource>>
where
    S: SecretStore,
{
    binding_token_source_with_mode(record, secret_store, TokenSourceReadMode::Normal)
}

fn binding_token_source_with_mode<S>(
    record: &BindingRecord,
    secret_store: &S,
    read_mode: TokenSourceReadMode,
) -> Result<Option<BindingTokenSource>>
where
    S: SecretStore,
{
    if let Some(provider) = record.metadata.get(TOKEN_PROVIDER_KEY) {
        return load_token_source_state(record, secret_store, read_mode).map(|state| {
            state.and_then(|state| match state {
                BindingTokenSource::Command { .. } => Some(state),
                BindingTokenSource::Provider {
                    provider: ref state_provider,
                    ..
                } if state_provider == provider => Some(state),
                BindingTokenSource::Provider { .. } => None,
            })
        });
    }

    if let Some(legacy) = record.metadata.get(LEGACY_TOKEN_SOURCE_KEY) {
        if let Some(state) = load_token_source_state_by_id(&record.id, secret_store, read_mode)? {
            return Ok(Some(state));
        }
        return binding_token_source_from_legacy_spec(legacy);
    }

    if let Some(_state) = load_token_source_state_by_id(&record.id, secret_store, read_mode)? {
        return Err(anyhow!(
            "binding `{}` has persisted token source state without binding metadata",
            record.label
        ));
    }

    Ok(None)
}

fn load_token_source_state<S>(
    record: &BindingRecord,
    secret_store: &S,
    read_mode: TokenSourceReadMode,
) -> Result<Option<BindingTokenSource>>
where
    S: SecretStore,
{
    let Some(expected_provider) = record.metadata.get(TOKEN_PROVIDER_KEY) else {
        return Ok(None);
    };
    let Some(raw_state) = secret_store.get(&token_source_state_id(&record.id))? else {
        return Err(anyhow!(
            "binding `{}` has token source metadata but its persisted token source state is missing",
            record.label
        ));
    };
    if raw_state == REDACTED_PLACEHOLDER {
        return Ok(match (expected_provider.as_str(), read_mode) {
            (COMMAND_TOKEN_PROVIDER, _) => Some(BindingTokenSource::Command {
                command: raw_state,
                prepared: true,
                needs_persist: false,
            }),
            (_, TokenSourceReadMode::Inspection) => Some(BindingTokenSource::Provider {
                provider: expected_provider.clone(),
                handle: None,
                adapter: None,
                needs_persist: false,
            }),
            _ => None,
        });
    }
    if !raw_state.trim_start().starts_with('{') {
        return Err(anyhow!(
            "binding `{}` has token source metadata but its persisted token source state is in an unsupported legacy format",
            record.label
        ));
    }
    let Some(state) = load_token_source_state_by_id_from_value(raw_state)? else {
        return Err(anyhow!(
            "binding `{}` has token source metadata but its persisted token source state is unreadable",
            record.label
        ));
    };
    match (&state, expected_provider.as_str()) {
        (BindingTokenSource::Command { .. }, COMMAND_TOKEN_PROVIDER) => Ok(Some(state)),
        (
            BindingTokenSource::Provider {
                provider: state_provider,
                ..
            },
            metadata_provider,
        ) if state_provider == metadata_provider => Ok(Some(state)),
        _ => Err(anyhow!(
            "binding `{}` has token source metadata that does not match its persisted token source state",
            record.label
        )),
    }
}

fn load_token_source_state_by_id<S>(
    binding_id: &BindingId,
    secret_store: &S,
    _read_mode: TokenSourceReadMode,
) -> Result<Option<BindingTokenSource>>
where
    S: SecretStore,
{
    let Some(state) = secret_store.get(&token_source_state_id(binding_id))? else {
        return Ok(None);
    };
    if state != REDACTED_PLACEHOLDER
        && !state.trim_start().starts_with('{')
        && !has_prepared_token_source_state(binding_id, secret_store)?
    {
        return Err(anyhow!(
            "binding `{binding_id:?}` has legacy token source state without a prepared marker"
        ));
    }
    load_token_source_state_by_id_from_value(state)
}

fn load_token_source_state_by_id_from_value(state: String) -> Result<Option<BindingTokenSource>> {
    if state == REDACTED_PLACEHOLDER {
        return Ok(Some(BindingTokenSource::Command {
            command: state,
            prepared: true,
            needs_persist: false,
        }));
    }
    if !state.trim_start().starts_with('{') {
        return Ok(Some(parse_legacy_prepared_command_state(&state)?));
    }
    let parsed: StoredTokenSourceState = serde_json::from_str(&state)?;
    Ok(Some(match parsed {
        StoredTokenSourceState::Command { canonical } => BindingTokenSource::Command {
            command: canonical,
            prepared: true,
            needs_persist: false,
        },
        StoredTokenSourceState::Provider {
            provider,
            handle,
            adapter,
        } => {
            let needs_persist = adapter.is_none();
            BindingTokenSource::Provider {
                provider,
                handle,
                adapter,
                needs_persist,
            }
        }
    }))
}

fn parse_legacy_prepared_command_state(state: &str) -> Result<BindingTokenSource> {
    let tokens = shlex::split(state)
        .ok_or_else(|| anyhow!("legacy prepared token source state is not valid shell syntax"))?;
    let (program, args) = tokens
        .split_first()
        .ok_or_else(|| anyhow!("legacy prepared token source state is empty"))?;
    let path = PathBuf::from(program);
    if !path.is_absolute() {
        return Err(anyhow!(
            "legacy prepared token source state must use an absolute canonical program path"
        ));
    }
    let canonical = serialize_token_source(&TokenSourceCommand {
        program: normalize_program_path(&path)?,
        args: args.to_vec(),
    });
    if canonical != state {
        return Err(anyhow!(
            "legacy prepared token source state is not in canonical direct-exec form"
        ));
    }
    Ok(BindingTokenSource::Command {
        command: state.to_string(),
        prepared: true,
        needs_persist: false,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TokenSourceKind {
    Command {
        program_hint: String,
    },
    Provider {
        provider: String,
        handle: Option<String>,
    },
}

fn classify_token_source_spec(spec: &str) -> Result<TokenSourceKind> {
    if let Some(command) = spec.strip_prefix(COMMAND_PREFIX) {
        let tokens =
            shlex::split(command).ok_or_else(|| anyhow!("invalid token source: {spec}"))?;
        let token = tokens
            .first()
            .ok_or_else(|| anyhow!("token source command is empty"))?;
        return Ok(TokenSourceKind::Command {
            program_hint: token.clone(),
        });
    }
    if let Some(provider_spec) = spec.strip_prefix(PROVIDER_PREFIX) {
        return parse_provider_kind(provider_spec);
    }

    let tokens = shlex::split(spec).ok_or_else(|| anyhow!("invalid token source: {spec}"))?;
    let token = tokens
        .first()
        .ok_or_else(|| anyhow!("token source command is empty"))?;
    if tokens.len() > 1 || looks_like_path(token) {
        return Ok(TokenSourceKind::Command {
            program_hint: token.clone(),
        });
    }
    if provider_supports_direct_acquisition(token) {
        return Ok(TokenSourceKind::Provider {
            provider: token.clone(),
            handle: None,
        });
    }
    if resolve_token_source_command(spec).is_ok() {
        return Ok(TokenSourceKind::Command {
            program_hint: token.clone(),
        });
    }
    parse_provider_kind(token)
}

fn binding_token_source_from_legacy_spec(spec: &str) -> Result<Option<BindingTokenSource>> {
    if let Some(command) = spec.strip_prefix(COMMAND_PREFIX) {
        return Ok(Some(BindingTokenSource::Command {
            command: command.to_string(),
            prepared: false,
            needs_persist: true,
        }));
    }
    if let Some(provider_spec) = spec.strip_prefix(PROVIDER_PREFIX) {
        let TokenSourceKind::Provider { provider, handle } = parse_provider_kind(provider_spec)?
        else {
            unreachable!("provider prefix must parse as provider");
        };
        return Ok(Some(BindingTokenSource::Provider {
            provider,
            handle,
            adapter: None,
            needs_persist: true,
        }));
    }

    let tokens = shlex::split(spec).ok_or_else(|| anyhow!("invalid token source: {spec}"))?;
    let token = tokens
        .first()
        .ok_or_else(|| anyhow!("token source command is empty"))?;
    if tokens.len() == 1 && !looks_like_path(token) && is_valid_provider_name(token) {
        return Err(anyhow!(
            "binding uses ambiguous legacy bare token source `{spec}`; repair it by rewriting the binding to use `command:{spec}` or `provider:{spec}`"
        ));
    }
    Ok(Some(BindingTokenSource::Command {
        command: spec.to_string(),
        prepared: false,
        needs_persist: true,
    }))
}

fn display_token_source_spec(spec: &str) -> Result<String> {
    match classify_token_source_spec(spec)? {
        TokenSourceKind::Command { program_hint } => {
            let name = Path::new(&program_hint)
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("command");
            Ok(format!("command:{name}#{}", command_handle(spec)))
        }
        TokenSourceKind::Provider { provider, handle } => {
            Ok(provider_display(&provider, handle.as_deref()))
        }
    }
}

fn display_legacy_token_source_spec(spec: &str) -> Result<String> {
    match binding_token_source_from_legacy_spec(spec)? {
        Some(BindingTokenSource::Command { command, .. }) => {
            let tokens =
                shlex::split(&command).ok_or_else(|| anyhow!("invalid token source: {spec}"))?;
            let token = tokens
                .first()
                .ok_or_else(|| anyhow!("token source command is empty"))?;
            let name = Path::new(token)
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("command");
            Ok(format!("command:{name}#{}", command_handle(&command)))
        }
        Some(BindingTokenSource::Provider {
            provider, handle, ..
        }) => Ok(provider_display(&provider, handle.as_deref())),
        None => Err(anyhow!("missing token source")),
    }
}

fn parse_token_source_spec(spec: &str) -> Result<TokenSourceSpec> {
    if let Some(command) = spec.strip_prefix(COMMAND_PREFIX) {
        let canonical = canonicalize_command_spec(command)?;
        let handle = command_handle(&canonical);
        let display =
            command_display(&canonical, &handle).unwrap_or_else(|| format!("command:{handle}"));
        return Ok(TokenSourceSpec::Command {
            canonical,
            handle,
            display,
        });
    }
    if let Some(provider_spec) = spec.strip_prefix(PROVIDER_PREFIX) {
        let TokenSourceKind::Provider { provider, handle } = parse_provider_kind(provider_spec)?
        else {
            unreachable!("provider prefix must parse as provider");
        };
        return Ok(TokenSourceSpec::Provider { provider, handle });
    }

    let tokens = shlex::split(spec).ok_or_else(|| anyhow!("invalid token source: {spec}"))?;
    let token = tokens
        .first()
        .ok_or_else(|| anyhow!("token source command is empty"))?;
    if tokens.len() > 1 || looks_like_path(token) {
        let canonical = canonicalize_command_spec(spec)?;
        let handle = command_handle(&canonical);
        let display =
            command_display(&canonical, &handle).unwrap_or_else(|| format!("command:{handle}"));
        return Ok(TokenSourceSpec::Command {
            canonical,
            handle,
            display,
        });
    }

    if provider_supports_direct_acquisition(token) {
        return Ok(TokenSourceSpec::Provider {
            provider: token.clone(),
            handle: None,
        });
    }
    if resolve_token_source_command(spec).is_ok() {
        let canonical = canonicalize_command_spec(spec)?;
        let handle = command_handle(&canonical);
        let display =
            command_display(&canonical, &handle).unwrap_or_else(|| format!("command:{handle}"));
        return Ok(TokenSourceSpec::Command {
            canonical,
            handle,
            display,
        });
    }

    let TokenSourceKind::Provider { provider, handle } = parse_provider_kind(token)? else {
        unreachable!("fallback must parse as provider");
    };
    Ok(TokenSourceSpec::Provider { provider, handle })
}

fn canonicalize_command_spec(spec: &str) -> Result<String> {
    let command = resolve_token_source_command(spec)?;
    Ok(serialize_token_source(&command))
}

fn command_handle(canonical: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    let digest = hasher.finalize();
    format!("{:x}", digest)[..12].to_string()
}

fn command_display(canonical: &str, handle: &str) -> Option<String> {
    let command = resolve_token_source_command(canonical).ok()?;
    let name = command
        .program
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("command");
    Some(format!("command:{name}#{handle}"))
}

fn provider_display(provider: &str, handle: Option<&str>) -> String {
    let _ = handle;
    provider.to_string()
}

fn parse_provider_kind(spec: &str) -> Result<TokenSourceKind> {
    let (provider, handle) = spec
        .split_once(':')
        .map_or((spec, None), |(provider, handle)| {
            let value = (!handle.is_empty()).then_some(handle.to_string());
            (provider, value)
        });
    if !is_valid_provider_name(provider) {
        return Err(anyhow!("invalid token source provider: {provider}"));
    }
    Ok(TokenSourceKind::Provider {
        provider: provider.to_string(),
        handle,
    })
}

fn runtime_provider_adapter(provider: &str) -> Option<RuntimeProviderAdapter> {
    match provider {
        "sso-jwt" => Some(RuntimeProviderAdapter::SsoJwt),
        _ => None,
    }
}

fn provider_supports_direct_acquisition(provider: &str) -> bool {
    runtime_provider_adapter_ops(provider)
        .and_then(|ops| (ops.prepare)(provider, None).ok())
        .flatten()
        .is_some()
}

fn prepare_provider_adapter_state(
    provider: &str,
    handle: Option<&str>,
) -> Result<Option<StoredProviderAdapterState>> {
    runtime_provider_adapter_ops(provider)
        .map(|ops| (ops.prepare)(provider, handle))
        .transpose()
        .map(|prepared| prepared.flatten())
}

fn acquire_secret_from_provider_adapter(adapter: &StoredProviderAdapterState) -> Result<String> {
    (runtime_provider_adapter_ops_for_state(adapter).acquire)(adapter)
}

fn prepared_provider_artifacts(
    provider: &str,
    handle: Option<&str>,
    adapter: &StoredProviderAdapterState,
) -> TokenSourceArtifactsSnapshot {
    TokenSourceArtifactsSnapshot {
        state: Some(
            serde_json::to_string(&StoredTokenSourceState::Provider {
                provider: provider.to_string(),
                handle: handle.map(ToOwned::to_owned),
                adapter: Some(adapter.clone()),
            })
            .expect("provider token source state should serialize"),
        ),
        prepared: true,
    }
}

fn prepared_command_artifacts(canonical: &str) -> TokenSourceArtifactsSnapshot {
    TokenSourceArtifactsSnapshot {
        state: Some(
            serde_json::to_string(&StoredTokenSourceState::Command {
                canonical: canonical.to_string(),
            })
            .expect("command token source state should serialize"),
        ),
        prepared: true,
    }
}

fn build_token_source_update(spec: &str) -> Result<TokenSourceUpdate> {
    match parse_token_source_spec(spec)? {
        TokenSourceSpec::Command {
            canonical, display, ..
        } => Ok(TokenSourceUpdate {
            metadata: TokenSourceMetadataUpdate {
                provider: COMMAND_TOKEN_PROVIDER.to_string(),
                display,
            },
            artifacts: TokenSourceArtifactsSnapshot {
                state: Some(serde_json::to_string(&StoredTokenSourceState::Command {
                    canonical,
                })?),
                prepared: true,
            },
        }),
        TokenSourceSpec::Provider { provider, handle } => {
            let artifacts = match prepare_provider_adapter_state(&provider, handle.as_deref()) {
                Ok(Some(adapter)) => TokenSourceArtifactsSnapshot {
                    state: Some(serde_json::to_string(&StoredTokenSourceState::Provider {
                        provider: provider.clone(),
                        handle,
                        adapter: Some(adapter),
                    })?),
                    prepared: true,
                },
                Ok(None) | Err(_) => TokenSourceArtifactsSnapshot {
                    state: Some(serde_json::to_string(&StoredTokenSourceState::Provider {
                        provider: provider.clone(),
                        handle,
                        adapter: None,
                    })?),
                    prepared: false,
                },
            };
            Ok(TokenSourceUpdate {
                metadata: TokenSourceMetadataUpdate {
                    provider: provider.clone(),
                    display: provider,
                },
                artifacts,
            })
        }
    }
}

fn apply_token_source_metadata_update(
    record: &mut BindingRecord,
    update: &TokenSourceMetadataUpdate,
) {
    record
        .metadata
        .insert(TOKEN_PROVIDER_KEY.to_string(), update.provider.clone());
    record
        .metadata
        .insert(TOKEN_DISPLAY_KEY.to_string(), update.display.clone());
    record.metadata.remove(TOKEN_HANDLE_KEY);
    record.metadata.remove(LEGACY_TOKEN_SOURCE_KEY);
}

fn apply_token_source_artifacts<S>(
    binding_id: &BindingId,
    desired: &TokenSourceArtifactsSnapshot,
    secret_store: &S,
) -> Result<()>
where
    S: SecretStore,
{
    let previous = snapshot_token_source_artifacts(binding_id, secret_store)?;
    if let Err(error) = write_token_source_artifacts(binding_id, desired, secret_store) {
        if let Err(rollback_error) =
            write_token_source_artifacts(binding_id, &previous, secret_store)
        {
            return Err(anyhow!(
                "{error}; additionally failed to restore previous token source artifacts: {rollback_error}"
            ));
        }
        return Err(error);
    }
    Ok(())
}

fn apply_pending_secret_update<S>(
    update: &PendingManagedSecretUpdate,
    secret_store: &S,
) -> Result<()>
where
    S: SecretStore,
{
    if let Some(artifacts) = &update.token_source_artifacts {
        apply_token_source_artifacts(&update.id, artifacts, secret_store)?;
    }
    secret_store.set(&update.id, &update.secret)?;
    Ok(())
}

fn write_token_source_artifacts<S>(
    binding_id: &BindingId,
    desired: &TokenSourceArtifactsSnapshot,
    secret_store: &S,
) -> Result<()>
where
    S: SecretStore,
{
    restore_token_source_state(binding_id, desired.state.as_deref(), secret_store)?;
    if desired.prepared {
        set_token_source_prepared_marker(binding_id, secret_store)?;
    } else {
        clear_token_source_prepared_marker(binding_id, secret_store)?;
    }
    Ok(())
}

pub fn prepare_token_source_metadata<S>(
    record: &mut BindingRecord,
    spec: &str,
    secret_store: &S,
) -> Result<()>
where
    S: SecretStore,
{
    let update = build_token_source_update(spec)?;
    apply_token_source_artifacts(&record.id, &update.artifacts, secret_store)?;
    apply_token_source_metadata_update(record, &update.metadata);
    Ok(())
}

fn prepare_sso_jwt_provider_state(
    _provider: &str,
    handle: Option<&str>,
) -> Result<Option<StoredProviderAdapterState>> {
    prepare_sso_jwt_provider_adapter(handle).map(Some)
}

fn prepare_sso_jwt_provider_adapter(handle: Option<&str>) -> Result<StoredProviderAdapterState> {
    let explicit_path = std::env::var_os("NPMENC_TOKEN_PROVIDER_SSO_JWT_BIN").map(PathBuf::from);
    let resolved = resolve_program(
        "sso-jwt",
        &ResolveOptions {
            explicit_path,
            mode: ResolveMode::Auto,
            shell: None,
        },
    )
    .map_err(anyhow::Error::from)?;
    let mut args = resolved.fixed_args;
    let (server, environment) = handle.map_or((None, None), parse_sso_jwt_handle);
    if let Some(server) = server {
        args.push("--server".to_string());
        args.push(server.to_string());
    }
    if let Some(environment) = environment {
        args.push("--environment".to_string());
        args.push(environment.to_string());
    }
    let canonical_command = serialize_token_source(&TokenSourceCommand {
        program: normalize_program_path(&resolved.path)?,
        args,
    });
    Ok(StoredProviderAdapterState::SsoJwt {
        canonical_command,
        server: server.map(ToOwned::to_owned),
        environment: environment.map(ToOwned::to_owned),
    })
}

fn acquire_secret_from_sso_jwt_adapter(adapter: &StoredProviderAdapterState) -> Result<String> {
    let StoredProviderAdapterState::SsoJwt {
        canonical_command, ..
    } = adapter
    else {
        unreachable!("sso-jwt acquisition requires SsoJwt state");
    };
    acquire_secret_from_command_spec(canonical_command)
}

fn prepare_generic_provider_state(
    provider: &str,
    handle: Option<&str>,
) -> Result<Option<StoredProviderAdapterState>> {
    let env_name = generic_provider_env_name(provider);
    let Some(explicit) = std::env::var_os(&env_name) else {
        return Ok(None);
    };
    let explicit_path = PathBuf::from(explicit);
    let program = explicit_path.to_string_lossy().into_owned();
    let resolved = resolve_program(
        &program,
        &ResolveOptions {
            explicit_path: Some(explicit_path),
            mode: ResolveMode::Auto,
            shell: None,
        },
    )
    .map_err(anyhow::Error::from)?;
    let canonical_command = serialize_token_source(&TokenSourceCommand {
        program: normalize_program_path(&resolved.path)?,
        args: resolved.fixed_args,
    });
    Ok(Some(StoredProviderAdapterState::GenericCommand {
        provider: provider.to_string(),
        canonical_command,
        handle: handle.map(ToOwned::to_owned),
    }))
}

fn acquire_secret_from_generic_provider_adapter(
    adapter: &StoredProviderAdapterState,
) -> Result<String> {
    let StoredProviderAdapterState::GenericCommand {
        provider,
        canonical_command,
        ..
    } = adapter
    else {
        unreachable!("generic provider acquisition requires GenericCommand state");
    };
    let handle = match adapter {
        StoredProviderAdapterState::GenericCommand { handle, .. } => handle.as_deref(),
        _ => None,
    };
    acquire_secret_from_command_with_env(
        resolve_token_source_command(canonical_command)?,
        &generic_provider_request_env(provider, handle)?,
    )
}

fn runtime_provider_adapter_ops(provider: &str) -> Option<&'static RuntimeProviderAdapterOps> {
    match runtime_provider_adapter(provider) {
        Some(RuntimeProviderAdapter::SsoJwt) => Some(&SSO_JWT_PROVIDER_ADAPTER_OPS),
        None => Some(&GENERIC_PROVIDER_ADAPTER_OPS),
    }
}

fn runtime_provider_adapter_ops_for_state(
    adapter: &StoredProviderAdapterState,
) -> &'static RuntimeProviderAdapterOps {
    match adapter {
        StoredProviderAdapterState::SsoJwt { .. } => &SSO_JWT_PROVIDER_ADAPTER_OPS,
        StoredProviderAdapterState::GenericCommand { .. } => &GENERIC_PROVIDER_ADAPTER_OPS,
    }
}

fn generic_provider_env_name(provider: &str) -> String {
    let suffix = provider
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect::<String>();
    let digest = Sha256::digest(provider.as_bytes());
    let hash = digest[..6]
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<String>();
    format!("NPMENC_TOKEN_PROVIDER_{suffix}_{hash}_BIN")
}

fn generic_provider_request_env(
    provider: &str,
    handle: Option<&str>,
) -> Result<Vec<(String, String)>> {
    let request = serde_json::json!({
        "provider": provider,
        "handle": handle,
    });
    Ok(vec![
        (
            "NPMENC_TOKEN_PROVIDER_PROTOCOL".to_string(),
            "v1".to_string(),
        ),
        (
            "NPMENC_TOKEN_PROVIDER_REQUEST_JSON".to_string(),
            serde_json::to_string(&request)?,
        ),
    ])
}

fn parse_sso_jwt_handle(handle: &str) -> (Option<&str>, Option<&str>) {
    let trimmed = handle.trim();
    if trimmed.is_empty() {
        return (None, None);
    }
    match trimmed.split_once('/') {
        Some((server, environment)) => {
            let server = (!server.is_empty()).then_some(server);
            let environment = (!environment.is_empty()).then_some(environment);
            (server, environment)
        }
        None => (Some(trimmed), None),
    }
}

fn is_valid_provider_name(provider: &str) -> bool {
    !provider.is_empty()
        && provider
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
}

fn token_source_state_id(binding_id: &BindingId) -> BindingId {
    BindingId::new(format!("{}:token-source", binding_id.as_str()))
}

fn token_source_prepared_id(binding_id: &BindingId) -> BindingId {
    BindingId::new(format!("{}:token-source-prepared", binding_id.as_str()))
}

fn has_prepared_token_source_state<S>(binding_id: &BindingId, secret_store: &S) -> Result<bool>
where
    S: SecretStore,
{
    Ok(secret_store
        .get(&token_source_prepared_id(binding_id))
        .map_err(anyhow::Error::from)?
        .is_some())
}

fn set_token_source_prepared_marker<S>(binding_id: &BindingId, secret_store: &S) -> Result<()>
where
    S: SecretStore,
{
    secret_store.set(
        &token_source_prepared_id(binding_id),
        TOKEN_SOURCE_PREPARED_MARKER,
    )?;
    Ok(())
}

fn clear_token_source_prepared_marker<S>(binding_id: &BindingId, secret_store: &S) -> Result<()>
where
    S: SecretStore,
{
    let _ = secret_store.delete(&token_source_prepared_id(binding_id))?;
    Ok(())
}

fn resolve_token_source_command(spec: &str) -> Result<TokenSourceCommand> {
    let tokens = shlex::split(spec).ok_or_else(|| anyhow!("invalid token source: {spec}"))?;
    let (program, args) = tokens
        .split_first()
        .ok_or_else(|| anyhow!("token source command is empty"))?;
    let explicit_path = looks_like_path(program).then(|| PathBuf::from(program));
    let resolved = resolve_program(
        program,
        &ResolveOptions {
            explicit_path,
            mode: ResolveMode::Auto,
            shell: None,
        },
    )
    .map_err(anyhow::Error::from)?;

    let mut resolved_args = resolved.fixed_args;
    resolved_args.extend(args.iter().cloned());
    Ok(TokenSourceCommand {
        program: normalize_program_path(&resolved.path)?,
        args: resolved_args,
    })
}

fn acquire_secret_from_command_spec(spec: &str) -> Result<String> {
    acquire_secret_from_command(resolve_token_source_command(spec)?)
}

fn acquire_secret_from_command(command: TokenSourceCommand) -> Result<String> {
    acquire_secret_from_command_with_env(command, &[])
}

fn acquire_secret_from_command_with_env(
    command: TokenSourceCommand,
    env_overrides: &[(String, String)],
) -> Result<String> {
    let mut process = Command::new(&command.program);
    process.args(&command.args);
    for (key, value) in env_overrides {
        process.env(key, value);
    }
    let output = process.output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        if stderr.is_empty() {
            return Err(anyhow!(
                "token source `{}` exited with {}",
                serialize_token_source(&command),
                output.status
            ));
        }
        return Err(anyhow!(
            "token source `{}` exited with {}: {stderr}",
            serialize_token_source(&command),
            output.status
        ));
    }

    let token = String::from_utf8(output.stdout).map_err(|error| {
        anyhow!(
            "token source `{}` returned invalid UTF-8: {error}",
            serialize_token_source(&command)
        )
    })?;
    let token = token.trim_end_matches(['\r', '\n']).to_string();
    if token.is_empty() {
        return Err(anyhow!(
            "token source `{}` produced an empty secret",
            serialize_token_source(&command)
        ));
    }

    Ok(token)
}

fn looks_like_path(program: &str) -> bool {
    let path = PathBuf::from(program);
    path.is_absolute() || program.contains(std::path::MAIN_SEPARATOR) || program.starts_with('.')
}

fn serialize_token_source(command: &TokenSourceCommand) -> String {
    let mut parts = Vec::with_capacity(command.args.len() + 1);
    parts.push(command.program.to_string_lossy().into_owned());
    parts.extend(command.args.iter().cloned());
    parts
        .into_iter()
        .map(|part| match shlex::try_quote(&part) {
            Ok(quoted) => quoted.into_owned(),
            Err(_) => part,
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn normalize_program_path(path: &Path) -> Result<PathBuf> {
    if path.exists() {
        return Ok(fs::canonicalize(path)?);
    }

    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }

    Ok(std::env::current_dir()?.join(path))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    use enclaveapp_app_adapter::MemorySecretStore;
    use tempfile::TempDir;

    use super::*;
    use crate::test_support::lock_env;

    #[test]
    fn acquires_secret_from_command_stdout() {
        let dir = TempDir::new().expect("temp dir");
        let script = dir.path().join("source-token");
        fs::write(&script, "#!/bin/sh\nprintf 'token-from-source\\n'\n").expect("write");
        let mut perms = fs::metadata(&script).expect("metadata").permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&script, perms).expect("chmod");

        let token = acquire_secret_from_token_source(&script.to_string_lossy()).expect("token");
        assert_eq!(token, "token-from-source");
    }

    #[test]
    fn canonicalizes_token_source_to_direct_exec_handle() {
        let dir = TempDir::new().expect("temp dir");
        let script = dir.path().join("source-token");
        fs::write(&script, "#!/bin/sh\nprintf 'token-from-source\\n'\n").expect("write");
        let mut perms = fs::metadata(&script).expect("metadata").permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&script, perms).expect("chmod");

        let canonical = canonicalize_token_source(&script.to_string_lossy()).expect("canonical");
        assert_eq!(
            canonical,
            shlex::try_quote(&script.to_string_lossy())
                .expect("quoted")
                .into_owned()
        );
    }

    #[test]
    fn stores_command_token_source_as_safe_metadata_and_encrypted_payload() {
        let dir = TempDir::new().expect("temp dir");
        let script = dir.path().join("source-token");
        fs::write(&script, "#!/bin/sh\nprintf 'token-from-source\\n'\n").expect("write");
        let mut perms = fs::metadata(&script).expect("metadata").permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&script, perms).expect("chmod");

        let secrets = MemorySecretStore::new();
        let mut record = BindingRecord {
            id: BindingId::new("npm:default"),
            label: "default".to_string(),
            target: "https://registry.npmjs.org/".to_string(),
            secret_env_var: "NPM_TOKEN_DEFAULT".to_string(),
            metadata: Default::default(),
        };
        set_token_source_metadata(&mut record, &script.to_string_lossy(), &secrets)
            .expect("set metadata");

        assert_eq!(
            record.metadata.get(TOKEN_PROVIDER_KEY),
            Some(&"command".to_string())
        );
        assert_eq!(record.metadata.get(TOKEN_HANDLE_KEY), None);
        assert!(record.metadata[TOKEN_DISPLAY_KEY].starts_with("command:source-token#"));
        assert!(!record.metadata[TOKEN_DISPLAY_KEY].contains(&script.to_string_lossy().to_string()));
        assert_eq!(record.metadata.get(LEGACY_TOKEN_SOURCE_KEY), None);
        assert!(snapshot_token_source_state(&record.id, &secrets)
            .expect("snapshot")
            .is_some());
    }

    #[test]
    fn classifies_bare_token_source_as_provider_metadata() {
        let parsed = parse_token_source_spec("sso-jwt").expect("provider");
        assert!(matches!(
            parsed,
            TokenSourceSpec::Provider {
                provider,
                handle: None
            } if provider == "sso-jwt"
        ));
    }

    #[test]
    fn provider_display_is_safe() {
        assert_eq!(
            token_source_display_for_spec("sso-jwt:corp").expect("display"),
            "sso-jwt"
        );
    }

    #[test]
    fn normalize_cli_token_source_rejects_ambiguous_bare_single_token_specs() {
        let error = normalize_cli_token_source_spec("sso-jwt").expect_err("ambiguous");
        assert!(error.to_string().contains("ambiguous bare token source"));
    }

    #[test]
    fn normalize_cli_token_source_accepts_explicit_provider_specs() {
        assert_eq!(
            normalize_cli_token_source_spec("provider:sso-jwt:corp/prod").expect("normalized"),
            "provider:sso-jwt:corp/prod"
        );
    }

    #[test]
    fn normalize_cli_token_source_accepts_unambiguous_command_specs() {
        assert_eq!(
            normalize_cli_token_source_spec("/usr/local/bin/source-token").expect("normalized"),
            "/usr/local/bin/source-token"
        );
        assert_eq!(
            normalize_cli_token_source_spec("source-token --audience npm").expect("normalized"),
            "source-token --audience npm"
        );
    }

    #[test]
    fn provider_metadata_without_sidecar_is_reported_as_corrupt() {
        let secrets = MemorySecretStore::new();
        let mut record = binding_record();
        record
            .metadata
            .insert(TOKEN_PROVIDER_KEY.to_string(), "sso-jwt".to_string());
        record
            .metadata
            .insert(TOKEN_DISPLAY_KEY.to_string(), "sso-jwt".to_string());

        let reacquirable_error =
            token_source_is_reacquirable(&record, &secrets).expect_err("corrupt state");
        assert!(reacquirable_error
            .to_string()
            .contains("persisted token source state is missing"));

        let acquire_error =
            acquire_secret_from_binding_token_source(&record, &secrets).expect_err("corrupt state");
        assert!(acquire_error
            .to_string()
            .contains("persisted token source state is missing"));
    }

    #[test]
    fn supported_provider_descriptor_is_inactive_when_provider_is_unavailable() {
        let _env_lock = lock_env();
        let previous = std::env::var_os("NPMENC_TOKEN_PROVIDER_SSO_JWT_BIN");
        std::env::set_var("NPMENC_TOKEN_PROVIDER_SSO_JWT_BIN", "/definitely/missing");

        let secrets = MemorySecretStore::new();
        let mut record = binding_record();
        set_token_source_metadata(&mut record, "provider:sso-jwt:corp/prod", &secrets)
            .expect("store descriptor");

        let reacquirable = token_source_is_reacquirable(&record, &secrets).expect("reacquirable");

        match previous {
            Some(value) => std::env::set_var("NPMENC_TOKEN_PROVIDER_SSO_JWT_BIN", value),
            None => std::env::remove_var("NPMENC_TOKEN_PROVIDER_SSO_JWT_BIN"),
        }

        assert!(!reacquirable);
    }

    #[test]
    fn legacy_provider_descriptor_degrades_to_inactive_when_provider_is_unavailable() {
        let _env_lock = lock_env();
        let previous = std::env::var_os("NPMENC_TOKEN_PROVIDER_SSO_JWT_BIN");
        std::env::set_var("NPMENC_TOKEN_PROVIDER_SSO_JWT_BIN", "/definitely/missing");

        let secrets = MemorySecretStore::new();
        let mut record = binding_record();
        record.metadata.insert(
            LEGACY_TOKEN_SOURCE_KEY.to_string(),
            "provider:sso-jwt:corp/prod".to_string(),
        );

        let reacquirable = token_source_is_reacquirable(&record, &secrets).expect("reacquirable");

        match previous {
            Some(value) => std::env::set_var("NPMENC_TOKEN_PROVIDER_SSO_JWT_BIN", value),
            None => std::env::remove_var("NPMENC_TOKEN_PROVIDER_SSO_JWT_BIN"),
        }

        assert!(!reacquirable);
    }

    #[test]
    fn ambiguous_legacy_bare_provider_spec_is_reported_as_corrupt() {
        let _env_lock = lock_env();
        let dir = TempDir::new().expect("temp dir");
        let script = dir.path().join("sso-jwt");
        fs::write(&script, "#!/bin/sh\nprintf 'legacy-provider-token\\n'\n").expect("write");
        let mut perms = fs::metadata(&script).expect("metadata").permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&script, perms).expect("chmod");

        let previous = std::env::var_os("NPMENC_TOKEN_PROVIDER_SSO_JWT_BIN");
        std::env::set_var("NPMENC_TOKEN_PROVIDER_SSO_JWT_BIN", &script);

        let secrets = MemorySecretStore::new();
        let mut record = binding_record();
        record
            .metadata
            .insert(LEGACY_TOKEN_SOURCE_KEY.to_string(), "sso-jwt".to_string());

        let error = acquire_secret_from_binding_token_source(&record, &secrets)
            .expect_err("ambiguous legacy provider should fail");

        match previous {
            Some(value) => std::env::set_var("NPMENC_TOKEN_PROVIDER_SSO_JWT_BIN", value),
            None => std::env::remove_var("NPMENC_TOKEN_PROVIDER_SSO_JWT_BIN"),
        }

        assert!(error
            .to_string()
            .contains("ambiguous legacy bare token source"));
    }

    #[test]
    fn stores_provider_descriptor_even_when_not_directly_supported() {
        let secrets = MemorySecretStore::new();
        let mut record = binding_record();

        set_token_source_metadata(&mut record, "provider:unknown-provider:corp", &secrets)
            .expect("set metadata");

        let state = snapshot_token_source_state(&record.id, &secrets)
            .expect("snapshot")
            .expect("state");
        let parsed: StoredTokenSourceState = serde_json::from_str(&state).expect("parsed");
        assert_eq!(
            parsed,
            StoredTokenSourceState::Provider {
                provider: "unknown-provider".to_string(),
                handle: Some("corp".to_string()),
                adapter: None,
            }
        );
        assert_eq!(
            token_source_display(&record).expect("display"),
            Some("unknown-provider".to_string())
        );
        assert!(!token_source_is_reacquirable(&record, &secrets).expect("reacquirable"));
    }

    #[test]
    fn generic_provider_uses_env_contract_instead_of_handle_argv() {
        let _env_lock = lock_env();
        let dir = TempDir::new().expect("temp dir");
        let script = dir.path().join("corp-provider");
        fs::write(
            &script,
            "#!/bin/sh\npython3 - <<'PY'\nimport json, os\nrequest = json.loads(os.environ['NPMENC_TOKEN_PROVIDER_REQUEST_JSON'])\nprint(f\"{os.environ['NPMENC_TOKEN_PROVIDER_PROTOCOL']}|{request['provider']}|{request['handle']}\")\nPY\n",
        )
        .expect("write");
        let mut perms = fs::metadata(&script).expect("metadata").permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&script, perms).expect("chmod");

        let env_name = generic_provider_env_name("corp-provider");
        let previous = std::env::var_os(&env_name);
        std::env::set_var(&env_name, &script);

        let token =
            acquire_secret_from_token_source("provider:corp-provider:prod").expect("acquire");

        match previous {
            Some(value) => std::env::set_var(&env_name, value),
            None => std::env::remove_var(&env_name),
        }

        assert_eq!(token, "v1|corp-provider|prod");
    }

    #[test]
    fn ambiguous_legacy_bare_generic_provider_spec_is_reported_as_corrupt() {
        let _env_lock = lock_env();
        let dir = TempDir::new().expect("temp dir");
        let script = dir.path().join("corp-provider");
        fs::write(
            &script,
            "#!/bin/sh\npython3 - <<'PY'\nimport json, os\nrequest = json.loads(os.environ['NPMENC_TOKEN_PROVIDER_REQUEST_JSON'])\nprint(f\"{request['provider']}|{request['handle'] or ''}\")\nPY\n",
        )
        .expect("write");
        let mut perms = fs::metadata(&script).expect("metadata").permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&script, perms).expect("chmod");

        let env_name = generic_provider_env_name("corp-provider");
        let previous = std::env::var_os(&env_name);
        std::env::set_var(&env_name, &script);

        let secrets = MemorySecretStore::new();
        let mut record = binding_record();
        record.metadata.insert(
            LEGACY_TOKEN_SOURCE_KEY.to_string(),
            "corp-provider".to_string(),
        );

        let error = acquire_secret_from_binding_token_source(&record, &secrets)
            .expect_err("ambiguous legacy provider should fail");

        match previous {
            Some(value) => std::env::set_var(&env_name, value),
            None => std::env::remove_var(&env_name),
        }

        assert!(error
            .to_string()
            .contains("ambiguous legacy bare token source"));
    }

    #[test]
    fn token_source_display_reports_ambiguous_legacy_bare_provider_as_corrupt() {
        let mut record = binding_record();
        record
            .metadata
            .insert(LEGACY_TOKEN_SOURCE_KEY.to_string(), "sso-jwt".to_string());

        let error = token_source_display(&record).expect_err("display should fail");
        assert!(error
            .to_string()
            .contains("ambiguous legacy bare token source"));
    }

    #[test]
    fn legacy_raw_sidecar_without_prepared_marker_is_reported_as_corrupt() {
        let secrets = MemorySecretStore::new();
        let record = binding_record();
        secrets
            .set(
                &token_source_state_id(&record.id),
                "/usr/local/bin/source-token",
            )
            .expect("store raw state");

        let error = acquire_secret_from_binding_token_source(&record, &secrets)
            .expect_err("raw legacy state without prepared marker should fail");
        assert!(error
            .to_string()
            .contains("legacy token source state without a prepared marker"));
    }

    #[test]
    fn generic_provider_env_names_do_not_collide_for_different_provider_names() {
        assert_ne!(
            generic_provider_env_name("foo-bar"),
            generic_provider_env_name("foo_bar")
        );
    }

    #[test]
    fn prepare_token_source_metadata_persists_prepared_supported_provider_state() {
        let _env_lock = lock_env();
        let dir = TempDir::new().expect("temp dir");
        let script = dir.path().join("sso-jwt");
        fs::write(&script, "#!/bin/sh\nprintf 'provider-token\\n'\n").expect("write");
        let mut perms = fs::metadata(&script).expect("metadata").permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&script, perms).expect("chmod");

        let previous = std::env::var_os("NPMENC_TOKEN_PROVIDER_SSO_JWT_BIN");
        std::env::set_var("NPMENC_TOKEN_PROVIDER_SSO_JWT_BIN", &script);

        let secrets = MemorySecretStore::new();
        let mut record = binding_record();
        prepare_token_source_metadata(&mut record, "provider:sso-jwt:corp/prod", &secrets)
            .expect("prepare metadata");

        match previous {
            Some(value) => std::env::set_var("NPMENC_TOKEN_PROVIDER_SSO_JWT_BIN", value),
            None => std::env::remove_var("NPMENC_TOKEN_PROVIDER_SSO_JWT_BIN"),
        }

        let state = snapshot_token_source_state(&record.id, &secrets)
            .expect("snapshot")
            .expect("state");
        let parsed: StoredTokenSourceState = serde_json::from_str(&state).expect("parsed");
        assert!(matches!(
            parsed,
            StoredTokenSourceState::Provider {
                provider,
                handle,
                adapter: Some(StoredProviderAdapterState::SsoJwt { canonical_command, .. }),
            } if provider == "sso-jwt"
                && handle.as_deref() == Some("corp/prod")
                && canonical_command.contains(&script.to_string_lossy().to_string())
        ));
    }

    #[test]
    fn prepared_provider_state_reacquires_from_persisted_command() {
        let dir = TempDir::new().expect("temp dir");
        let script = dir.path().join("sso-jwt-prepared");
        fs::write(&script, "#!/bin/sh\nprintf 'prepared-provider-token\\n'\n").expect("write");
        let mut perms = fs::metadata(&script).expect("metadata").permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&script, perms).expect("chmod");

        let adapter = StoredProviderAdapterState::SsoJwt {
            canonical_command: shlex::try_quote(&script.to_string_lossy())
                .expect("quoted")
                .into_owned(),
            server: Some("corp".to_string()),
            environment: Some("prod".to_string()),
        };
        let state = serde_json::to_string(&StoredTokenSourceState::Provider {
            provider: "sso-jwt".to_string(),
            handle: Some("corp/prod".to_string()),
            adapter: Some(adapter),
        })
        .expect("state");
        let secrets = MemorySecretStore::new();
        let record = binding_record_with_provider("sso-jwt");
        secrets
            .set(&token_source_state_id(&record.id), &state)
            .expect("store state");

        assert!(token_source_is_reacquirable(&record, &secrets).expect("reacquirable"));
        assert_eq!(
            acquire_secret_from_binding_token_source(&record, &secrets).expect("acquire"),
            Some("prepared-provider-token".to_string())
        );
    }

    #[test]
    fn inspection_reacquires_redacted_provider_state_when_prepared_marker_exists() {
        let secrets = MemorySecretStore::new();
        let record = binding_record_with_provider("sso-jwt");
        secrets
            .set(&token_source_state_id(&record.id), REDACTED_PLACEHOLDER)
            .expect("state");
        secrets
            .set(
                &token_source_prepared_id(&record.id),
                TOKEN_SOURCE_PREPARED_MARKER,
            )
            .expect("marker");

        assert!(
            token_source_is_reacquirable_for_inspection(&record, &secrets)
                .expect("inspection reacquirable")
        );
    }

    #[test]
    fn legacy_command_source_converges_after_first_successful_acquisition() {
        let _env_lock = lock_env();
        let dir = TempDir::new().expect("temp dir");
        let bin1 = dir.path().join("bin1");
        let bin2 = dir.path().join("bin2");
        fs::create_dir_all(&bin1).expect("bin1");
        fs::create_dir_all(&bin2).expect("bin2");
        let helper1 = bin1.join("legacy-helper");
        let helper2 = bin2.join("legacy-helper");
        fs::write(&helper1, "#!/bin/sh\nprintf 'token-one\\n'\n").expect("write");
        fs::write(&helper2, "#!/bin/sh\nprintf 'token-two\\n'\n").expect("write");
        let mut perms = fs::metadata(&helper1).expect("metadata").permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&helper1, perms.clone()).expect("chmod1");
        fs::set_permissions(&helper2, perms).expect("chmod2");

        let previous_path = std::env::var_os("PATH");
        std::env::set_var("PATH", format!("{}:/usr/bin:/bin", bin1.display()));

        let secrets = MemorySecretStore::new();
        let mut record = binding_record();
        record.metadata.insert(
            LEGACY_TOKEN_SOURCE_KEY.to_string(),
            "command:legacy-helper".to_string(),
        );

        let first =
            acquire_secret_from_binding_token_source(&record, &secrets).expect("first acquire");
        assert_eq!(first.as_deref(), Some("token-one"));

        std::env::set_var("PATH", format!("{}:/usr/bin:/bin", bin2.display()));
        let second =
            acquire_secret_from_binding_token_source(&record, &secrets).expect("second acquire");

        match previous_path {
            Some(value) => std::env::set_var("PATH", value),
            None => std::env::remove_var("PATH"),
        }

        assert_eq!(second.as_deref(), Some("token-one"));
        let persisted = snapshot_token_source_state(&record.id, &secrets)
            .expect("snapshot")
            .expect("persisted");
        let parsed: StoredTokenSourceState = serde_json::from_str(&persisted).expect("parsed");
        assert!(matches!(
            parsed,
            StoredTokenSourceState::Command { canonical } if canonical.contains("legacy-helper")
        ));
    }

    #[test]
    fn legacy_command_metadata_uses_persisted_command_state_for_reacquirability() {
        let secrets = MemorySecretStore::new();
        let mut record = binding_record();
        record.metadata.insert(
            LEGACY_TOKEN_SOURCE_KEY.to_string(),
            "command:missing-helper".to_string(),
        );
        secrets
            .set(
                &token_source_state_id(&record.id),
                &serde_json::to_string(&StoredTokenSourceState::Command {
                    canonical: "/usr/bin/printf token".to_string(),
                })
                .expect("state"),
            )
            .expect("store state");

        assert!(token_source_is_reacquirable(&record, &secrets).expect("reacquirable"));
    }

    #[test]
    fn invalid_legacy_prepared_raw_command_state_is_reported_as_corrupt() {
        let secrets = MemorySecretStore::new();
        let record = binding_record();
        secrets
            .set(
                &token_source_state_id(&record.id),
                "relative-helper --token",
            )
            .expect("store raw state");
        secrets
            .set(
                &token_source_prepared_id(&record.id),
                TOKEN_SOURCE_PREPARED_MARKER,
            )
            .expect("marker");

        let error = acquire_secret_from_binding_token_source(&record, &secrets)
            .expect_err("invalid prepared raw state should fail");
        assert!(error
            .to_string()
            .contains("absolute canonical program path"));
    }

    #[cfg(unix)]
    #[test]
    fn noncanonical_legacy_prepared_raw_command_state_is_reported_as_corrupt() {
        use std::os::unix::fs::symlink;

        let dir = TempDir::new().expect("temp dir");
        let target = dir.path().join("source-token");
        let link = dir.path().join("source-token-link");
        fs::write(&target, "#!/bin/sh\nprintf 'token-from-source\\n'\n").expect("write");
        let mut perms = fs::metadata(&target).expect("metadata").permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&target, perms).expect("chmod");
        symlink(&target, &link).expect("symlink");

        let secrets = MemorySecretStore::new();
        let record = binding_record();
        secrets
            .set(
                &token_source_state_id(&record.id),
                &format!("{} --flag", link.display()),
            )
            .expect("store raw state");
        secrets
            .set(
                &token_source_prepared_id(&record.id),
                TOKEN_SOURCE_PREPARED_MARKER,
            )
            .expect("marker");

        let error = acquire_secret_from_binding_token_source(&record, &secrets)
            .expect_err("noncanonical prepared raw state should fail");
        assert!(error.to_string().contains("canonical direct-exec form"));
    }

    #[test]
    fn unprepared_provider_state_upgrades_to_prepared_state_after_acquisition() {
        let _env_lock = lock_env();
        let dir = TempDir::new().expect("temp dir");
        let script = dir.path().join("sso-jwt");
        fs::write(&script, "#!/bin/sh\nprintf 'upgraded-provider-token\\n'\n").expect("write");
        let mut perms = fs::metadata(&script).expect("metadata").permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&script, perms).expect("chmod");

        let previous = std::env::var_os("NPMENC_TOKEN_PROVIDER_SSO_JWT_BIN");
        std::env::set_var("NPMENC_TOKEN_PROVIDER_SSO_JWT_BIN", &script);

        let secrets = MemorySecretStore::new();
        let record = binding_record_with_provider("sso-jwt");
        let state = serde_json::to_string(&StoredTokenSourceState::Provider {
            provider: "sso-jwt".to_string(),
            handle: Some("corp/prod".to_string()),
            adapter: None,
        })
        .expect("state");
        secrets
            .set(&token_source_state_id(&record.id), &state)
            .expect("store state");

        let acquired =
            acquire_secret_from_binding_token_source(&record, &secrets).expect("acquire");
        match previous {
            Some(value) => std::env::set_var("NPMENC_TOKEN_PROVIDER_SSO_JWT_BIN", value),
            None => std::env::remove_var("NPMENC_TOKEN_PROVIDER_SSO_JWT_BIN"),
        }

        assert_eq!(acquired, Some("upgraded-provider-token".to_string()));
        let upgraded = snapshot_token_source_state(&record.id, &secrets)
            .expect("snapshot")
            .expect("upgraded state");
        let parsed: StoredTokenSourceState = serde_json::from_str(&upgraded).expect("parsed");
        assert!(matches!(
            &parsed,
            StoredTokenSourceState::Provider {
                provider,
                handle,
                adapter: Some(StoredProviderAdapterState::SsoJwt { canonical_command, .. }),
            } if provider == "sso-jwt"
                && handle.as_deref() == Some("corp/prod")
                && canonical_command.contains(&script.to_string_lossy().to_string())
        ));
    }

    #[test]
    fn legacy_command_display_is_safe_without_resolving_the_command() {
        let display =
            token_source_display_for_spec("/missing/path/to/source-token --bearer topsecret")
                .expect("display");
        assert!(display.starts_with("command:source-token#"));
        assert!(!display.contains("/missing/path/to/source-token"));
        assert!(!display.contains("topsecret"));
    }

    #[test]
    fn modern_metadata_without_state_is_reported_as_corrupt() {
        let secrets = MemorySecretStore::new();
        let record = binding_record_with_provider("sso-jwt");

        let error = token_source_is_reacquirable(&record, &secrets).expect_err("corrupt state");
        assert!(error
            .to_string()
            .contains("persisted token source state is missing"));
    }

    #[test]
    fn modern_metadata_with_mismatched_state_is_reported_as_corrupt() {
        let secrets = MemorySecretStore::new();
        let record = binding_record_with_provider("sso-jwt");
        let mismatched = serde_json::to_string(&StoredTokenSourceState::Provider {
            provider: "other-provider".to_string(),
            handle: None,
            adapter: None,
        })
        .expect("state");
        secrets
            .set(&token_source_state_id(&record.id), &mismatched)
            .expect("store state");

        let error = token_source_is_reacquirable(&record, &secrets).expect_err("corrupt state");
        assert!(error
            .to_string()
            .contains("does not match its persisted token source state"));
    }

    #[test]
    fn token_source_display_for_listing_reports_modern_metadata_without_state_as_corrupt() {
        let secrets = MemorySecretStore::new();
        let record = binding_record_with_provider("sso-jwt");

        let error =
            token_source_display_for_listing(&record, &secrets).expect_err("corrupt display");
        assert!(error
            .to_string()
            .contains("persisted token source state is missing"));
    }

    #[test]
    fn token_source_display_for_listing_reports_mismatched_state_as_corrupt() {
        let secrets = MemorySecretStore::new();
        let record = binding_record_with_provider("sso-jwt");
        secrets
            .set(
                &token_source_state_id(&record.id),
                &serde_json::to_string(&StoredTokenSourceState::Command {
                    canonical: "/usr/bin/printf token".to_string(),
                })
                .expect("state"),
            )
            .expect("store state");

        let error =
            token_source_display_for_listing(&record, &secrets).expect_err("corrupt display");
        assert!(error
            .to_string()
            .contains("does not match its persisted token source state"));
    }

    #[test]
    fn token_source_display_for_listing_reports_orphan_sidecar_state_as_corrupt() {
        let secrets = MemorySecretStore::new();
        let record = binding_record();
        secrets
            .set(
                &token_source_state_id(&record.id),
                &serde_json::to_string(&StoredTokenSourceState::Command {
                    canonical: "/usr/bin/printf token".to_string(),
                })
                .expect("state"),
            )
            .expect("store state");

        let error =
            token_source_display_for_listing(&record, &secrets).expect_err("corrupt display");
        assert!(error
            .to_string()
            .contains("persisted token source state without binding metadata"));
    }

    #[test]
    fn token_source_is_reacquirable_reports_orphan_sidecar_state_as_corrupt() {
        let secrets = MemorySecretStore::new();
        let record = binding_record();
        secrets
            .set(
                &token_source_state_id(&record.id),
                &serde_json::to_string(&StoredTokenSourceState::Command {
                    canonical: "/usr/bin/printf token".to_string(),
                })
                .expect("state"),
            )
            .expect("store state");

        let error = token_source_is_reacquirable(&record, &secrets).expect_err("corrupt state");
        assert!(error
            .to_string()
            .contains("persisted token source state without binding metadata"));
    }

    fn binding_record() -> BindingRecord {
        BindingRecord {
            id: BindingId::new("npm:default"),
            label: "default".to_string(),
            target: "https://registry.npmjs.org/".to_string(),
            secret_env_var: "NPM_TOKEN_DEFAULT".to_string(),
            metadata: Default::default(),
        }
    }

    fn binding_record_with_provider(provider: &str) -> BindingRecord {
        let mut record = binding_record();
        record
            .metadata
            .insert(TOKEN_PROVIDER_KEY.to_string(), provider.to_string());
        record
            .metadata
            .insert(TOKEN_DISPLAY_KEY.to_string(), provider.to_string());
        record
    }
}
