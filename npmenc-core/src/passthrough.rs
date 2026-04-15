#![cfg_attr(test, allow(clippy::unwrap_used))]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;

use anyhow::Result;
use enclaveapp_app_adapter::{
    prepare_best_app_launch, resolve_program, AdapterError, AppSpec, BindingStore, ConfigOverride,
    IntegrationCandidates, IntegrationPayload, LaunchRequest, ResolveMode, ResolveOptions,
    SecretStore, TempConfig, REDACTED_PLACEHOLDER,
};

use crate::command_kind::CommandKind;
use crate::config_path::resolve_effective_userconfig;
use crate::management::validate_unique_auth_keys;
use crate::npmrc::{
    analyze_auth_entries, discover_scoped_auth_tokens, discover_unscoped_auth_tokens,
    rewrite_with_bindings, RewriteOptions,
};
use crate::registry_bindings::{binding_for_auth_key, default_registry_binding, RegistryBinding};
use crate::state_lock::{with_state_lock, with_state_lock_read_only};
use crate::token_source::{
    acquire_secret_from_binding_token_source_staged, apply_pending_secret_updates,
    has_token_source_metadata, token_source_is_reacquirable,
    token_source_is_reacquirable_for_inspection, PendingManagedSecretUpdate,
};
use crate::unscoped_auth::{
    classify_unscoped_auth, effective_unscoped_token, looks_like_empty_secret,
    looks_like_placeholder, UnscopedAuthState,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrapperInvocation {
    pub userconfig_override: Option<PathBuf>,
    pub resolve_mode: ResolveMode,
    pub shell: Option<PathBuf>,
    pub explicit_bin: Option<PathBuf>,
    pub strict: bool,
    pub allow_unscoped_auth: bool,
    pub args: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WrapperMode {
    Passthrough,
    ManagedBindings,
    TransientFallback,
}

#[derive(Debug)]
pub struct PreparedInvocation {
    pub launch: LaunchRequest,
    pub effective_config_path: PathBuf,
    pub effective_config_contents: String,
    pub temp_config_path: Option<PathBuf>,
    pub mode: WrapperMode,
    pub warnings: Vec<String>,
    temp_config: Option<std::sync::Arc<TempConfig>>,
}

pub fn prepare_passthrough(
    command_kind: CommandKind,
    invocation: WrapperInvocation,
) -> Result<PreparedInvocation> {
    let WrapperInvocation {
        userconfig_override,
        resolve_mode,
        shell,
        explicit_bin,
        args,
        ..
    } = invocation;

    let program = resolve_program(
        command_kind.executable_name(),
        &ResolveOptions {
            explicit_path: explicit_bin,
            mode: resolve_mode,
            shell,
        },
    )?;
    let effective_userconfig = resolve_effective_userconfig(userconfig_override.as_deref())?;
    let source = match fs::read_to_string(&effective_userconfig) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(error) => return Err(error.into()),
    };

    let mut env_overrides = BTreeMap::new();
    env_overrides.insert(
        "NPM_CONFIG_USERCONFIG".to_string(),
        effective_userconfig.to_string_lossy().into_owned(),
    );

    Ok(PreparedInvocation {
        launch: LaunchRequest {
            program,
            args,
            env_overrides,
            env_removals: Vec::new(),
        },
        effective_config_path: effective_userconfig,
        effective_config_contents: source,
        temp_config_path: None,
        mode: WrapperMode::Passthrough,
        warnings: Vec::new(),
        temp_config: None,
    })
}

pub fn prepare_wrapped_invocation<B, S>(
    command_kind: CommandKind,
    invocation: WrapperInvocation,
    binding_store: &B,
    secret_store: &S,
) -> Result<PreparedInvocation>
where
    B: BindingStore,
    S: SecretStore,
{
    prepare_wrapped_invocation_inner(command_kind, invocation, binding_store, secret_store, true)
}

pub fn prepare_wrapped_invocation_read_only<B, S>(
    command_kind: CommandKind,
    invocation: WrapperInvocation,
    binding_store: &B,
    secret_store: &S,
) -> Result<PreparedInvocation>
where
    B: BindingStore,
    S: SecretStore,
{
    prepare_wrapped_invocation_inner(command_kind, invocation, binding_store, secret_store, false)
}

fn prepare_wrapped_invocation_inner<B, S>(
    command_kind: CommandKind,
    invocation: WrapperInvocation,
    binding_store: &B,
    secret_store: &S,
    allow_secret_mutation: bool,
) -> Result<PreparedInvocation>
where
    B: BindingStore,
    S: SecretStore,
{
    let work = || {
        let WrapperInvocation {
            userconfig_override,
            resolve_mode,
            shell,
            explicit_bin,
            strict,
            allow_unscoped_auth,
            args,
        } = invocation;

        let program = resolve_program(
            command_kind.executable_name(),
            &ResolveOptions {
                explicit_path: explicit_bin.clone(),
                mode: resolve_mode,
                shell: shell.clone(),
            },
        )?;

        let effective_userconfig = resolve_effective_userconfig(userconfig_override.as_deref())?;
        let source = match fs::read_to_string(&effective_userconfig) {
            Ok(contents) => contents,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(error) => return Err(error.into()),
        };
        let diagnostics = analyze_auth_entries(&source);
        let unscoped_tokens = discover_unscoped_auth_tokens(&source);
        let effective_unscoped_token = effective_unscoped_token(&unscoped_tokens);
        let mut warnings = Vec::new();
        if !diagnostics.legacy_auth_keys.is_empty() {
            let message = format!(
                "found legacy auth entries that npmenc v1 does not migrate automatically: {}",
                diagnostics.legacy_auth_keys.join(", ")
            );
            if strict {
                return Err(anyhow::anyhow!(message));
            }
            warnings.push(message);
        }

        let binding_records = binding_store.list()?;
        validate_unique_auth_keys(&binding_records)?;
        let managed_default_binding_in_state = binding_records
            .iter()
            .any(|record| record.label == "default");
        let unscoped_state = classify_unscoped_auth(
            effective_unscoped_token,
            allow_unscoped_auth,
            managed_default_binding_in_state,
        );
        if unscoped_state.requires_warning_or_strict() {
            let message = format!(
                "found unscoped auth entries that are not automatically protected: {}",
                diagnostics.unscoped_auth_tokens.join(", ")
            );
            if strict {
                return Err(anyhow::anyhow!(message));
            }
            warnings.push(message);
        }
        let mut active_binding_records = Vec::new();
        let mut stored_secret_labels = BTreeSet::new();
        for record in &binding_records {
            if secret_store.get(&record.id)?.is_some() {
                stored_secret_labels.insert(record.label.clone());
                active_binding_records.push(record.clone());
            } else if if allow_secret_mutation {
                token_source_is_reacquirable(record, secret_store)?
            } else {
                token_source_is_reacquirable_for_inspection(record, secret_store)?
            } {
                active_binding_records.push(record.clone());
            } else if has_token_source_metadata(record) {
                warnings.push(format!(
                    "ignoring managed binding `{}` because its token source cannot reacquire secrets in the current environment",
                    record.label
                ));
            } else {
                warnings.push(format!(
                "ignoring managed binding `{}` because it has neither a stored secret nor a token source",
                record.label
            ));
            }
        }
        let persisted_bindings = active_binding_records
            .iter()
            .map(RegistryBinding::from_binding_record)
            .collect::<Vec<_>>();

        let mut bindings = persisted_bindings.clone();
        let mut seen_labels = bindings
            .iter()
            .map(|binding| binding.label.clone())
            .collect::<BTreeSet<_>>();
        let mut transient_secrets = BTreeMap::new();
        let managed_default_binding = persisted_bindings
            .iter()
            .find(|binding| binding.label == "default")
            .cloned();

        if let Some(value) = effective_unscoped_token {
            if matches!(
                unscoped_state,
                UnscopedAuthState::ManagedPlaceholder | UnscopedAuthState::RawAllowed
            ) {
                let default_binding = persisted_bindings
                    .iter()
                    .find(|binding| binding.label == "default");
                if looks_like_placeholder(value) {
                    if default_binding.is_none() {
                        return Err(anyhow::anyhow!(
                        "found npmenc-managed unscoped placeholder auth entry in config but no matching managed state exists"
                    ));
                    }
                } else if looks_like_empty_secret(value) {
                    warnings.push("ignoring empty unscoped _authToken entry".to_string());
                } else {
                    let default_binding = default_binding
                        .cloned()
                        .unwrap_or_else(default_registry_binding);
                    if !bindings.iter().any(|binding| binding.label == "default") {
                        bindings.push(default_binding.clone());
                        seen_labels.insert("default".to_string());
                    }
                    if stored_secret_labels.contains("default") {
                        warnings.push(
                        "ignoring materialized unscoped token in config for managed default binding; using stored managed secret"
                            .to_string(),
                    );
                    } else {
                        transient_secrets.insert("default".to_string(), value.to_string());
                    }
                }
            } else if matches!(
                unscoped_state,
                UnscopedAuthState::RawProtectedByManagedDefault
            ) {
                let Some(default_binding) = &managed_default_binding else {
                    unreachable!("managed default binding state should exist for protected auth");
                };
                if stored_secret_labels.contains("default") {
                    warnings.push(
                    "ignoring materialized unscoped token in config for managed default binding; using stored managed secret"
                        .to_string(),
                );
                } else {
                    warnings.push(
                    "ignoring materialized unscoped token in config for managed default binding; using managed token source"
                        .to_string(),
                );
                }
                if !bindings.iter().any(|binding| binding.label == "default") {
                    bindings.push(default_binding.clone());
                    seen_labels.insert("default".to_string());
                }
            } else if matches!(unscoped_state, UnscopedAuthState::Empty) {
                warnings.push("ignoring empty unscoped _authToken entry".to_string());
            }
            if unscoped_tokens.len() > 1 {
                warnings.push(
                    "multiple unscoped _authToken entries found; using the last one only"
                        .to_string(),
                );
            }
        }

        for token in discover_scoped_auth_tokens(&source) {
            if looks_like_placeholder(&token.value) {
                continue;
            }
            if looks_like_empty_secret(&token.value) {
                warnings.push(format!(
                    "ignoring empty auth token entry for `{}`",
                    token.auth_key
                ));
                continue;
            }

            if let Some(binding) = bindings
                .iter()
                .find(|binding| binding.auth_key == token.auth_key)
            {
                if stored_secret_labels.contains(&binding.label) {
                    warnings.push(format!(
                    "ignoring materialized token in config for managed binding `{}`; using stored managed secret",
                    binding.label
                ));
                } else {
                    transient_secrets.insert(binding.label.clone(), token.value);
                }
                continue;
            }

            let binding = binding_for_auth_key(&token.auth_key, &mut seen_labels);
            transient_secrets.insert(binding.label.clone(), token.value);
            bindings.push(binding);
        }

        if !transient_secrets.is_empty() {
            warnings.push(
            "using one-shot transient secrets from the source config because managed bindings are incomplete or not installed"
                .to_string(),
        );
        }

        let missing_placeholder_auth_keys = discover_scoped_auth_tokens(&source)
            .into_iter()
            .filter(|token| looks_like_placeholder(&token.value))
            .filter(|token| {
                !bindings
                    .iter()
                    .any(|binding| binding.auth_key == token.auth_key)
            })
            .map(|token| token.auth_key)
            .collect::<Vec<_>>();
        if !missing_placeholder_auth_keys.is_empty() {
            return Err(anyhow::anyhow!(
            "found npmenc-managed placeholder auth entries in config but no matching managed state exists for: {}",
            missing_placeholder_auth_keys.join(", ")
        ));
        }

        if bindings.is_empty() {
            let mut prepared = prepare_passthrough(
                command_kind,
                WrapperInvocation {
                    userconfig_override: Some(effective_userconfig),
                    resolve_mode,
                    shell,
                    explicit_bin,
                    strict,
                    allow_unscoped_auth,
                    args,
                },
            )?;
            prepared.warnings = warnings;
            return Ok(prepared);
        }

        let rewritten = rewrite_with_bindings(
            &source,
            &bindings,
            RewriteOptions {
                append_missing_bindings: true,
                allow_unscoped_auth: should_rewrite_unscoped_auth(
                    effective_unscoped_token,
                    allow_unscoped_auth,
                    bindings.iter().any(|binding| binding.label == "default"),
                ),
            },
        );
        let mut env_overrides = BTreeMap::new();
        let mut pending_secret_updates: Vec<PendingManagedSecretUpdate> = Vec::new();

        for label in &rewritten.used_bindings {
            if let Some(binding) = bindings.iter().find(|binding| &binding.label == label) {
                let secret = if let Some(secret) = transient_secrets.get(&binding.label) {
                    secret.clone()
                } else {
                    let staged = managed_secret_for_binding(
                        binding,
                        &active_binding_records,
                        secret_store,
                        allow_secret_mutation,
                    )?;
                    if let Some(update) = staged.1 {
                        pending_secret_updates.push(update);
                    }
                    staged.0
                };
                env_overrides.insert(binding.placeholder_env_var.clone(), secret.clone());
                if binding.label == "default" {
                    env_overrides.insert("NPM_TOKEN".to_string(), secret);
                }
            }
        }

        let app_spec = AppSpec {
            display_name: command_kind.display_name().to_string(),
            executable_name: command_kind.executable_name().to_string(),
            supported_integrations: vec![enclaveapp_app_adapter::IntegrationType::EnvInterpolation],
            config_override: ConfigOverride::EnvironmentVariable {
                name: "NPM_CONFIG_USERCONFIG".to_string(),
            },
        };
        let prepared_launch = prepare_best_app_launch(
            &app_spec,
            program,
            args,
            IntegrationCandidates {
                env_interpolation: Some(IntegrationPayload::EnvInterpolation {
                    config_bytes: Some(rewritten.contents.clone().into_bytes()),
                    env_overrides,
                }),
                ..IntegrationCandidates::default()
            },
        )
        .map_err(anyhow::Error::from)?;
        if allow_secret_mutation {
            apply_pending_secret_updates(&pending_secret_updates, secret_store)?;
        }
        let (mut launch, temp_config_path, temp_config) = prepared_launch.into_parts();
        launch.env_removals = vec![
            "NPM_CONFIG_USERCONFIG".to_string(),
            "npm_config_userconfig".to_string(),
            "NPM_TOKEN".to_string(),
        ];
        for binding in &bindings {
            launch
                .env_removals
                .push(binding.placeholder_env_var.clone());
        }
        let effective_config_path = temp_config_path
            .clone()
            .expect("env interpolation launch should materialize a placeholder temp config");

        Ok(PreparedInvocation {
            launch,
            effective_config_path,
            effective_config_contents: rewritten.contents,
            temp_config_path,
            mode: if transient_secrets.is_empty() {
                WrapperMode::ManagedBindings
            } else {
                WrapperMode::TransientFallback
            },
            warnings,
            temp_config,
        })
    };

    if allow_secret_mutation {
        with_state_lock(work)
    } else {
        with_state_lock_read_only(work)
    }
}

impl PreparedInvocation {
    pub fn temp_config(&self) -> Option<&TempConfig> {
        self.temp_config.as_deref()
    }
}

fn should_rewrite_unscoped_auth(
    value: Option<&str>,
    allow_unscoped_auth: bool,
    managed_default_binding_active: bool,
) -> bool {
    classify_unscoped_auth(value, allow_unscoped_auth, managed_default_binding_active)
        .should_rewrite()
}

fn managed_secret_for_binding<S>(
    binding: &RegistryBinding,
    binding_records: &[enclaveapp_app_adapter::BindingRecord],
    secret_store: &S,
    allow_secret_mutation: bool,
) -> Result<(String, Option<PendingManagedSecretUpdate>)>
where
    S: SecretStore,
{
    if let Some(secret) = secret_store.get(&binding.id)? {
        return Ok((secret, None));
    }

    let record = binding_records
        .iter()
        .find(|record| record.id == binding.id)
        .ok_or_else(|| AdapterError::MissingSecret(binding.label.clone()))?;
    if !allow_secret_mutation {
        return Ok((REDACTED_PLACEHOLDER.to_string(), None));
    }
    let staged = acquire_secret_from_binding_token_source_staged(record, secret_store)?
        .ok_or_else(|| AdapterError::MissingSecret(binding.label.clone()))?;
    Ok((
        staged.secret.clone(),
        Some(PendingManagedSecretUpdate {
            id: binding.id.clone(),
            secret: staged.secret,
            token_source_artifacts: staged.token_source_artifacts,
        }),
    ))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::os::unix::fs::PermissionsExt;

    use enclaveapp_app_adapter::{
        BindingRecord, MemoryBindingStore, MemorySecretStore, ResolutionStrategy,
    };
    use tempfile::TempDir;

    use super::*;
    use crate::test_support::{lock_env, EnvVarGuard};

    fn make_executable(path: &std::path::Path) {
        let mut perms = fs::metadata(path).expect("metadata").permissions();
        perms.set_mode(0o755);
        fs::set_permissions(path, perms).expect("chmod");
    }

    #[test]
    fn wrapped_invocation_writes_placeholder_temp_config_and_env() {
        let _env_lock = lock_env();
        let dir = TempDir::new().expect("temp dir");
        let npm_path = dir.path().join("npm");
        fs::write(&npm_path, b"#!/bin/sh\n").expect("write npm");
        make_executable(&npm_path);
        let npmrc_path = dir.path().join("user.npmrc");
        fs::write(
            &npmrc_path,
            "//registry.npmjs.org/:_authToken=${NPM_TOKEN_DEFAULT}\ncolor=true\n",
        )
        .expect("write npmrc");

        let bindings = MemoryBindingStore::new();
        let secrets = MemorySecretStore::new();
        let record = BindingRecord {
            id: "npm:default".into(),
            label: "default".into(),
            target: "https://registry.npmjs.org/".into(),
            secret_env_var: "NPM_TOKEN_DEFAULT".into(),
            metadata: BTreeMap::new(),
        };
        bindings.upsert(record.clone()).expect("binding");
        secrets.set(&record.id, "npm_ABC123").expect("secret");

        let prepared = prepare_wrapped_invocation(
            CommandKind::Npm,
            WrapperInvocation {
                userconfig_override: Some(npmrc_path),
                resolve_mode: ResolveMode::Auto,
                shell: None,
                explicit_bin: Some(npm_path.clone()),
                strict: false,
                allow_unscoped_auth: false,
                args: vec!["--version".into()],
            },
            &bindings,
            &secrets,
        )
        .expect("prepared");

        assert_eq!(prepared.launch.program.path, npm_path);
        assert_eq!(
            prepared.launch.program.strategy,
            ResolutionStrategy::ExplicitPath
        );
        assert_eq!(prepared.mode, WrapperMode::ManagedBindings);
        assert_eq!(
            prepared.launch.env_overrides.get("NPM_TOKEN_DEFAULT"),
            Some(&"npm_ABC123".to_string())
        );
        assert_eq!(
            prepared.launch.env_overrides.get("NPM_TOKEN"),
            Some(&"npm_ABC123".to_string())
        );
        assert!(prepared.warnings.is_empty());

        let temp_path = prepared
            .temp_config_path
            .as_ref()
            .expect("temp config path");
        let temp_contents = fs::read_to_string(temp_path).expect("read temp config");
        assert!(temp_contents.contains("${NPM_TOKEN_DEFAULT}"));
        assert!(!temp_contents.contains("npm_ABC123"));
    }

    #[test]
    fn wrapped_invocation_uses_transient_tokens_without_managed_state() {
        let _env_lock = lock_env();
        let dir = TempDir::new().expect("temp dir");
        let npm_path = dir.path().join("npm");
        fs::write(&npm_path, b"#!/bin/sh\n").expect("write npm");
        make_executable(&npm_path);
        let npmrc_path = dir.path().join("user.npmrc");
        fs::write(
            &npmrc_path,
            "//registry.npmjs.org/:_authToken=npm_ABC123\n//artifactory.example.com/api/npm/npm/:_authToken=jwt_456\n",
        )
        .expect("write npmrc");

        let bindings = MemoryBindingStore::new();
        let secrets = MemorySecretStore::new();

        let prepared = prepare_wrapped_invocation(
            CommandKind::Npm,
            WrapperInvocation {
                userconfig_override: Some(npmrc_path),
                resolve_mode: ResolveMode::Auto,
                shell: None,
                explicit_bin: Some(npm_path),
                strict: false,
                allow_unscoped_auth: false,
                args: vec!["--version".into()],
            },
            &bindings,
            &secrets,
        )
        .expect("prepared");

        assert_eq!(
            prepared.launch.env_overrides.get("NPM_TOKEN"),
            Some(&"npm_ABC123".to_string())
        );
        assert_eq!(prepared.mode, WrapperMode::TransientFallback);
        assert_eq!(
            prepared.launch.env_overrides.get("NPM_TOKEN_DEFAULT"),
            Some(&"npm_ABC123".to_string())
        );
        assert_eq!(
            prepared
                .launch
                .env_overrides
                .get("NPM_TOKEN_ARTIFACTORY_EXAMPLE_COM_API_NPM_NPM"),
            Some(&"jwt_456".to_string())
        );

        let temp_path = prepared.temp_config_path.as_ref().expect("temp path");
        let temp_contents = fs::read_to_string(temp_path).expect("read temp");
        assert!(temp_contents.contains("${NPM_TOKEN_DEFAULT}"));
        assert!(temp_contents.contains("${NPM_TOKEN_ARTIFACTORY_EXAMPLE_COM_API_NPM_NPM}"));
        assert!(!temp_contents.contains("npm_ABC123"));
        assert!(!temp_contents.contains("jwt_456"));
    }

    #[test]
    fn strict_mode_rejects_problematic_auth_entries() {
        let _env_lock = lock_env();
        let dir = TempDir::new().expect("temp dir");
        let npm_path = dir.path().join("npm");
        fs::write(&npm_path, b"#!/bin/sh\n").expect("write npm");
        make_executable(&npm_path);
        let npmrc_path = dir.path().join("user.npmrc");
        fs::write(&npmrc_path, "_authToken=abc\n").expect("write npmrc");

        let bindings = MemoryBindingStore::new();
        let secrets = MemorySecretStore::new();

        let error = prepare_wrapped_invocation(
            CommandKind::Npm,
            WrapperInvocation {
                userconfig_override: Some(npmrc_path),
                resolve_mode: ResolveMode::Auto,
                shell: None,
                explicit_bin: Some(npm_path),
                strict: true,
                allow_unscoped_auth: false,
                args: vec!["--version".into()],
            },
            &bindings,
            &secrets,
        )
        .expect_err("strict error");

        assert!(error.to_string().contains("unscoped auth entries"));
    }

    #[test]
    fn strict_mode_allows_raw_unscoped_auth_when_managed_default_binding_exists() {
        let _env_lock = lock_env();
        let dir = TempDir::new().expect("temp dir");
        let npm_path = dir.path().join("npm");
        fs::write(&npm_path, b"#!/bin/sh\n").expect("write npm");
        make_executable(&npm_path);
        let npmrc_path = dir.path().join("user.npmrc");
        fs::write(&npmrc_path, "_authToken=file_token\n").expect("write npmrc");

        let bindings = MemoryBindingStore::new();
        let secrets = MemorySecretStore::new();
        let record = BindingRecord {
            id: "npm:default".into(),
            label: "default".into(),
            target: "https://registry.npmjs.org/".into(),
            secret_env_var: "NPM_TOKEN_DEFAULT".into(),
            metadata: BTreeMap::new(),
        };
        bindings.upsert(record.clone()).expect("binding");
        secrets.set(&record.id, "stored_token").expect("secret");

        let prepared = prepare_wrapped_invocation(
            CommandKind::Npm,
            WrapperInvocation {
                userconfig_override: Some(npmrc_path),
                resolve_mode: ResolveMode::Auto,
                shell: None,
                explicit_bin: Some(npm_path),
                strict: true,
                allow_unscoped_auth: false,
                args: vec!["--version".into()],
            },
            &bindings,
            &secrets,
        )
        .expect("prepared");

        assert_eq!(prepared.mode, WrapperMode::ManagedBindings);
        assert_eq!(
            prepared.launch.env_overrides.get("NPM_TOKEN_DEFAULT"),
            Some(&"stored_token".to_string())
        );
        assert!(prepared
            .effective_config_contents
            .contains("//registry.npmjs.org/:_authToken=${NPM_TOKEN_DEFAULT}"));
    }

    #[test]
    fn allow_unscoped_auth_uses_default_transient_secret() {
        let _env_lock = lock_env();
        let dir = TempDir::new().expect("temp dir");
        let npm_path = dir.path().join("npm");
        fs::write(&npm_path, b"#!/bin/sh\n").expect("write npm");
        make_executable(&npm_path);
        let npmrc_path = dir.path().join("user.npmrc");
        fs::write(&npmrc_path, "_authToken=abc\n").expect("write npmrc");

        let bindings = MemoryBindingStore::new();
        let secrets = MemorySecretStore::new();

        let prepared = prepare_wrapped_invocation(
            CommandKind::Npm,
            WrapperInvocation {
                userconfig_override: Some(npmrc_path),
                resolve_mode: ResolveMode::Auto,
                shell: None,
                explicit_bin: Some(npm_path),
                strict: false,
                allow_unscoped_auth: true,
                args: vec!["--version".into()],
            },
            &bindings,
            &secrets,
        )
        .expect("prepared");

        assert_eq!(
            prepared.launch.env_overrides.get("NPM_TOKEN_DEFAULT"),
            Some(&"abc".to_string())
        );
        let temp_path = prepared.temp_config_path.as_ref().expect("temp");
        let contents = fs::read_to_string(temp_path).expect("read");
        assert!(contents.contains("//registry.npmjs.org/:_authToken=${NPM_TOKEN_DEFAULT}"));
    }

    #[test]
    fn wrapped_invocation_uses_last_unscoped_auth_token() {
        let _env_lock = lock_env();
        let dir = TempDir::new().expect("temp dir");
        let npm_path = dir.path().join("npm");
        fs::write(&npm_path, b"#!/bin/sh\n").expect("write npm");
        make_executable(&npm_path);
        let npmrc_path = dir.path().join("user.npmrc");
        fs::write(&npmrc_path, "_authToken=first\n_authToken=second\n").expect("write npmrc");

        let bindings = MemoryBindingStore::new();
        let secrets = MemorySecretStore::new();

        let prepared = prepare_wrapped_invocation(
            CommandKind::Npm,
            WrapperInvocation {
                userconfig_override: Some(npmrc_path),
                resolve_mode: ResolveMode::Auto,
                shell: None,
                explicit_bin: Some(npm_path),
                strict: false,
                allow_unscoped_auth: true,
                args: vec!["--version".into()],
            },
            &bindings,
            &secrets,
        )
        .expect("prepared");

        assert_eq!(prepared.mode, WrapperMode::TransientFallback);
        assert_eq!(
            prepared.launch.env_overrides.get("NPM_TOKEN_DEFAULT"),
            Some(&"second".to_string())
        );
        assert!(prepared
            .warnings
            .iter()
            .any(|warning| warning.contains("last one")));
    }

    #[test]
    fn wrapped_invocation_recognizes_managed_unscoped_placeholder_without_flag() {
        let _env_lock = lock_env();
        let dir = TempDir::new().expect("temp dir");
        let npm_path = dir.path().join("npm");
        fs::write(&npm_path, b"#!/bin/sh\n").expect("write npm");
        make_executable(&npm_path);
        let npmrc_path = dir.path().join("user.npmrc");
        fs::write(&npmrc_path, "_authToken=${NPM_TOKEN_DEFAULT}\n").expect("write npmrc");

        let bindings = MemoryBindingStore::new();
        let secrets = MemorySecretStore::new();
        let record = BindingRecord {
            id: "npm:default".into(),
            label: "default".into(),
            target: "https://registry.npmjs.org/".into(),
            secret_env_var: "NPM_TOKEN_DEFAULT".into(),
            metadata: BTreeMap::new(),
        };
        bindings.upsert(record.clone()).expect("binding");
        secrets.set(&record.id, "npm_ABC123").expect("secret");

        let prepared = prepare_wrapped_invocation(
            CommandKind::Npm,
            WrapperInvocation {
                userconfig_override: Some(npmrc_path),
                resolve_mode: ResolveMode::Auto,
                shell: None,
                explicit_bin: Some(npm_path),
                strict: false,
                allow_unscoped_auth: false,
                args: vec!["--version".into()],
            },
            &bindings,
            &secrets,
        )
        .expect("prepared");

        assert_eq!(prepared.mode, WrapperMode::ManagedBindings);
        assert_eq!(
            prepared.launch.env_overrides.get("NPM_TOKEN_DEFAULT"),
            Some(&"npm_ABC123".to_string())
        );
        assert!(!prepared
            .warnings
            .iter()
            .any(|warning| warning.contains("found unscoped auth entries")));

        let temp_path = prepared.temp_config_path.as_ref().expect("temp");
        let contents = fs::read_to_string(temp_path).expect("read");
        assert!(contents.contains("//registry.npmjs.org/:_authToken=${NPM_TOKEN_DEFAULT}"));
        assert!(!contents
            .lines()
            .any(|line| line.trim() == "_authToken=${NPM_TOKEN_DEFAULT}"));
    }

    #[test]
    fn wrapped_invocation_rewrites_raw_unscoped_auth_when_managed_default_binding_is_active() {
        let _env_lock = lock_env();
        let dir = TempDir::new().expect("temp dir");
        let npm_path = dir.path().join("npm");
        fs::write(&npm_path, b"#!/bin/sh\n").expect("write npm");
        make_executable(&npm_path);
        let npmrc_path = dir.path().join("user.npmrc");
        fs::write(&npmrc_path, "_authToken=file_token\n").expect("write npmrc");

        let bindings = MemoryBindingStore::new();
        let secrets = MemorySecretStore::new();
        let record = BindingRecord {
            id: "npm:default".into(),
            label: "default".into(),
            target: "https://registry.npmjs.org/".into(),
            secret_env_var: "NPM_TOKEN_DEFAULT".into(),
            metadata: BTreeMap::new(),
        };
        bindings.upsert(record.clone()).expect("binding");
        secrets.set(&record.id, "managed_token").expect("secret");

        let prepared = prepare_wrapped_invocation(
            CommandKind::Npm,
            WrapperInvocation {
                userconfig_override: Some(npmrc_path),
                resolve_mode: ResolveMode::Auto,
                shell: None,
                explicit_bin: Some(npm_path),
                strict: false,
                allow_unscoped_auth: false,
                args: vec!["--version".into()],
            },
            &bindings,
            &secrets,
        )
        .expect("prepared");

        assert_eq!(prepared.mode, WrapperMode::ManagedBindings);
        let temp_path = prepared.temp_config_path.as_ref().expect("temp");
        let contents = fs::read_to_string(temp_path).expect("read");
        assert_eq!(
            contents,
            "//registry.npmjs.org/:_authToken=${NPM_TOKEN_DEFAULT}\n"
        );
        assert_eq!(
            prepared.launch.env_overrides.get("NPM_TOKEN_DEFAULT"),
            Some(&"managed_token".to_string())
        );
    }

    #[test]
    fn read_only_wrapped_invocation_does_not_acquire_or_persist_secret() {
        let _env_lock = lock_env();
        let dir = TempDir::new().expect("temp dir");
        let _config_guard = EnvVarGuard::set("NPMENC_CONFIG_DIR", dir.path().join("config-root"));
        let npm_path = dir.path().join("npm");
        let source_path = dir.path().join("source-token");
        let marker_path = dir.path().join("token-source-ran");
        fs::write(&npm_path, b"#!/bin/sh\n").expect("write npm");
        make_executable(&npm_path);
        fs::write(
            &source_path,
            format!(
                "#!/bin/sh\nprintf x > \"{}\"\nprintf 'token-from-source\\n'\n",
                marker_path.display()
            ),
        )
        .expect("write token source");
        make_executable(&source_path);
        let npmrc_path = dir.path().join("user.npmrc");
        fs::write(
            &npmrc_path,
            "//registry.npmjs.org/:_authToken=${NPM_TOKEN_DEFAULT}\n",
        )
        .expect("write npmrc");

        let bindings = MemoryBindingStore::new();
        let secrets = MemorySecretStore::new();
        let mut record = BindingRecord {
            id: "npm:default".into(),
            label: "default".into(),
            target: "https://registry.npmjs.org/".into(),
            secret_env_var: "NPM_TOKEN_DEFAULT".into(),
            metadata: BTreeMap::new(),
        };
        record.metadata.insert(
            "token_source".to_string(),
            source_path.to_string_lossy().into_owned(),
        );
        bindings.upsert(record.clone()).expect("binding");

        let prepared = prepare_wrapped_invocation_read_only(
            CommandKind::Npm,
            WrapperInvocation {
                userconfig_override: Some(npmrc_path),
                resolve_mode: ResolveMode::Auto,
                shell: None,
                explicit_bin: Some(npm_path),
                strict: false,
                allow_unscoped_auth: false,
                args: vec!["--version".into()],
            },
            &bindings,
            &secrets,
        )
        .expect("prepared");

        assert_eq!(prepared.mode, WrapperMode::ManagedBindings);
        assert_eq!(
            prepared.launch.env_overrides.get("NPM_TOKEN_DEFAULT"),
            Some(&REDACTED_PLACEHOLDER.to_string())
        );
        assert!(!marker_path.exists());
        assert_eq!(secrets.get(&record.id).expect("secret"), None);
    }

    #[test]
    fn wrapped_invocation_ignores_inactive_managed_bindings() {
        let _env_lock = lock_env();
        let dir = TempDir::new().expect("temp dir");
        let npm_path = dir.path().join("npm");
        fs::write(&npm_path, b"#!/bin/sh\n").expect("write npm");
        make_executable(&npm_path);
        let npmrc_path = dir.path().join("user.npmrc");
        fs::write(&npmrc_path, "color=true\n").expect("write npmrc");

        let bindings = MemoryBindingStore::new();
        let secrets = MemorySecretStore::new();
        let record = BindingRecord {
            id: "npm:ghost".into(),
            label: "ghost".into(),
            target: "https://ghost.example.com/npm/".into(),
            secret_env_var: "NPM_TOKEN_GHOST".into(),
            metadata: BTreeMap::from([(
                "auth_key".to_string(),
                "//ghost.example.com/npm/:_authToken".to_string(),
            )]),
        };
        bindings.upsert(record).expect("binding");

        let prepared = prepare_wrapped_invocation(
            CommandKind::Npm,
            WrapperInvocation {
                userconfig_override: Some(npmrc_path),
                resolve_mode: ResolveMode::Auto,
                shell: None,
                explicit_bin: Some(npm_path),
                strict: false,
                allow_unscoped_auth: false,
                args: vec!["--version".into()],
            },
            &bindings,
            &secrets,
        )
        .expect("prepared");

        assert_eq!(prepared.mode, WrapperMode::Passthrough);
        assert!(prepared
            .warnings
            .iter()
            .any(|warning| warning.contains("ignoring managed binding `ghost`")));
    }

    #[test]
    fn wrapped_invocation_can_acquire_secret_from_token_source() {
        let _env_lock = lock_env();
        let dir = TempDir::new().expect("temp dir");
        let npm_path = dir.path().join("npm");
        let source_path = dir.path().join("source-token");
        fs::write(&npm_path, b"#!/bin/sh\n").expect("write npm");
        make_executable(&npm_path);
        fs::write(&source_path, "#!/bin/sh\nprintf 'token-from-source\\n'\n")
            .expect("write token source");
        let mut perms = fs::metadata(&source_path).expect("metadata").permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&source_path, perms).expect("chmod");
        let npmrc_path = dir.path().join("user.npmrc");
        fs::write(
            &npmrc_path,
            "//registry.npmjs.org/:_authToken=${NPM_TOKEN_DEFAULT}\n",
        )
        .expect("write npmrc");

        let bindings = MemoryBindingStore::new();
        let secrets = MemorySecretStore::new();
        let mut record = BindingRecord {
            id: "npm:default".into(),
            label: "default".into(),
            target: "https://registry.npmjs.org/".into(),
            secret_env_var: "NPM_TOKEN_DEFAULT".into(),
            metadata: BTreeMap::new(),
        };
        record.metadata.insert(
            "token_source".to_string(),
            source_path.to_string_lossy().into_owned(),
        );
        bindings.upsert(record.clone()).expect("binding");

        let prepared = prepare_wrapped_invocation(
            CommandKind::Npm,
            WrapperInvocation {
                userconfig_override: Some(npmrc_path),
                resolve_mode: ResolveMode::Auto,
                shell: None,
                explicit_bin: Some(npm_path),
                strict: false,
                allow_unscoped_auth: false,
                args: vec!["--version".into()],
            },
            &bindings,
            &secrets,
        )
        .expect("prepared");

        assert_eq!(
            prepared.launch.env_overrides.get("NPM_TOKEN_DEFAULT"),
            Some(&"token-from-source".to_string())
        );
        assert_eq!(
            secrets.get(&record.id).expect("stored"),
            Some("token-from-source".to_string())
        );
    }

    #[test]
    fn wrapped_invocation_uses_stored_secret_even_when_token_source_is_stale() {
        let _env_lock = lock_env();
        let dir = TempDir::new().expect("temp dir");
        let npm_path = dir.path().join("npm");
        fs::write(&npm_path, b"#!/bin/sh\n").expect("write npm");
        make_executable(&npm_path);
        let npmrc_path = dir.path().join("user.npmrc");
        fs::write(
            &npmrc_path,
            "//registry.npmjs.org/:_authToken=${NPM_TOKEN_DEFAULT}\n",
        )
        .expect("write npmrc");

        let bindings = MemoryBindingStore::new();
        let secrets = MemorySecretStore::new();
        let mut record = BindingRecord {
            id: "npm:default".into(),
            label: "default".into(),
            target: "https://registry.npmjs.org/".into(),
            secret_env_var: "NPM_TOKEN_DEFAULT".into(),
            metadata: BTreeMap::new(),
        };
        record.metadata.insert(
            "token_source".to_string(),
            "/definitely/missing/token-source".to_string(),
        );
        bindings.upsert(record.clone()).expect("binding");
        secrets.set(&record.id, "npm_ABC123").expect("secret");

        let prepared = prepare_wrapped_invocation(
            CommandKind::Npm,
            WrapperInvocation {
                userconfig_override: Some(npmrc_path),
                resolve_mode: ResolveMode::Auto,
                shell: None,
                explicit_bin: Some(npm_path),
                strict: false,
                allow_unscoped_auth: false,
                args: vec!["--version".into()],
            },
            &bindings,
            &secrets,
        )
        .expect("prepared");

        assert_eq!(
            prepared.launch.env_overrides.get("NPM_TOKEN_DEFAULT"),
            Some(&"npm_ABC123".to_string())
        );
    }

    #[test]
    fn wrapped_invocation_prefers_materialized_source_token_over_stale_token_source() {
        let _env_lock = lock_env();
        let dir = TempDir::new().expect("temp dir");
        let npm_path = dir.path().join("npm");
        fs::write(&npm_path, b"#!/bin/sh\n").expect("write npm");
        make_executable(&npm_path);
        let npmrc_path = dir.path().join("user.npmrc");
        fs::write(&npmrc_path, "//registry.npmjs.org/:_authToken=file_token\n").expect("write");

        let bindings = MemoryBindingStore::new();
        let secrets = MemorySecretStore::new();
        let mut record = BindingRecord {
            id: "npm:default".into(),
            label: "default".into(),
            target: "https://registry.npmjs.org/".into(),
            secret_env_var: "NPM_TOKEN_DEFAULT".into(),
            metadata: BTreeMap::new(),
        };
        record.metadata.insert(
            "token_source".to_string(),
            dir.path()
                .join("missing-source")
                .to_string_lossy()
                .into_owned(),
        );
        bindings.upsert(record).expect("binding");

        let prepared = prepare_wrapped_invocation(
            CommandKind::Npm,
            WrapperInvocation {
                userconfig_override: Some(npmrc_path),
                resolve_mode: ResolveMode::Auto,
                shell: None,
                explicit_bin: Some(npm_path),
                strict: false,
                allow_unscoped_auth: false,
                args: vec!["--version".into()],
            },
            &bindings,
            &secrets,
        )
        .expect("prepared");

        assert_eq!(prepared.mode, WrapperMode::TransientFallback);
        assert_eq!(
            prepared.launch.env_overrides.get("NPM_TOKEN_DEFAULT"),
            Some(&"file_token".to_string())
        );
    }

    #[test]
    fn wrapped_invocation_errors_when_placeholder_config_has_no_managed_state() {
        let _env_lock = lock_env();
        let dir = TempDir::new().expect("temp dir");
        let npm_path = dir.path().join("npm");
        fs::write(&npm_path, b"#!/bin/sh\n").expect("write npm");
        make_executable(&npm_path);
        let npmrc_path = dir.path().join("user.npmrc");
        fs::write(
            &npmrc_path,
            "//registry.npmjs.org/:_authToken=${NPM_TOKEN_DEFAULT}\n",
        )
        .expect("write npmrc");

        let bindings = MemoryBindingStore::new();
        let secrets = MemorySecretStore::new();
        let error = prepare_wrapped_invocation(
            CommandKind::Npm,
            WrapperInvocation {
                userconfig_override: Some(npmrc_path),
                resolve_mode: ResolveMode::Auto,
                shell: None,
                explicit_bin: Some(npm_path),
                strict: false,
                allow_unscoped_auth: false,
                args: vec!["--version".into()],
            },
            &bindings,
            &secrets,
        )
        .expect_err("placeholder-only config without state should fail");

        assert!(error
            .to_string()
            .contains("no matching managed state exists"));
    }

    #[test]
    fn wrapped_invocation_errors_when_unscoped_placeholder_has_no_managed_state() {
        let _env_lock = lock_env();
        let dir = TempDir::new().expect("temp dir");
        let npm_path = dir.path().join("npm");
        fs::write(&npm_path, b"#!/bin/sh\n").expect("write npm");
        make_executable(&npm_path);
        let npmrc_path = dir.path().join("user.npmrc");
        fs::write(&npmrc_path, "_authToken=${NPM_TOKEN_DEFAULT}\n").expect("write npmrc");

        let bindings = MemoryBindingStore::new();
        let secrets = MemorySecretStore::new();
        let error = prepare_wrapped_invocation(
            CommandKind::Npm,
            WrapperInvocation {
                userconfig_override: Some(npmrc_path),
                resolve_mode: ResolveMode::Auto,
                shell: None,
                explicit_bin: Some(npm_path),
                strict: false,
                allow_unscoped_auth: true,
                args: vec!["--version".into()],
            },
            &bindings,
            &secrets,
        )
        .expect_err("unscoped placeholder without state should fail");

        assert!(error
            .to_string()
            .contains("unscoped placeholder auth entry"));
    }

    #[test]
    fn wrapped_invocation_ignores_empty_source_token_entries() {
        let _env_lock = lock_env();
        let dir = TempDir::new().expect("temp dir");
        let npm_path = dir.path().join("npm");
        fs::write(&npm_path, b"#!/bin/sh\n").expect("write npm");
        make_executable(&npm_path);
        let npmrc_path = dir.path().join("user.npmrc");
        fs::write(&npmrc_path, "//registry.npmjs.org/:_authToken=\n").expect("write npmrc");

        let bindings = MemoryBindingStore::new();
        let secrets = MemorySecretStore::new();
        let prepared = prepare_wrapped_invocation(
            CommandKind::Npm,
            WrapperInvocation {
                userconfig_override: Some(npmrc_path),
                resolve_mode: ResolveMode::Auto,
                shell: None,
                explicit_bin: Some(npm_path),
                strict: false,
                allow_unscoped_auth: false,
                args: vec!["--version".into()],
            },
            &bindings,
            &secrets,
        )
        .expect("prepared");

        assert_eq!(prepared.mode, WrapperMode::Passthrough);
        assert!(prepared
            .warnings
            .iter()
            .any(|warning| warning.contains("ignoring empty auth token entry")));
    }
}
