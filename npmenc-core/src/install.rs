#![cfg_attr(test, allow(clippy::unwrap_used))]

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Result;
use enclaveapp_app_adapter::{BindingStore, SecretStore};

use crate::common::restore_previous_secret;
use crate::config_path::resolve_effective_userconfig;
use crate::management::validate_unique_auth_keys;
use crate::npmrc::{
    analyze_auth_entries, discover_scoped_auth_tokens, discover_unscoped_auth_tokens,
    rewrite_with_bindings, RewriteOptions,
};
use crate::provenance::{provenance_for_path, set_provenance_for_path, InstallProvenance};
use crate::registry_bindings::{binding_for_auth_key, default_registry_binding};
use crate::state_lock::with_state_lock;
use crate::token_source::{
    acquire_secret_from_binding_token_source_staged, apply_pending_secret_updates,
    restore_token_source_artifacts, snapshot_token_source_artifacts, token_source_is_reacquirable,
    PendingManagedSecretUpdate, TokenSourceArtifactsSnapshot,
};
use crate::unscoped_auth::{
    classify_unscoped_auth, effective_unscoped_token, looks_like_empty_secret,
    looks_like_placeholder, UnscopedAuthState,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallReport {
    pub path: PathBuf,
    pub imported_labels: Vec<String>,
    pub active_labels: Vec<String>,
    pub rewritten: bool,
    pub warnings: Vec<String>,
}

pub fn install_userconfig<B, S>(
    userconfig_override: Option<&Path>,
    allow_unscoped_auth: bool,
    binding_store: &B,
    secret_store: &S,
) -> Result<InstallReport>
where
    B: BindingStore,
    S: SecretStore,
{
    with_state_lock(|| {
        let path = resolve_effective_userconfig(userconfig_override)?;
        let source = match fs::read_to_string(&path) {
            Ok(contents) => contents,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(error) => return Err(error.into()),
        };
        let diagnostics = analyze_auth_entries(&source);
        let unscoped_tokens = discover_unscoped_auth_tokens(&source);
        let effective_unscoped_token = effective_unscoped_token(&unscoped_tokens);
        let mut warnings = Vec::new();
        if !diagnostics.legacy_auth_keys.is_empty() {
            warnings.push(format!(
                "legacy auth entries were left unchanged: {}",
                diagnostics.legacy_auth_keys.join(", ")
            ));
        }

        let existing = binding_store.list()?;
        validate_unique_auth_keys(&existing)?;
        let existing_bindings = existing
            .iter()
            .map(crate::registry_bindings::RegistryBinding::from_binding_record)
            .collect::<Vec<_>>();
        let mut active_labels = BTreeSet::new();
        let mut seen_labels = existing
            .iter()
            .map(|record| record.label.clone())
            .collect::<BTreeSet<_>>();
        let mut bindings: Vec<crate::registry_bindings::RegistryBinding> = Vec::new();
        let mut imported_labels = Vec::new();
        let mut pending_record_updates = Vec::new();
        let mut pending_secret_updates: Vec<PendingManagedSecretUpdate> = Vec::new();
        let mut placeholder_inactive_labels = BTreeSet::new();
        let managed_default_binding = existing_bindings
            .iter()
            .find(|binding| binding.label == "default")
            .cloned();
        let unscoped_state = classify_unscoped_auth(
            effective_unscoped_token,
            allow_unscoped_auth,
            managed_default_binding.is_some(),
        );
        if unscoped_state.requires_warning_or_strict() {
            warnings.push(format!(
                "unscoped auth entries were left unchanged: {}",
                diagnostics.unscoped_auth_tokens.join(", ")
            ));
        }

        if let Some(value) = effective_unscoped_token {
            if matches!(
                unscoped_state,
                UnscopedAuthState::ManagedPlaceholder | UnscopedAuthState::RawAllowed
            ) {
                let existing_default = existing_bindings
                    .iter()
                    .find(|binding| binding.label == "default")
                    .cloned();
                let binding = existing_default
                    .clone()
                    .unwrap_or_else(default_registry_binding);
                let mut record = existing_record_for_binding(&existing, &binding);
                if looks_like_placeholder(value) {
                    if existing_default.is_none() {
                        return Err(anyhow::anyhow!(
                            "found npmenc-managed unscoped placeholder auth entry in config but no matching managed state exists"
                        ));
                    }
                    if secret_store.get(&binding.id)?.is_some() {
                        set_provenance_for_path(
                            &mut record,
                            &path,
                            InstallProvenance {
                                config_line_origin: "source".to_string(),
                                installed_from_npmrc: true,
                                original_line_kind: Some("unscoped_authToken".to_string()),
                            },
                        )?;
                        pending_record_updates.push(record);
                        active_labels.insert(binding.label.clone());
                        if !bindings
                            .iter()
                            .any(|existing| existing.label == binding.label)
                        {
                            bindings.push(binding);
                        }
                    } else {
                        placeholder_inactive_labels.insert(binding.label.clone());
                    }
                } else if looks_like_empty_secret(value) {
                    warnings.push("ignoring empty unscoped _authToken entry".to_string());
                } else {
                    set_provenance_for_path(
                        &mut record,
                        &path,
                        InstallProvenance {
                            config_line_origin: "source".to_string(),
                            installed_from_npmrc: true,
                            original_line_kind: Some("unscoped_authToken".to_string()),
                        },
                    )?;
                    upsert_record_with_secret_transaction(
                        &binding,
                        value,
                        record,
                        &mut pending_record_updates,
                        &mut pending_secret_updates,
                        None,
                    )?;
                    imported_labels.push(binding.label.clone());
                    active_labels.insert(binding.label.clone());
                    if !bindings
                        .iter()
                        .any(|existing| existing.label == binding.label)
                    {
                        bindings.push(binding);
                    }
                }
            } else if matches!(
                unscoped_state,
                UnscopedAuthState::RawProtectedByManagedDefault
            ) {
                warnings.push(
                    "ignoring materialized unscoped token in config for managed default binding"
                        .to_string(),
                );
            } else if matches!(unscoped_state, UnscopedAuthState::Empty) {
                warnings.push("ignoring empty unscoped _authToken entry".to_string());
            }
            if unscoped_tokens.len() > 1 {
                warnings.push(
                    "multiple unscoped _authToken entries found; install used the last one"
                        .to_string(),
                );
            }
        }

        for token in discover_scoped_auth_tokens(&source) {
            let existing_binding = existing_bindings
                .iter()
                .find(|binding| binding.auth_key == token.auth_key)
                .cloned();
            let binding = existing_binding
                .clone()
                .unwrap_or_else(|| binding_for_auth_key(&token.auth_key, &mut seen_labels));
            let mut record = existing_record_for_binding(&existing, &binding);
            let mut binding_is_active = false;
            if looks_like_placeholder(&token.value) {
                if existing_binding.is_none() {
                    return Err(anyhow::anyhow!(
                    "found npmenc-managed placeholder auth entry in config but no matching managed state exists for: {}",
                    token.auth_key
                ));
                }
                if secret_store.get(&binding.id)?.is_some() {
                    set_provenance_for_path(
                        &mut record,
                        &path,
                        InstallProvenance {
                            config_line_origin: "source".to_string(),
                            installed_from_npmrc: true,
                            original_line_kind: Some("scoped_authToken".to_string()),
                        },
                    )?;
                    pending_record_updates.push(record);
                    binding_is_active = true;
                } else if secret_store.get(&binding.id)?.is_none() {
                    placeholder_inactive_labels.insert(binding.label.clone());
                }
            } else if looks_like_empty_secret(&token.value) {
                warnings.push(format!(
                    "ignoring empty auth token entry for `{}`",
                    token.auth_key
                ));
            } else {
                set_provenance_for_path(
                    &mut record,
                    &path,
                    InstallProvenance {
                        config_line_origin: "source".to_string(),
                        installed_from_npmrc: true,
                        original_line_kind: Some("scoped_authToken".to_string()),
                    },
                )?;
                upsert_record_with_secret_transaction(
                    &binding,
                    &token.value,
                    record,
                    &mut pending_record_updates,
                    &mut pending_secret_updates,
                    None,
                )?;
                imported_labels.push(binding.label.clone());
                binding_is_active = true;
            }
            if binding_is_active {
                active_labels.insert(binding.label.clone());
            }
            if binding_is_active
                && !bindings
                    .iter()
                    .any(|existing| existing.label == binding.label)
            {
                bindings.push(binding);
            }
        }

        for binding in &existing_bindings {
            if active_labels.contains(&binding.label) {
                continue;
            }

            let available_secret = if secret_store.get(&binding.id)?.is_some() {
                None
            } else if let Some(record) = existing.iter().find(|record| record.id == binding.id) {
                if token_source_is_reacquirable(record, secret_store)? {
                    acquire_secret_from_binding_token_source_staged(record, secret_store)?
                } else {
                    continue;
                }
            } else {
                continue;
            };

            let mut record = existing
                .iter()
                .find(|record| record.id == binding.id)
                .cloned()
                .unwrap_or_else(|| binding.to_binding_record());
            ensure_install_provenance(
                &mut record,
                binding,
                &source,
                allow_unscoped_auth,
                managed_default_binding.is_some(),
                &path,
            )?;
            if let Some(staged) = available_secret {
                upsert_record_with_secret_transaction(
                    binding,
                    &staged.secret,
                    record,
                    &mut pending_record_updates,
                    &mut pending_secret_updates,
                    staged.token_source_artifacts,
                )?;
            } else {
                pending_record_updates.push(record);
            }
            active_labels.insert(binding.label.clone());
            bindings.push(binding.clone());
        }

        for binding in &existing_bindings {
            if active_labels.contains(&binding.label) {
                continue;
            }
            if placeholder_inactive_labels.contains(&binding.label) {
                continue;
            }

            warnings.push(format!(
            "binding `{}` exists in managed metadata but has no stored secret; install left it inactive",
            binding.label
        ));
        }
        for label in placeholder_inactive_labels {
            if !active_labels.contains(&label) {
                if label == "default" {
                    warnings.push(
                        "default binding is already in placeholder form but no managed secret was imported"
                            .to_string(),
                    );
                } else {
                    warnings.push(format!(
                        "binding `{label}` is already in placeholder form but no managed secret was imported"
                    ));
                }
            }
        }

        if bindings.is_empty() {
            return Ok(InstallReport {
                path,
                imported_labels,
                active_labels: Vec::new(),
                rewritten: false,
                warnings,
            });
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
        let changed = rewritten.contents != source;
        if changed {
            fs::write(&path, &rewritten.contents)?;
        }
        if let Err(error) = apply_install_state_changes(
            &pending_record_updates,
            &pending_secret_updates,
            binding_store,
            secret_store,
        ) {
            if changed {
                if let Err(restore_error) = fs::write(&path, &source) {
                    return Err(anyhow::anyhow!(
                        "{error}; additionally failed to restore original config at {}: {restore_error}",
                        path.display()
                    ));
                }
            }
            return Err(error);
        }

        Ok(InstallReport {
            path,
            imported_labels,
            active_labels: active_labels.into_iter().collect(),
            rewritten: changed,
            warnings,
        })
    })
}

fn existing_record_for_binding(
    existing: &[enclaveapp_app_adapter::BindingRecord],
    binding: &crate::registry_bindings::RegistryBinding,
) -> enclaveapp_app_adapter::BindingRecord {
    existing
        .iter()
        .find(|record| record.id == binding.id)
        .cloned()
        .unwrap_or_else(|| binding.to_binding_record())
}

fn should_rewrite_unscoped_auth(
    value: Option<&str>,
    allow_unscoped_auth: bool,
    managed_default_binding_active: bool,
) -> bool {
    classify_unscoped_auth(value, allow_unscoped_auth, managed_default_binding_active)
        .should_rewrite()
}

fn upsert_record_with_secret_transaction(
    binding: &crate::registry_bindings::RegistryBinding,
    secret: &str,
    record: enclaveapp_app_adapter::BindingRecord,
    pending_record_updates: &mut Vec<enclaveapp_app_adapter::BindingRecord>,
    pending_secret_updates: &mut Vec<PendingManagedSecretUpdate>,
    token_source_artifacts: Option<TokenSourceArtifactsSnapshot>,
) -> Result<()> {
    pending_record_updates.push(record);
    pending_secret_updates.push(PendingManagedSecretUpdate {
        id: binding.id.clone(),
        secret: secret.to_string(),
        token_source_artifacts,
    });
    Ok(())
}

fn apply_install_state_changes<B, S>(
    pending_record_updates: &[enclaveapp_app_adapter::BindingRecord],
    pending_secret_updates: &[PendingManagedSecretUpdate],
    binding_store: &B,
    secret_store: &S,
) -> Result<()>
where
    B: BindingStore,
    S: SecretStore,
{
    let mut touched_ids = pending_record_updates
        .iter()
        .map(|record| record.id.clone())
        .collect::<BTreeSet<_>>();
    touched_ids.extend(
        pending_secret_updates
            .iter()
            .map(|update| update.id.clone()),
    );

    let previous_records = touched_ids
        .iter()
        .map(|id| Ok((id.clone(), binding_store.get(id)?)))
        .collect::<Result<Vec<_>>>()?;
    let previous_secrets = touched_ids
        .iter()
        .map(|id| Ok((id.clone(), secret_store.get(id)?)))
        .collect::<Result<Vec<_>>>()?;
    let previous_token_source_states = touched_ids
        .iter()
        .map(|id| {
            Ok((
                id.clone(),
                snapshot_token_source_artifacts(id, secret_store)?,
            ))
        })
        .collect::<Result<Vec<_>>>()?;

    if let Err(error) = apply_pending_secret_updates(pending_secret_updates, secret_store) {
        rollback_install_state(
            &previous_records,
            &previous_secrets,
            &previous_token_source_states,
            binding_store,
            secret_store,
        )?;
        return Err(error);
    }
    for record in pending_record_updates {
        if let Err(error) = binding_store.upsert(record.clone()) {
            rollback_install_state(
                &previous_records,
                &previous_secrets,
                &previous_token_source_states,
                binding_store,
                secret_store,
            )?;
            return Err(error.into());
        }
    }
    Ok(())
}

fn rollback_install_state<B, S>(
    previous_records: &[(
        enclaveapp_app_adapter::BindingId,
        Option<enclaveapp_app_adapter::BindingRecord>,
    )],
    previous_secrets: &[(enclaveapp_app_adapter::BindingId, Option<String>)],
    previous_token_source_states: &[(
        enclaveapp_app_adapter::BindingId,
        TokenSourceArtifactsSnapshot,
    )],
    binding_store: &B,
    secret_store: &S,
) -> Result<()>
where
    B: BindingStore,
    S: SecretStore,
{
    for (id, secret) in previous_secrets {
        restore_previous_secret(secret_store, id, secret.as_deref())?;
    }
    for (id, token_source_state) in previous_token_source_states {
        restore_token_source_artifacts(id, token_source_state, secret_store)?;
    }
    for (id, record) in previous_records {
        match record {
            Some(record) => binding_store.upsert(record.clone())?,
            None => {
                let _ = binding_store.delete(id)?;
            }
        }
    }
    Ok(())
}

fn ensure_install_provenance(
    record: &mut enclaveapp_app_adapter::BindingRecord,
    binding: &crate::registry_bindings::RegistryBinding,
    source: &str,
    allow_unscoped_auth: bool,
    managed_default_binding_active: bool,
    path: &Path,
) -> Result<()> {
    let path_string = path.to_string_lossy().into_owned();
    if provenance_for_path(record, &path_string).is_some() {
        return Ok(());
    }

    let original_line_kind = source_line_kind(
        source,
        binding,
        allow_unscoped_auth,
        managed_default_binding_active,
    );
    let origin = if original_line_kind.is_some() {
        "source"
    } else {
        "appended"
    };
    set_provenance_for_path(
        record,
        path,
        InstallProvenance {
            config_line_origin: origin.to_string(),
            installed_from_npmrc: false,
            original_line_kind,
        },
    )
}

fn source_line_kind(
    source: &str,
    binding: &crate::registry_bindings::RegistryBinding,
    allow_unscoped_auth: bool,
    managed_default_binding_active: bool,
) -> Option<String> {
    if source.lines().any(|line| {
        let trimmed = line.trim();
        trimmed.starts_with(&binding.auth_key) && trimmed.contains('=')
    }) {
        return Some("scoped_authToken".to_string());
    }

    if binding.label == "default" {
        let state = classify_unscoped_auth(
            effective_unscoped_token(&discover_unscoped_auth_tokens(source)),
            allow_unscoped_auth,
            managed_default_binding_active,
        );
        if let Some(kind) = state.source_line_kind() {
            return Some(kind.to_string());
        }
    }

    None
}

#[cfg(all(test, unix))]
mod tests {
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    use enclaveapp_app_adapter::{
        BindingStore, MemoryBindingStore, MemorySecretStore, SecretStore,
    };
    use tempfile::TempDir;

    use super::*;

    #[test]
    fn install_interns_tokens_and_rewrites_file() {
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join("user.npmrc");
        fs::write(
            &path,
            "//registry.npmjs.org/:_authToken=npm_ABC123\n//artifactory.example.com/api/npm/npm/:_authToken=jwt\n",
        )
        .expect("write");

        let bindings = MemoryBindingStore::new();
        let secrets = MemorySecretStore::new();

        let report = install_userconfig(Some(&path), false, &bindings, &secrets).expect("install");
        assert!(report.rewritten);
        assert_eq!(report.imported_labels.len(), 2);
        assert_eq!(report.active_labels.len(), 2);
        assert!(report.warnings.is_empty());

        let updated = fs::read_to_string(&path).expect("read");
        assert!(updated.contains("${NPM_TOKEN_DEFAULT}"));
        assert!(updated.contains("${NPM_TOKEN_ARTIFACTORY_EXAMPLE_COM_API_NPM_NPM}"));

        let stored = bindings.list().expect("list");
        assert_eq!(stored.len(), 2);
        assert_eq!(
            secrets
                .get(&enclaveapp_app_adapter::BindingId::new("npm:default"))
                .expect("secret"),
            Some("npm_ABC123".to_string())
        );
    }

    #[test]
    fn install_reuses_existing_binding_for_same_auth_key() {
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join("user.npmrc");
        fs::write(&path, "//registry.npmjs.org/:_authToken=npm_ABC123\n").expect("write");

        let bindings = MemoryBindingStore::new();
        let secrets = MemorySecretStore::new();
        let existing = default_registry_binding();
        bindings
            .upsert(existing.to_binding_record())
            .expect("upsert");

        let report = install_userconfig(Some(&path), false, &bindings, &secrets).expect("install");
        assert_eq!(report.imported_labels, vec!["default".to_string()]);
        assert_eq!(bindings.list().expect("list").len(), 1);
    }

    #[test]
    fn install_can_import_unscoped_auth_when_allowed() {
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join("user.npmrc");
        fs::write(&path, "_authToken=npm_ABC123\n").expect("write");

        let bindings = MemoryBindingStore::new();
        let secrets = MemorySecretStore::new();

        let report = install_userconfig(Some(&path), true, &bindings, &secrets).expect("install");
        assert_eq!(report.imported_labels, vec!["default".to_string()]);
        assert_eq!(report.active_labels, vec!["default".to_string()]);
        let updated = fs::read_to_string(&path).expect("read");
        assert!(updated.contains("//registry.npmjs.org/:_authToken=${NPM_TOKEN_DEFAULT}"));
    }

    #[test]
    fn install_uses_last_unscoped_auth_token() {
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join("user.npmrc");
        fs::write(&path, "_authToken=first\n_authToken=second\n").expect("write");

        let bindings = MemoryBindingStore::new();
        let secrets = MemorySecretStore::new();

        let report = install_userconfig(Some(&path), true, &bindings, &secrets).expect("install");

        assert_eq!(report.imported_labels, vec!["default".to_string()]);
        assert!(report
            .warnings
            .iter()
            .any(|warning| warning.contains("used the last one")));
        assert_eq!(
            secrets
                .get(&enclaveapp_app_adapter::BindingId::new("npm:default"))
                .expect("secret"),
            Some("second".to_string())
        );
    }

    #[test]
    fn install_ignores_empty_unscoped_auth_as_source_state() {
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join("user.npmrc");
        fs::write(&path, "_authToken=\ncolor=true\n").expect("write");

        let bindings = MemoryBindingStore::new();
        let secrets = MemorySecretStore::new();
        let binding = default_registry_binding();
        bindings
            .upsert(binding.to_binding_record())
            .expect("upsert binding");
        secrets.set(&binding.id, "npm_ABC123").expect("set secret");

        let report = install_userconfig(Some(&path), false, &bindings, &secrets).expect("install");

        assert!(report.active_labels.iter().any(|label| label == "default"));
        let updated = fs::read_to_string(&path).expect("read");
        assert!(updated.contains("_authToken=\n"));
        assert!(updated.contains("//registry.npmjs.org/:_authToken=${NPM_TOKEN_DEFAULT}\n"));
        let stored = bindings.get(&binding.id).expect("get").expect("record");
        assert_eq!(
            stored.metadata.get("config_line_origin"),
            Some(&"appended".to_string())
        );
    }

    #[test]
    fn install_recognizes_managed_unscoped_placeholder_without_flag() {
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join("user.npmrc");
        fs::write(&path, "_authToken=${NPM_TOKEN_DEFAULT}\n").expect("write");

        let bindings = MemoryBindingStore::new();
        let secrets = MemorySecretStore::new();
        let binding = default_registry_binding();
        bindings
            .upsert(binding.to_binding_record())
            .expect("upsert binding");
        secrets.set(&binding.id, "npm_ABC123").expect("set secret");

        let report = install_userconfig(Some(&path), false, &bindings, &secrets).expect("install");

        assert_eq!(report.active_labels, vec!["default".to_string()]);
        assert!(!report
            .warnings
            .iter()
            .any(|warning| warning.contains("unscoped auth entries were left unchanged")));

        let updated = fs::read_to_string(&path).expect("read");
        assert!(updated.contains("//registry.npmjs.org/:_authToken=${NPM_TOKEN_DEFAULT}"));
        assert!(!updated
            .lines()
            .any(|line| line.trim() == "_authToken=${NPM_TOKEN_DEFAULT}"));
    }

    #[test]
    fn install_rewrites_raw_unscoped_auth_when_managed_default_binding_is_active() {
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join("user.npmrc");
        fs::write(&path, "_authToken=file_token\n").expect("write");

        let bindings = MemoryBindingStore::new();
        let secrets = MemorySecretStore::new();
        let binding = default_registry_binding();
        bindings
            .upsert(binding.to_binding_record())
            .expect("upsert binding");
        secrets
            .set(&binding.id, "managed_token")
            .expect("set secret");

        let report = install_userconfig(Some(&path), false, &bindings, &secrets).expect("install");

        assert_eq!(report.active_labels, vec!["default".to_string()]);
        let updated = fs::read_to_string(&path).expect("read");
        assert_eq!(
            updated,
            "//registry.npmjs.org/:_authToken=${NPM_TOKEN_DEFAULT}\n"
        );
        assert_eq!(
            secrets.get(&binding.id).expect("secret"),
            Some("managed_token".to_string())
        );
        let stored = bindings.get(&binding.id).expect("get").expect("record");
        let path_string = path.to_string_lossy().into_owned();
        let provenance = provenance_for_path(&stored, &path_string).expect("provenance");
        assert_eq!(provenance.config_line_origin, "source");
        assert_eq!(
            provenance.original_line_kind.as_deref(),
            Some("unscoped_authToken")
        );
    }

    #[test]
    fn install_projects_existing_managed_binding_into_empty_file() {
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join("user.npmrc");
        fs::write(&path, "color=true\n").expect("write");

        let bindings = MemoryBindingStore::new();
        let secrets = MemorySecretStore::new();
        let binding = default_registry_binding();
        bindings
            .upsert(binding.to_binding_record())
            .expect("upsert binding");
        secrets.set(&binding.id, "npm_ABC123").expect("set secret");

        let report = install_userconfig(Some(&path), false, &bindings, &secrets).expect("install");
        assert!(report.imported_labels.is_empty());
        assert_eq!(report.active_labels, vec!["default".to_string()]);

        let updated = fs::read_to_string(&path).expect("read");
        assert!(updated.contains("color=true\n"));
        assert!(updated.contains("//registry.npmjs.org/:_authToken=${NPM_TOKEN_DEFAULT}\n"));

        let stored = bindings.list().expect("list");
        let default = stored
            .into_iter()
            .find(|record| record.label == "default")
            .expect("default binding");
        assert_eq!(
            default.metadata.get("config_line_origin"),
            Some(&"appended".to_string())
        );
        assert_eq!(
            default.metadata.get("installed_from_npmrc"),
            Some(&"false".to_string())
        );
        assert_eq!(
            default.metadata.get("original_config_path"),
            Some(&path.to_string_lossy().into_owned())
        );
    }

    #[test]
    fn install_activates_binding_via_token_source_when_secret_is_missing() {
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join("user.npmrc");
        let token_source = dir.path().join("source-token");
        fs::write(&path, "color=true\n").expect("write");
        fs::write(&token_source, "#!/bin/sh\nprintf 'token-from-source\\n'\n").expect("write");
        let mut perms = fs::metadata(&token_source).expect("metadata").permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&token_source, perms).expect("chmod");

        let bindings = MemoryBindingStore::new();
        let secrets = MemorySecretStore::new();
        let mut record = default_registry_binding().to_binding_record();
        record.metadata.insert(
            "token_source".to_string(),
            token_source.to_string_lossy().into_owned(),
        );
        bindings.upsert(record.clone()).expect("upsert binding");

        let report = install_userconfig(Some(&path), false, &bindings, &secrets).expect("install");

        assert!(report.imported_labels.is_empty());
        assert_eq!(report.active_labels, vec!["default".to_string()]);
        assert_eq!(
            secrets.get(&record.id).expect("secret"),
            Some("token-from-source".to_string())
        );
    }

    #[test]
    fn install_does_not_warn_for_placeholder_binding_activated_via_token_source() {
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join("user.npmrc");
        let token_source = dir.path().join("source-token");
        fs::write(&path, "_authToken=${NPM_TOKEN_DEFAULT}\n").expect("write");
        fs::write(&token_source, "#!/bin/sh\nprintf 'token-from-source\\n'\n").expect("write");
        let mut perms = fs::metadata(&token_source).expect("metadata").permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&token_source, perms).expect("chmod");

        let bindings = MemoryBindingStore::new();
        let secrets = MemorySecretStore::new();
        let mut record = default_registry_binding().to_binding_record();
        record.metadata.insert(
            "token_source".to_string(),
            token_source.to_string_lossy().into_owned(),
        );
        bindings.upsert(record).expect("upsert binding");

        let report = install_userconfig(Some(&path), false, &bindings, &secrets).expect("install");

        assert_eq!(report.active_labels, vec!["default".to_string()]);
        assert!(!report
            .warnings
            .iter()
            .any(|warning| warning.contains("no managed secret was imported")));
        assert_eq!(
            secrets
                .get(&enclaveapp_app_adapter::BindingId::new("npm:default"))
                .expect("secret"),
            Some("token-from-source".to_string())
        );
    }

    #[test]
    fn install_preserves_existing_source_provenance_on_token_source_reactivation() {
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join("user.npmrc");
        let token_source = dir.path().join("source-token");
        fs::write(&path, "color=true\n").expect("write");
        fs::write(&token_source, "#!/bin/sh\nprintf 'token-from-source\\n'\n").expect("write");
        let mut perms = fs::metadata(&token_source).expect("metadata").permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&token_source, perms).expect("chmod");

        let bindings = MemoryBindingStore::new();
        let secrets = MemorySecretStore::new();
        let mut record = default_registry_binding().to_binding_record();
        record.metadata.insert(
            "token_source".to_string(),
            token_source.to_string_lossy().into_owned(),
        );
        set_provenance_for_path(
            &mut record,
            &path,
            InstallProvenance {
                config_line_origin: "source".to_string(),
                installed_from_npmrc: true,
                original_line_kind: Some("scoped_authToken".to_string()),
            },
        )
        .expect("provenance");
        bindings.upsert(record.clone()).expect("upsert binding");

        let report = install_userconfig(Some(&path), false, &bindings, &secrets).expect("install");

        assert_eq!(report.active_labels, vec!["default".to_string()]);
        let stored = bindings.get(&record.id).expect("get").expect("record");
        let path_string = path.to_string_lossy().into_owned();
        let provenance = provenance_for_path(&stored, &path_string).expect("provenance");
        assert!(provenance.installed_from_npmrc);
        assert_eq!(
            provenance.original_line_kind,
            Some("scoped_authToken".to_string())
        );
    }

    #[test]
    fn install_preserves_existing_token_source_metadata() {
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join("user.npmrc");
        let token_source = dir.path().join("source-token");
        fs::write(
            &path,
            "//registry.npmjs.org/:_authToken=${NPM_TOKEN_DEFAULT}\n",
        )
        .expect("write");
        fs::write(&token_source, "#!/bin/sh\nprintf 'token-from-source\\n'\n").expect("write");
        let mut perms = fs::metadata(&token_source).expect("metadata").permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&token_source, perms).expect("chmod");

        let bindings = MemoryBindingStore::new();
        let secrets = MemorySecretStore::new();
        let mut record = default_registry_binding().to_binding_record();
        record.metadata.insert(
            "token_source".to_string(),
            token_source.to_string_lossy().into_owned(),
        );
        bindings.upsert(record.clone()).expect("upsert binding");
        secrets.set(&record.id, "token").expect("set secret");

        let report = install_userconfig(Some(&path), false, &bindings, &secrets).expect("install");

        assert_eq!(report.active_labels, vec!["default".to_string()]);
        let stored = bindings.get(&record.id).expect("get").expect("record");
        let expected = shlex::try_quote(&token_source.to_string_lossy())
            .expect("quoted")
            .into_owned();
        assert_eq!(
            crate::token_source::token_source_command(&stored, &secrets)
                .expect("token source")
                .as_deref(),
            Some(expected.as_str())
        );
        assert!(crate::token_source::token_source_display(&stored)
            .expect("token source display")
            .expect("display")
            .starts_with("command:source-token#"));
    }

    #[test]
    fn install_prefers_materialized_source_token_over_stale_token_source() {
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join("user.npmrc");
        let missing = dir.path().join("missing-source");
        fs::write(&path, "//registry.npmjs.org/:_authToken=file_token\n").expect("write");

        let bindings = MemoryBindingStore::new();
        let secrets = MemorySecretStore::new();
        let mut record = default_registry_binding().to_binding_record();
        record.metadata.insert(
            "token_source".to_string(),
            missing.to_string_lossy().into_owned(),
        );
        bindings.upsert(record.clone()).expect("upsert");

        let report = install_userconfig(Some(&path), false, &bindings, &secrets).expect("install");

        assert_eq!(report.imported_labels, vec!["default".to_string()]);
        assert_eq!(
            secrets.get(&record.id).expect("get secret"),
            Some("file_token".to_string())
        );
    }

    #[test]
    fn install_rejects_unscoped_placeholder_without_matching_managed_state() {
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join("user.npmrc");
        fs::write(&path, "_authToken=${NPM_TOKEN_DEFAULT}\n").expect("write");

        let bindings = MemoryBindingStore::new();
        let secrets = MemorySecretStore::new();
        let error = install_userconfig(Some(&path), true, &bindings, &secrets)
            .expect_err("placeholder without state should fail");

        assert!(error
            .to_string()
            .contains("unscoped placeholder auth entry"));
    }

    #[test]
    fn install_rejects_scoped_placeholder_without_matching_managed_state() {
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join("user.npmrc");
        fs::write(
            &path,
            "//registry.npmjs.org/:_authToken=${NPM_TOKEN_DEFAULT}\n",
        )
        .expect("write");

        let bindings = MemoryBindingStore::new();
        let secrets = MemorySecretStore::new();
        let error = install_userconfig(Some(&path), false, &bindings, &secrets)
            .expect_err("placeholder without state should fail");

        assert!(error
            .to_string()
            .contains("no matching managed state exists"));
    }

    #[test]
    fn install_does_not_record_provenance_for_placeholder_without_secret() {
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join("user.npmrc");
        fs::write(
            &path,
            "//registry.npmjs.org/:_authToken=${NPM_TOKEN_DEFAULT}\n",
        )
        .expect("write");

        let bindings = MemoryBindingStore::new();
        let secrets = MemorySecretStore::new();
        let record = default_registry_binding().to_binding_record();
        bindings.upsert(record.clone()).expect("upsert");

        let report = install_userconfig(Some(&path), false, &bindings, &secrets).expect("install");

        assert!(report.active_labels.is_empty());
        let stored = bindings.get(&record.id).expect("get").expect("record");
        assert_eq!(stored.metadata.get("original_config_path"), None);
        assert_eq!(stored.metadata.get("config_line_origin"), None);
    }

    #[test]
    fn install_ignores_empty_source_token_entries() {
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join("user.npmrc");
        fs::write(&path, "//registry.npmjs.org/:_authToken=\n").expect("write");

        let bindings = MemoryBindingStore::new();
        let secrets = MemorySecretStore::new();
        let report = install_userconfig(Some(&path), false, &bindings, &secrets).expect("install");

        assert!(report.imported_labels.is_empty());
        assert!(report.active_labels.is_empty());
        assert!(report
            .warnings
            .iter()
            .any(|warning| warning.contains("ignoring empty auth token entry")));
    }
}
