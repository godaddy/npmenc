#![cfg_attr(test, allow(clippy::unwrap_used))]

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Result;
use enclaveapp_app_adapter::{AdapterError, BindingStore, SecretStore};

use crate::atomic_write::atomic_write_preserving_mode;
use crate::common::restore_previous_secret;
use crate::config_path::resolve_effective_userconfig;
use crate::management::validate_unique_auth_keys;
use crate::npmrc::{
    discover_scoped_auth_tokens, dominant_newline, split_line_ending,
    split_lines_preserving_endings,
};
use crate::provenance::{
    applies_to_config_path, provenance_for_path, remove_provenance_for_path, InstallProvenance,
};
use crate::registry_bindings::RegistryBinding;
use crate::state_lock::with_state_lock;
use crate::token_source::{
    acquire_secret_from_binding_token_source_staged, apply_pending_secret_updates,
    clear_token_source_state, restore_token_source_artifacts, snapshot_token_source_artifacts,
    PendingManagedSecretUpdate,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UninstallReport {
    pub path: PathBuf,
    pub restored_labels: Vec<String>,
    pub removed_labels: Vec<String>,
    pub purged: bool,
}

pub fn uninstall_userconfig<B, S>(
    userconfig_override: Option<&Path>,
    purge: bool,
    binding_store: &B,
    secret_store: &S,
) -> Result<UninstallReport>
where
    B: BindingStore,
    S: SecretStore,
{
    with_state_lock(|| {
        let path = resolve_effective_userconfig(userconfig_override)?;
        let path_string = path.to_string_lossy().into_owned();
        let source = match fs::read_to_string(&path) {
            Ok(contents) => contents,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(error) => return Err(error.into()),
        };
        let source_scoped_auth_keys = discover_scoped_auth_tokens(&source)
            .into_iter()
            .map(|token| token.auth_key)
            .collect::<std::collections::BTreeSet<_>>();

        let records = binding_store.list()?;
        validate_unique_auth_keys(&records)?;
        let binding_records = records
            .into_iter()
            .filter(|record| applies_to_config_path(record, &path_string))
            .collect::<Vec<_>>();
        let mut secrets = BTreeMap::new();
        let mut pending_secret_updates: Vec<PendingManagedSecretUpdate> = Vec::new();
        let mut restored_labels = Vec::new();
        let mut removed_labels = Vec::new();
        for record in &binding_records {
            let binding = RegistryBinding::from_binding_record(record);
            match uninstall_action_for_record(
                record,
                &binding,
                &source_scoped_auth_keys,
                &path_string,
            ) {
                UninstallAction::None => {}
                UninstallAction::RemoveManagedLine => {
                    removed_labels.push(binding.label.clone());
                }
                UninstallAction::RestoreMaterialized => {
                    let (secret, pending_update) =
                        secret_for_uninstall(record, &binding, secret_store)?;
                    if !purge {
                        if let Some(update) = pending_update {
                            pending_secret_updates.push(update);
                        }
                    }
                    secrets.insert(binding.label.clone(), secret);
                    restored_labels.push(binding.label.clone());
                }
            }
        }

        let restored = restore_with_provenance(
            &source,
            &binding_records,
            &secrets,
            &source_scoped_auth_keys,
            &path_string,
        );
        let changed = restored != source;
        if changed {
            atomic_write_preserving_mode(&path, restored.as_bytes())?;
        }

        let pending_updates = match build_uninstall_updates(&binding_records, &path_string, purge) {
            Ok(updates) => updates,
            Err(error) => {
                if changed {
                    if let Err(restore_error) =
                        atomic_write_preserving_mode(&path, source.as_bytes())
                    {
                        return Err(anyhow::anyhow!(
                            "{error}; additionally failed to restore original config at {}: {restore_error}",
                            path.display()
                        ));
                    }
                }
                return Err(error);
            }
        };
        if let Err(error) = apply_uninstall_state_changes(
            &pending_updates,
            &pending_secret_updates,
            binding_store,
            secret_store,
        ) {
            if changed {
                if let Err(restore_error) = atomic_write_preserving_mode(&path, source.as_bytes()) {
                    return Err(anyhow::anyhow!(
                        "{error}; additionally failed to restore original config at {}: {restore_error}",
                        path.display()
                    ));
                }
            }
            return Err(error);
        }

        Ok(UninstallReport {
            path,
            restored_labels,
            removed_labels,
            purged: purge,
        })
    })
}

#[derive(Debug, Clone)]
enum PendingUninstallUpdate {
    Upsert(enclaveapp_app_adapter::BindingRecord),
    Delete {
        id: enclaveapp_app_adapter::BindingId,
        delete_secret: bool,
        delete_token_source_state: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UninstallAction {
    None,
    RemoveManagedLine,
    RestoreMaterialized,
}

fn build_uninstall_updates(
    binding_records: &[enclaveapp_app_adapter::BindingRecord],
    path_string: &str,
    purge: bool,
) -> Result<Vec<PendingUninstallUpdate>> {
    let mut updates = Vec::with_capacity(binding_records.len());
    for mut record in binding_records.iter().cloned() {
        let binding = RegistryBinding::from_binding_record(&record);
        let has_remaining_provenance = remove_provenance_for_path(&mut record, path_string)?;
        if purge {
            if has_remaining_provenance {
                updates.push(PendingUninstallUpdate::Upsert(record));
            } else {
                updates.push(PendingUninstallUpdate::Delete {
                    id: binding.id,
                    delete_secret: true,
                    delete_token_source_state: true,
                });
            }
        } else {
            updates.push(PendingUninstallUpdate::Upsert(record));
        }
    }
    Ok(updates)
}

fn apply_uninstall_state_changes<B, S>(
    pending_updates: &[PendingUninstallUpdate],
    pending_secret_updates: &[PendingManagedSecretUpdate],
    binding_store: &B,
    secret_store: &S,
) -> Result<()>
where
    B: BindingStore,
    S: SecretStore,
{
    let touched_ids = pending_updates
        .iter()
        .map(|update| match update {
            PendingUninstallUpdate::Upsert(record) => record.id.clone(),
            PendingUninstallUpdate::Delete { id, .. } => id.clone(),
        })
        .collect::<Vec<_>>();
    let previous_token_source_states = touched_ids
        .iter()
        .map(|id| {
            Ok((
                id.clone(),
                snapshot_token_source_artifacts(id, secret_store)?,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    let previous_records = touched_ids
        .iter()
        .map(|id| Ok((id.clone(), binding_store.get(id)?)))
        .collect::<Result<Vec<_>>>()?;
    let previous_secrets = touched_ids
        .iter()
        .map(|id| Ok((id.clone(), secret_store.get(id)?)))
        .collect::<Result<Vec<_>>>()?;

    if let Err(error) = apply_pending_secret_updates(pending_secret_updates, secret_store) {
        rollback_uninstall_state(
            &previous_records,
            &previous_secrets,
            &previous_token_source_states,
            binding_store,
            secret_store,
        )?;
        return Err(error);
    }
    for update in pending_updates {
        if let Err(error) = apply_uninstall_update(update, binding_store, secret_store) {
            rollback_uninstall_state(
                &previous_records,
                &previous_secrets,
                &previous_token_source_states,
                binding_store,
                secret_store,
            )?;
            return Err(error);
        }
    }
    Ok(())
}

fn apply_uninstall_update<B, S>(
    update: &PendingUninstallUpdate,
    binding_store: &B,
    secret_store: &S,
) -> Result<()>
where
    B: BindingStore,
    S: SecretStore,
{
    match update {
        PendingUninstallUpdate::Upsert(record) => binding_store.upsert(record.clone())?,
        PendingUninstallUpdate::Delete {
            id,
            delete_secret,
            delete_token_source_state,
        } => {
            let _deleted_binding = binding_store.delete(id)?;
            if *delete_secret {
                let _deleted_secret = secret_store.delete(id)?;
            }
            if *delete_token_source_state {
                clear_token_source_state(id, secret_store)?;
            }
        }
    }
    Ok(())
}

fn rollback_uninstall_state<B, S>(
    previous_records: &[(
        enclaveapp_app_adapter::BindingId,
        Option<enclaveapp_app_adapter::BindingRecord>,
    )],
    previous_secrets: &[(enclaveapp_app_adapter::BindingId, Option<String>)],
    previous_token_source_states: &[(
        enclaveapp_app_adapter::BindingId,
        crate::token_source::TokenSourceArtifactsSnapshot,
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
                let _deleted_binding = binding_store.delete(id)?;
            }
        }
    }
    Ok(())
}

fn restore_with_provenance(
    source: &str,
    binding_records: &[enclaveapp_app_adapter::BindingRecord],
    secrets: &BTreeMap<String, String>,
    source_scoped_auth_keys: &std::collections::BTreeSet<String>,
    path: &str,
) -> String {
    let mut contents = String::with_capacity(source.len());
    let mut restored_keys = std::collections::BTreeSet::new();

    for line in split_lines_preserving_endings(source) {
        let (body, line_ending) = split_line_ending(line);
        if let Some((lhs, _rhs)) = body.split_once('=') {
            let key = lhs.trim();
            if let Some((record, action, secret)) = binding_records.iter().find_map(|record| {
                let binding = RegistryBinding::from_binding_record(record);
                let provenance = provenance_for_path(record, path)?;
                let action =
                    uninstall_action_for_record(record, &binding, source_scoped_auth_keys, path);
                let matches = match action {
                    UninstallAction::None => false,
                    UninstallAction::RemoveManagedLine => key == binding.auth_key,
                    UninstallAction::RestoreMaterialized => {
                        key == binding.auth_key
                            || (provenance.original_line_kind.as_deref()
                                == Some("unscoped_authToken")
                                && key == "_authToken")
                    }
                };
                if !matches {
                    return None;
                }
                let secret = secrets.get(&binding.label);
                Some((record, action, secret))
            }) {
                let Some(provenance) = provenance_for_path(record, path) else {
                    contents.push_str(line);
                    continue;
                };
                if action == UninstallAction::RemoveManagedLine {
                    restored_keys.insert(record.id.clone());
                    continue;
                }
                let Some(secret) = secret else {
                    continue;
                };
                let binding = RegistryBinding::from_binding_record(record);
                let replacement_key = replacement_key_for_uninstall(&provenance, &binding);
                contents.push_str(&replacement_key);
                contents.push('=');
                contents.push_str(secret);
                contents.push_str(line_ending);
                restored_keys.insert(record.id.clone());
                continue;
            }
        }

        contents.push_str(line);
    }

    let newline = dominant_newline(source);
    for record in binding_records {
        let Some(provenance) = provenance_for_path(record, path) else {
            continue;
        };
        let binding = RegistryBinding::from_binding_record(record);
        if restored_keys.contains(&record.id)
            || uninstall_action_for_record(record, &binding, source_scoped_auth_keys, path)
                != UninstallAction::RestoreMaterialized
            || !record_should_append_on_uninstall(&provenance)
        {
            continue;
        }

        let Some(secret) = secrets.get(&binding.label) else {
            continue;
        };
        if !contents.is_empty() && !contents.ends_with('\n') {
            contents.push_str(newline);
        }
        contents.push_str(&replacement_key_for_uninstall(&provenance, &binding));
        contents.push('=');
        contents.push_str(secret);
        contents.push_str(newline);
    }

    contents
}

fn uninstall_action_for_record(
    record: &enclaveapp_app_adapter::BindingRecord,
    binding: &RegistryBinding,
    source_scoped_auth_keys: &std::collections::BTreeSet<String>,
    path: &str,
) -> UninstallAction {
    let Some(provenance) = provenance_for_path(record, path) else {
        return UninstallAction::None;
    };
    if record_should_append_on_uninstall(&provenance) {
        return UninstallAction::RestoreMaterialized;
    }
    if source_scoped_auth_keys.contains(&binding.auth_key) {
        UninstallAction::RemoveManagedLine
    } else {
        UninstallAction::None
    }
}

fn record_should_append_on_uninstall(provenance: &InstallProvenance) -> bool {
    provenance.config_line_origin == "source"
}

fn replacement_key_for_uninstall(
    provenance: &InstallProvenance,
    binding: &RegistryBinding,
) -> String {
    if provenance.original_line_kind.as_deref() == Some("unscoped_authToken") {
        "_authToken".to_string()
    } else {
        binding.auth_key.clone()
    }
}

fn secret_for_uninstall<S>(
    record: &enclaveapp_app_adapter::BindingRecord,
    binding: &RegistryBinding,
    secret_store: &S,
) -> Result<(String, Option<PendingManagedSecretUpdate>)>
where
    S: SecretStore,
{
    if let Some(secret) = secret_store.get(&binding.id)? {
        return Ok((secret, None));
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

#[cfg(all(test, unix))]
mod tests {
    use std::collections::HashMap;
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Mutex;

    use enclaveapp_app_adapter::{
        AdapterError, BindingId, BindingRecord, BindingStore, MemoryBindingStore,
        MemorySecretStore, SecretStore,
    };
    use tempfile::TempDir;

    use super::*;
    use crate::provenance::{set_provenance_for_path, InstallProvenance};

    fn canon(dir: &TempDir) -> PathBuf {
        dir.path()
            .canonicalize()
            .unwrap_or_else(|_| dir.path().to_path_buf())
    }

    #[derive(Debug, Default)]
    struct FailingBindingStore {
        records: Mutex<Vec<BindingRecord>>,
        fail_on_upsert: bool,
    }

    impl FailingBindingStore {
        fn with_records(records: Vec<BindingRecord>, fail_on_upsert: bool) -> Self {
            Self {
                records: Mutex::new(records),
                fail_on_upsert,
            }
        }
    }

    impl BindingStore for FailingBindingStore {
        fn list(&self) -> std::result::Result<Vec<BindingRecord>, AdapterError> {
            Ok(self
                .records
                .lock()
                .map_err(|_| AdapterError::Storage("binding store mutex poisoned".to_string()))?
                .clone())
        }

        fn get(&self, id: &BindingId) -> std::result::Result<Option<BindingRecord>, AdapterError> {
            Ok(self
                .records
                .lock()
                .map_err(|_| AdapterError::Storage("binding store mutex poisoned".to_string()))?
                .iter()
                .find(|record| &record.id == id)
                .cloned())
        }

        fn upsert(&self, record: BindingRecord) -> std::result::Result<(), AdapterError> {
            if self.fail_on_upsert {
                return Err(AdapterError::Storage(
                    "simulated upsert failure".to_string(),
                ));
            }
            let mut records = self
                .records
                .lock()
                .map_err(|_| AdapterError::Storage("binding store mutex poisoned".to_string()))?;
            if let Some(existing) = records.iter_mut().find(|entry| entry.id == record.id) {
                *existing = record;
            } else {
                records.push(record);
            }
            Ok(())
        }

        fn delete(&self, id: &BindingId) -> std::result::Result<bool, AdapterError> {
            let mut records = self
                .records
                .lock()
                .map_err(|_| AdapterError::Storage("binding store mutex poisoned".to_string()))?;
            let before = records.len();
            records.retain(|record| &record.id != id);
            Ok(before != records.len())
        }

        fn mutate<T, F>(&self, update: F) -> std::result::Result<T, AdapterError>
        where
            F: FnOnce(&mut Vec<BindingRecord>) -> std::result::Result<T, AdapterError>,
        {
            let mut records = self
                .records
                .lock()
                .map_err(|_| AdapterError::Storage("binding store mutex poisoned".to_string()))?;
            update(&mut records)
        }
    }

    #[derive(Debug, Default)]
    struct SimpleSecretStore {
        values: Mutex<HashMap<BindingId, String>>,
    }

    impl SecretStore for SimpleSecretStore {
        fn set(&self, id: &BindingId, secret: &str) -> std::result::Result<(), AdapterError> {
            self.values
                .lock()
                .map_err(|_| AdapterError::Storage("secret store mutex poisoned".to_string()))?
                .insert(id.clone(), secret.to_string());
            Ok(())
        }

        fn get(&self, id: &BindingId) -> std::result::Result<Option<String>, AdapterError> {
            Ok(self
                .values
                .lock()
                .map_err(|_| AdapterError::Storage("secret store mutex poisoned".to_string()))?
                .get(id)
                .cloned())
        }

        fn delete(&self, id: &BindingId) -> std::result::Result<bool, AdapterError> {
            Ok(self
                .values
                .lock()
                .map_err(|_| AdapterError::Storage("secret store mutex poisoned".to_string()))?
                .remove(id)
                .is_some())
        }
    }

    #[test]
    fn uninstall_materializes_placeholders() {
        let dir = TempDir::new().expect("temp dir");
        let path = canon(&dir).join("user.npmrc");
        fs::write(
            &path,
            "//registry.npmjs.org/:_authToken=${NPM_TOKEN_DEFAULT}\n",
        )
        .expect("write");

        let bindings = MemoryBindingStore::new();
        let secrets = MemorySecretStore::new();
        let binding = crate::registry_bindings::default_registry_binding();
        let mut record = binding.to_binding_record();
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
        bindings.upsert(record).expect("binding");
        secrets.set(&binding.id, "npm_ABC123").expect("secret");

        let report =
            uninstall_userconfig(Some(&path), true, &bindings, &secrets).expect("uninstall");
        assert_eq!(report.restored_labels, vec!["default".to_string()]);
        assert!(report.purged);
        let updated = fs::read_to_string(&path).expect("read");
        assert!(updated.contains("npm_ABC123"));
        assert!(bindings.list().expect("list").is_empty());
    }

    #[test]
    fn uninstall_restores_unscoped_auth_shape_when_recorded() {
        let dir = TempDir::new().expect("temp dir");
        let path = canon(&dir).join("user.npmrc");
        fs::write(
            &path,
            "//registry.npmjs.org/:_authToken=${NPM_TOKEN_DEFAULT}\n",
        )
        .expect("write");

        let bindings = MemoryBindingStore::new();
        let secrets = MemorySecretStore::new();
        let mut record = crate::registry_bindings::default_registry_binding().to_binding_record();
        set_provenance_for_path(
            &mut record,
            &path,
            InstallProvenance {
                config_line_origin: "source".to_string(),
                installed_from_npmrc: true,
                original_line_kind: Some("unscoped_authToken".to_string()),
            },
        )
        .expect("provenance");
        bindings.upsert(record.clone()).expect("binding");
        secrets.set(&record.id, "npm_ABC123").expect("secret");

        let report =
            uninstall_userconfig(Some(&path), false, &bindings, &secrets).expect("uninstall");
        assert_eq!(report.restored_labels, vec!["default".to_string()]);
        let updated = fs::read_to_string(&path).expect("read");
        assert_eq!(updated, "_authToken=npm_ABC123\n");
    }

    #[test]
    fn uninstall_removes_appended_managed_lines() {
        let dir = TempDir::new().expect("temp dir");
        let path = canon(&dir).join("user.npmrc");
        fs::write(
            &path,
            "color=true\n//registry.npmjs.org/:_authToken=${NPM_TOKEN_DEFAULT}\n",
        )
        .expect("write");

        let bindings = MemoryBindingStore::new();
        let secrets = MemorySecretStore::new();
        let mut record = crate::registry_bindings::default_registry_binding().to_binding_record();
        set_provenance_for_path(
            &mut record,
            &path,
            InstallProvenance {
                config_line_origin: "appended".to_string(),
                installed_from_npmrc: false,
                original_line_kind: None,
            },
        )
        .expect("provenance");
        bindings.upsert(record.clone()).expect("binding");
        secrets.set(&record.id, "npm_ABC123").expect("secret");

        let report =
            uninstall_userconfig(Some(&path), false, &bindings, &secrets).expect("uninstall");
        assert!(report.restored_labels.is_empty());
        assert_eq!(report.removed_labels, vec!["default".to_string()]);
        let updated = fs::read_to_string(&path).expect("read");
        assert_eq!(updated, "color=true\n");
    }

    #[test]
    fn uninstall_removes_appended_managed_lines_without_needing_secret() {
        let dir = TempDir::new().expect("temp dir");
        let path = canon(&dir).join("user.npmrc");
        fs::write(
            &path,
            "color=true\n//registry.npmjs.org/:_authToken=${NPM_TOKEN_DEFAULT}\n",
        )
        .expect("write");

        let bindings = MemoryBindingStore::new();
        let secrets = MemorySecretStore::new();
        let mut record = crate::registry_bindings::default_registry_binding().to_binding_record();
        set_provenance_for_path(
            &mut record,
            &path,
            InstallProvenance {
                config_line_origin: "appended".to_string(),
                installed_from_npmrc: false,
                original_line_kind: None,
            },
        )
        .expect("provenance");
        record.metadata.insert(
            "token_source".to_string(),
            "/definitely/missing-token-source".to_string(),
        );
        bindings.upsert(record).expect("binding");

        let report =
            uninstall_userconfig(Some(&path), false, &bindings, &secrets).expect("uninstall");
        assert!(report.restored_labels.is_empty());
        assert_eq!(report.removed_labels, vec!["default".to_string()]);
        assert_eq!(fs::read_to_string(&path).expect("read"), "color=true\n");
    }

    #[test]
    fn uninstall_ignores_records_from_other_config_paths() {
        let dir = TempDir::new().expect("temp dir");
        let path = canon(&dir).join("user.npmrc");
        let other_path = canon(&dir).join("other.npmrc");
        fs::write(
            &path,
            "//registry.npmjs.org/:_authToken=${NPM_TOKEN_DEFAULT}\n",
        )
        .expect("write");

        let bindings = MemoryBindingStore::new();
        let secrets = MemorySecretStore::new();
        let mut record = crate::registry_bindings::default_registry_binding().to_binding_record();
        record.metadata.insert(
            "original_config_path".to_string(),
            other_path.to_string_lossy().into_owned(),
        );
        bindings.upsert(record.clone()).expect("binding");
        secrets.set(&record.id, "npm_ABC123").expect("secret");

        let report =
            uninstall_userconfig(Some(&path), false, &bindings, &secrets).expect("uninstall");
        assert!(report.restored_labels.is_empty());
        let updated = fs::read_to_string(&path).expect("read");
        assert_eq!(
            updated,
            "//registry.npmjs.org/:_authToken=${NPM_TOKEN_DEFAULT}\n"
        );
    }

    #[test]
    fn uninstall_reacquires_secret_from_token_source_when_missing() {
        let dir = TempDir::new().expect("temp dir");
        let path = canon(&dir).join("user.npmrc");
        let script_path = canon(&dir).join("source-token");
        fs::write(
            &path,
            "//registry.npmjs.org/:_authToken=${NPM_TOKEN_DEFAULT}\n",
        )
        .expect("write");
        fs::write(&script_path, "#!/bin/sh\nprintf 'token-from-source'\n").expect("script");
        let mut permissions = fs::metadata(&script_path).expect("metadata").permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&script_path, permissions).expect("permissions");

        let bindings = MemoryBindingStore::new();
        let secrets = MemorySecretStore::new();
        let mut record = crate::registry_bindings::default_registry_binding().to_binding_record();
        record.metadata.insert(
            "token_source".to_string(),
            script_path.to_string_lossy().into_owned(),
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
        bindings.upsert(record.clone()).expect("binding");

        let report =
            uninstall_userconfig(Some(&path), false, &bindings, &secrets).expect("uninstall");
        assert_eq!(report.restored_labels, vec!["default".to_string()]);
        let updated = fs::read_to_string(&path).expect("read");
        assert_eq!(
            updated,
            "//registry.npmjs.org/:_authToken=token-from-source\n"
        );
        assert_eq!(
            secrets.get(&record.id).expect("secret"),
            Some("token-from-source".to_string())
        );
    }

    #[test]
    fn uninstall_restores_original_secret_state_when_reacquired_secret_rollback_is_needed() {
        let dir = TempDir::new().expect("temp dir");
        let path = canon(&dir).join("user.npmrc");
        let script_path = canon(&dir).join("source-token");
        fs::write(
            &path,
            "//registry.npmjs.org/:_authToken=${NPM_TOKEN_DEFAULT}\n",
        )
        .expect("write");
        fs::write(&script_path, "#!/bin/sh\nprintf 'token-from-source'\n").expect("script");
        let mut permissions = fs::metadata(&script_path).expect("metadata").permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&script_path, permissions).expect("permissions");

        let mut record = crate::registry_bindings::default_registry_binding().to_binding_record();
        record.metadata.insert(
            "token_source".to_string(),
            script_path.to_string_lossy().into_owned(),
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

        let bindings = FailingBindingStore::with_records(vec![record.clone()], true);
        let secrets = SimpleSecretStore::default();

        let error = uninstall_userconfig(Some(&path), false, &bindings, &secrets)
            .expect_err("uninstall should fail");

        assert!(error.to_string().contains("simulated upsert failure"));
        assert_eq!(secrets.get(&record.id).expect("secret"), None);
        assert_eq!(
            fs::read_to_string(&path).expect("read restored"),
            "//registry.npmjs.org/:_authToken=${NPM_TOKEN_DEFAULT}\n"
        );
    }

    #[test]
    fn uninstall_restores_source_managed_binding_even_if_placeholder_line_was_removed() {
        let dir = TempDir::new().expect("temp dir");
        let path = canon(&dir).join("user.npmrc");
        fs::write(&path, "color=true\n").expect("write");

        let bindings = MemoryBindingStore::new();
        let secrets = MemorySecretStore::new();
        let mut record = crate::registry_bindings::default_registry_binding().to_binding_record();
        record
            .metadata
            .insert("config_line_origin".to_string(), "source".to_string());
        record.metadata.insert(
            "original_config_path".to_string(),
            path.to_string_lossy().into_owned(),
        );
        record
            .metadata
            .insert("installed_from_npmrc".to_string(), "true".to_string());
        bindings.upsert(record.clone()).expect("binding");
        secrets.set(&record.id, "npm_ABC123").expect("secret");

        let report =
            uninstall_userconfig(Some(&path), true, &bindings, &secrets).expect("uninstall");
        assert_eq!(report.restored_labels, vec!["default".to_string()]);
        let updated = fs::read_to_string(&path).expect("read");
        assert_eq!(
            updated,
            "color=true\n//registry.npmjs.org/:_authToken=npm_ABC123\n"
        );
        assert!(bindings.list().expect("list").is_empty());
    }

    #[test]
    fn uninstall_restores_unscoped_auth_when_placeholder_line_was_removed() {
        let dir = TempDir::new().expect("temp dir");
        let path = canon(&dir).join("user.npmrc");
        fs::write(&path, "color=true\n").expect("write");

        let bindings = MemoryBindingStore::new();
        let secrets = MemorySecretStore::new();
        let mut record = crate::registry_bindings::default_registry_binding().to_binding_record();
        set_provenance_for_path(
            &mut record,
            &path,
            InstallProvenance {
                config_line_origin: "source".to_string(),
                installed_from_npmrc: true,
                original_line_kind: Some("unscoped_authToken".to_string()),
            },
        )
        .expect("provenance");
        bindings.upsert(record.clone()).expect("binding");
        secrets.set(&record.id, "npm_ABC123").expect("secret");

        let report =
            uninstall_userconfig(Some(&path), false, &bindings, &secrets).expect("uninstall");
        assert_eq!(report.restored_labels, vec!["default".to_string()]);
        assert_eq!(
            fs::read_to_string(&path).expect("read"),
            "color=true\n_authToken=npm_ABC123\n"
        );
    }

    #[test]
    fn uninstall_does_not_purge_manual_binding_without_install_provenance() {
        let dir = TempDir::new().expect("temp dir");
        let path = canon(&dir).join("user.npmrc");
        fs::write(&path, "color=true\n").expect("write");

        let bindings = MemoryBindingStore::new();
        let secrets = MemorySecretStore::new();
        let record = crate::registry_bindings::default_registry_binding().to_binding_record();
        bindings.upsert(record.clone()).expect("binding");
        secrets.set(&record.id, "npm_ABC123").expect("secret");

        let report =
            uninstall_userconfig(Some(&path), true, &bindings, &secrets).expect("uninstall");
        assert!(report.restored_labels.is_empty());
        assert_eq!(fs::read_to_string(&path).expect("read"), "color=true\n");
        assert!(bindings.get(&record.id).expect("get").is_some());
        assert_eq!(
            secrets.get(&record.id).expect("get secret"),
            Some("npm_ABC123".to_string())
        );
    }

    #[test]
    fn uninstall_keeps_binding_when_other_config_provenance_remains() {
        let dir = TempDir::new().expect("temp dir");
        let path_a = canon(&dir).join("a.npmrc");
        let path_b = canon(&dir).join("b.npmrc");
        fs::write(&path_a, "color=true\n").expect("write a");
        fs::write(&path_b, "color=true\n").expect("write b");

        let bindings = MemoryBindingStore::new();
        let secrets = MemorySecretStore::new();
        let binding = crate::registry_bindings::default_registry_binding();
        bindings
            .upsert(binding.to_binding_record())
            .expect("upsert binding");
        secrets.set(&binding.id, "npm_ABC123").expect("set secret");

        crate::install::install_userconfig(Some(&path_a), false, &bindings, &secrets)
            .expect("install a");
        crate::install::install_userconfig(Some(&path_b), false, &bindings, &secrets)
            .expect("install b");

        let report =
            uninstall_userconfig(Some(&path_b), true, &bindings, &secrets).expect("uninstall");
        assert!(report.restored_labels.is_empty());
        assert_eq!(report.removed_labels, vec!["default".to_string()]);
        assert_eq!(fs::read_to_string(&path_b).expect("read b"), "color=true\n");
        assert!(bindings.get(&binding.id).expect("get binding").is_some());
        assert_eq!(
            secrets.get(&binding.id).expect("get secret"),
            Some("npm_ABC123".to_string())
        );
        let path_a_contents = fs::read_to_string(&path_a).expect("read a");
        assert!(path_a_contents.contains("//registry.npmjs.org/:_authToken=${NPM_TOKEN_DEFAULT}"));
    }

    #[test]
    fn uninstall_keep_secrets_removes_config_provenance() {
        let dir = TempDir::new().expect("temp dir");
        let path = canon(&dir).join("user.npmrc");
        fs::write(
            &path,
            "color=true\n//registry.npmjs.org/:_authToken=${NPM_TOKEN_DEFAULT}\n",
        )
        .expect("write");

        let bindings = MemoryBindingStore::new();
        let secrets = MemorySecretStore::new();
        let binding = crate::registry_bindings::default_registry_binding();
        bindings
            .upsert(binding.to_binding_record())
            .expect("upsert binding");
        secrets.set(&binding.id, "npm_ABC123").expect("set secret");

        crate::install::install_userconfig(Some(&path), false, &bindings, &secrets)
            .expect("install");

        let report =
            uninstall_userconfig(Some(&path), false, &bindings, &secrets).expect("uninstall");
        assert_eq!(report.restored_labels, vec!["default".to_string()]);
        assert_eq!(
            fs::read_to_string(&path).expect("read"),
            "color=true\n//registry.npmjs.org/:_authToken=npm_ABC123\n"
        );

        let record = bindings
            .get(&binding.id)
            .expect("get binding")
            .expect("record");
        let path_string = path.to_string_lossy();
        assert!(!applies_to_config_path(&record, &path_string));
    }

    #[test]
    fn uninstall_rejects_duplicate_auth_key_state() {
        let dir = TempDir::new().expect("temp dir");
        let path = canon(&dir).join("user.npmrc");
        fs::write(&path, "color=true\n").expect("write");

        let bindings = MemoryBindingStore::new();
        let secrets = MemorySecretStore::new();
        let first = RegistryBinding::new("first", "https://artifactory.example.com/api/npm/npm/")
            .to_binding_record();
        let mut second =
            RegistryBinding::new("second", "https://other.example.com/npm/").to_binding_record();
        second
            .metadata
            .insert("auth_key".to_string(), first.metadata["auth_key"].clone());
        second.target = first.target.clone();
        bindings.upsert(first).expect("upsert first");
        bindings.upsert(second).expect("upsert second");

        let error = uninstall_userconfig(Some(&path), true, &bindings, &secrets)
            .expect_err("duplicate state should fail");
        assert!(error.to_string().contains("managed by multiple bindings"));
    }

    #[test]
    fn uninstall_restores_original_file_when_state_update_fails() {
        let dir = TempDir::new().expect("temp dir");
        let path = canon(&dir).join("user.npmrc");
        fs::write(
            &path,
            "//registry.npmjs.org/:_authToken=${NPM_TOKEN_DEFAULT}\n",
        )
        .expect("write");

        let mut record = crate::registry_bindings::default_registry_binding().to_binding_record();
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

        let bindings = FailingBindingStore::with_records(vec![record.clone()], true);
        let secrets = SimpleSecretStore::default();
        secrets.set(&record.id, "npm_ABC123").expect("secret");

        let error = uninstall_userconfig(Some(&path), false, &bindings, &secrets)
            .expect_err("uninstall should fail");

        assert!(error.to_string().contains("simulated upsert failure"));
        assert_eq!(
            fs::read_to_string(&path).expect("read restored"),
            "//registry.npmjs.org/:_authToken=${NPM_TOKEN_DEFAULT}\n"
        );
        let stored = bindings.get(&record.id).expect("get").expect("record");
        assert!(provenance_for_path(&stored, &path.to_string_lossy()).is_some());
    }

    #[test]
    fn uninstall_does_not_treat_auth_key_mentions_in_comments_as_managed_lines() {
        let dir = TempDir::new().expect("temp dir");
        let path = canon(&dir).join("user.npmrc");
        fs::write(
            &path,
            "# mention //registry.npmjs.org/:_authToken in a comment only\ncolor=true\n",
        )
        .expect("write");

        let bindings = MemoryBindingStore::new();
        let secrets = MemorySecretStore::new();
        let mut record = crate::registry_bindings::default_registry_binding().to_binding_record();
        set_provenance_for_path(
            &mut record,
            &path,
            InstallProvenance {
                config_line_origin: "appended".to_string(),
                installed_from_npmrc: false,
                original_line_kind: None,
            },
        )
        .expect("provenance");
        bindings.upsert(record).expect("binding");

        let report =
            uninstall_userconfig(Some(&path), false, &bindings, &secrets).expect("uninstall");

        assert!(report.restored_labels.is_empty());
        assert!(report.removed_labels.is_empty());
        assert_eq!(
            fs::read_to_string(&path).expect("read"),
            "# mention //registry.npmjs.org/:_authToken in a comment only\ncolor=true\n"
        );
    }
}
