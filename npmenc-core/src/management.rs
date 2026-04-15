#![cfg_attr(test, allow(clippy::unwrap_used))]

use anyhow::{anyhow, Result};
use enclaveapp_app_adapter::{BindingStore, SecretStore};

use crate::common::restore_previous_secret;
use crate::provenance::has_any_install_provenance;
use crate::registry_bindings::{
    default_registry_binding, normalize_registry_url_to_auth_key, RegistryBinding,
};
use crate::state_lock::{with_state_lock, with_state_lock_read_only};
use crate::token_source::{
    clear_token_source_metadata, clear_token_source_state, prepare_token_source_metadata,
    restore_token_source_artifacts, snapshot_token_source_artifacts,
    token_source_display_for_listing,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingListRow {
    pub label: String,
    pub target: String,
    pub secret_env_var: String,
    pub token_source_display: Option<String>,
}

pub fn store_binding_secret<B, S>(
    label: Option<&str>,
    url: Option<&str>,
    secret: &str,
    token_source: Option<&str>,
    binding_store: &B,
    secret_store: &S,
) -> Result<RegistryBinding>
where
    B: BindingStore,
    S: SecretStore,
{
    with_state_lock(|| {
        let requested_label = label.unwrap_or("default");
        let requested_url = url.unwrap_or("https://registry.npmjs.org/");
        let requested_auth_key = normalize_registry_url_to_auth_key(requested_url);
        if requested_label == "default"
            && requested_auth_key
                != normalize_registry_url_to_auth_key("https://registry.npmjs.org/")
        {
            return Err(anyhow!(
                "the `default` binding is reserved for https://registry.npmjs.org/"
            ));
        }

        let binding = if requested_label == "default" && url.is_none() {
            default_registry_binding()
        } else {
            RegistryBinding::new(requested_label.to_string(), requested_url.to_string())
        };
        ensure_non_empty_secret(&binding, secret)?;
        let existing_record = binding_store.get(&binding.id)?;
        let previous_secret = secret_store.get(&binding.id)?;
        let previous_token_source_state =
            snapshot_token_source_artifacts(&binding.id, secret_store)?;
        let mut record = if let Some(existing) = existing_record.clone() {
            merge_binding_record(existing, &binding)
        } else {
            binding.to_binding_record()
        };
        if let Some(token_source) = token_source {
            if let Err(error) =
                prepare_token_source_metadata(&mut record, token_source, secret_store)
            {
                if let Err(rollback_error) = restore_token_source_artifacts(
                    &binding.id,
                    &previous_token_source_state,
                    secret_store,
                ) {
                    return Err(anyhow!(
                        "{error}; additionally failed to restore previous token source state: {rollback_error}"
                    ));
                }
                return Err(error);
            }
        } else {
            clear_token_source_metadata(&mut record);
            if let Err(error) = clear_token_source_state(&binding.id, secret_store) {
                if let Err(rollback_error) = restore_token_source_artifacts(
                    &binding.id,
                    &previous_token_source_state,
                    secret_store,
                ) {
                    return Err(anyhow!(
                        "{error}; additionally failed to restore previous token source state: {rollback_error}"
                    ));
                }
                return Err(error);
            }
        }

        if let Err(error) = secret_store.set(&binding.id, secret) {
            if let Err(rollback_error) = restore_token_source_artifacts(
                &binding.id,
                &previous_token_source_state,
                secret_store,
            ) {
                return Err(anyhow!(
                    "{error}; additionally failed to restore previous token source state: {rollback_error}"
                ));
            }
            return Err(error.into());
        }
        let update_result = binding_store.mutate(|records| {
            reject_duplicate_auth_key_in_records(records, &binding).map_err(|error| {
                enclaveapp_app_adapter::AdapterError::Storage(error.to_string())
            })?;
            if let Some(existing) = records.iter_mut().find(|entry| entry.id == record.id) {
                *existing = record.clone();
            } else {
                records.push(record.clone());
            }
            Ok(())
        });
        if let Err(error) = update_result {
            if let Err(rollback_error) =
                restore_previous_secret(secret_store, &binding.id, previous_secret.as_deref())
            {
                return Err(anyhow!(
                    "{error}; additionally failed to restore previous secret state: {rollback_error}"
                ));
            }
            if let Err(rollback_error) = restore_token_source_artifacts(
                &binding.id,
                &previous_token_source_state,
                secret_store,
            ) {
                return Err(anyhow!(
                    "{error}; additionally failed to restore previous token source state: {rollback_error}"
                ));
            }
            return Err(error.into());
        }
        Ok(binding)
    })
}

pub fn list_binding_records<B>(
    binding_store: &B,
) -> Result<Vec<enclaveapp_app_adapter::BindingRecord>>
where
    B: BindingStore,
{
    let records = binding_store.list()?;
    validate_unique_auth_keys(&records)?;
    Ok(records)
}

pub fn list_binding_rows<B, S>(binding_store: &B, secret_store: &S) -> Result<Vec<BindingListRow>>
where
    B: BindingStore,
    S: SecretStore,
{
    with_state_lock_read_only(|| {
        let records = list_binding_records(binding_store)?;
        records
            .into_iter()
            .map(|record| {
                Ok(BindingListRow {
                    label: record.label.clone(),
                    target: record.target.clone(),
                    secret_env_var: record.secret_env_var.clone(),
                    token_source_display: token_source_display_for_listing(&record, secret_store)?,
                })
            })
            .collect()
    })
}

pub fn delete_binding_label<B, S>(label: &str, binding_store: &B, secret_store: &S) -> Result<bool>
where
    B: BindingStore,
    S: SecretStore,
{
    with_state_lock(|| {
        let id = enclaveapp_app_adapter::BindingId::new(format!("npm:{label}"));
        let Some(record) = binding_store.get(&id)? else {
            return Ok(false);
        };
        if has_any_install_provenance(&record) {
            return Err(anyhow!(
                "binding `{label}` is still installed into one or more configs; run uninstall first"
            ));
        }
        let binding = RegistryBinding::from_binding_record(&record);
        let previous_secret = secret_store.get(&binding.id)?;
        let previous_token_source_state =
            snapshot_token_source_artifacts(&binding.id, secret_store)?;

        if let Err(error) = secret_store.delete(&binding.id) {
            return Err(error.into());
        }
        if let Err(error) = clear_token_source_state(&binding.id, secret_store) {
            if let Err(rollback_error) =
                restore_previous_secret(secret_store, &binding.id, previous_secret.as_deref())
            {
                return Err(anyhow!(
                    "{error}; additionally failed to restore previous secret state: {rollback_error}"
                ));
            }
            if let Err(rollback_error) = restore_token_source_artifacts(
                &binding.id,
                &previous_token_source_state,
                secret_store,
            ) {
                return Err(anyhow!(
                    "{error}; additionally failed to restore previous token source state: {rollback_error}"
                ));
            }
            return Err(error);
        }
        let deleted_binding = match binding_store.delete(&binding.id) {
            Ok(value) => value,
            Err(error) => {
                if let Err(rollback_error) =
                    restore_previous_secret(secret_store, &binding.id, previous_secret.as_deref())
                {
                    return Err(anyhow!(
                        "{error}; additionally failed to restore previous secret state: {rollback_error}"
                    ));
                }
                if let Err(rollback_error) = restore_token_source_artifacts(
                    &binding.id,
                    &previous_token_source_state,
                    secret_store,
                ) {
                    return Err(anyhow!(
                        "{error}; additionally failed to restore previous token source state: {rollback_error}"
                    ));
                }
                return Err(error.into());
            }
        };
        Ok(deleted_binding || previous_secret.is_some())
    })
}

pub fn binding_for_label<B>(label: &str, binding_store: &B) -> Result<RegistryBinding>
where
    B: BindingStore,
{
    let id = enclaveapp_app_adapter::BindingId::new(format!("npm:{label}"));
    let record = binding_store
        .get(&id)?
        .ok_or_else(|| anyhow!("binding not found for `{label}`"))?;
    Ok(RegistryBinding::from_binding_record(&record))
}

pub fn validate_unique_auth_keys(records: &[enclaveapp_app_adapter::BindingRecord]) -> Result<()> {
    for (index, record) in records.iter().enumerate() {
        let binding = RegistryBinding::from_binding_record(record);
        if let Some(existing) = records[index + 1..]
            .iter()
            .find(|other| RegistryBinding::from_binding_record(other).auth_key == binding.auth_key)
        {
            return Err(anyhow!(
                "registry `{}` is managed by multiple bindings (`{}` and `{}`); repair managed state before continuing",
                binding.registry_url,
                record.label,
                existing.label
            ));
        }
    }
    Ok(())
}

fn reject_duplicate_auth_key_in_records(
    records: &[enclaveapp_app_adapter::BindingRecord],
    binding: &RegistryBinding,
) -> Result<()> {
    let duplicate = records.iter().find(|record| {
        record.id != binding.id
            && RegistryBinding::from_binding_record(record).auth_key == binding.auth_key
    });
    if let Some(existing) = duplicate {
        return Err(anyhow!(
            "registry `{}` is already managed by binding `{}`; each registry may only have one binding",
            binding.registry_url,
            existing.label
        ));
    }
    Ok(())
}

fn merge_binding_record(
    existing: enclaveapp_app_adapter::BindingRecord,
    binding: &RegistryBinding,
) -> enclaveapp_app_adapter::BindingRecord {
    let mut record = binding.to_binding_record();
    if existing.target == binding.registry_url {
        record.metadata.extend(existing.metadata);
        record
            .metadata
            .insert("auth_key".to_string(), binding.auth_key.clone());
        record
            .metadata
            .insert("registry_url".to_string(), binding.registry_url.clone());
        record
            .metadata
            .insert("managed_by".to_string(), "npmenc".to_string());
    }
    record
}

fn ensure_non_empty_secret(binding: &RegistryBinding, secret: &str) -> Result<()> {
    if secret.is_empty() {
        return Err(anyhow!(
            "binding `{}` cannot use an empty secret",
            binding.label
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Mutex;

    use enclaveapp_app_adapter::{
        AdapterError, BindingStore, MemoryBindingStore, MemorySecretStore, SecretStore,
    };
    use tempfile::TempDir;

    use super::*;
    use crate::provenance::{set_provenance_for_path, InstallProvenance};
    use crate::token_source::{
        prepare_token_source_metadata, snapshot_token_source_artifacts,
        snapshot_token_source_state, token_source_display,
    };

    #[derive(Debug, Default)]
    struct FailingDeleteBindingStore {
        records: Mutex<Vec<enclaveapp_app_adapter::BindingRecord>>,
    }

    #[derive(Debug, Default)]
    struct FailingSetSecretStore {
        inner: MemorySecretStore,
    }

    #[derive(Debug, Default)]
    struct FailingPreparedMarkerDeleteSecretStore {
        inner: MemorySecretStore,
    }

    impl BindingStore for FailingDeleteBindingStore {
        fn list(
            &self,
        ) -> enclaveapp_app_adapter::Result<Vec<enclaveapp_app_adapter::BindingRecord>> {
            Ok(self
                .records
                .lock()
                .map_err(|_| AdapterError::Storage("binding store mutex poisoned".to_string()))?
                .clone())
        }

        fn get(
            &self,
            id: &enclaveapp_app_adapter::BindingId,
        ) -> enclaveapp_app_adapter::Result<Option<enclaveapp_app_adapter::BindingRecord>> {
            Ok(self
                .records
                .lock()
                .map_err(|_| AdapterError::Storage("binding store mutex poisoned".to_string()))?
                .iter()
                .find(|record| &record.id == id)
                .cloned())
        }

        fn upsert(
            &self,
            record: enclaveapp_app_adapter::BindingRecord,
        ) -> enclaveapp_app_adapter::Result<()> {
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

        fn delete(
            &self,
            _id: &enclaveapp_app_adapter::BindingId,
        ) -> enclaveapp_app_adapter::Result<bool> {
            Err(AdapterError::Storage(
                "simulated delete failure".to_string(),
            ))
        }

        fn mutate<T, F>(&self, update: F) -> enclaveapp_app_adapter::Result<T>
        where
            F: FnOnce(
                &mut Vec<enclaveapp_app_adapter::BindingRecord>,
            ) -> enclaveapp_app_adapter::Result<T>,
        {
            let mut records = self
                .records
                .lock()
                .map_err(|_| AdapterError::Storage("binding store mutex poisoned".to_string()))?;
            update(&mut records)
        }
    }

    impl SecretStore for FailingSetSecretStore {
        fn set(
            &self,
            id: &enclaveapp_app_adapter::BindingId,
            secret: &str,
        ) -> enclaveapp_app_adapter::Result<()> {
            if id.as_str() == "npm:default" {
                return Err(AdapterError::Storage(
                    "simulated secret set failure".to_string(),
                ));
            }
            self.inner.set(id, secret)
        }

        fn get(
            &self,
            id: &enclaveapp_app_adapter::BindingId,
        ) -> enclaveapp_app_adapter::Result<Option<String>> {
            self.inner.get(id)
        }

        fn delete(
            &self,
            id: &enclaveapp_app_adapter::BindingId,
        ) -> enclaveapp_app_adapter::Result<bool> {
            self.inner.delete(id)
        }
    }

    impl SecretStore for FailingPreparedMarkerDeleteSecretStore {
        fn set(
            &self,
            id: &enclaveapp_app_adapter::BindingId,
            secret: &str,
        ) -> enclaveapp_app_adapter::Result<()> {
            self.inner.set(id, secret)
        }

        fn get(
            &self,
            id: &enclaveapp_app_adapter::BindingId,
        ) -> enclaveapp_app_adapter::Result<Option<String>> {
            self.inner.get(id)
        }

        fn delete(
            &self,
            id: &enclaveapp_app_adapter::BindingId,
        ) -> enclaveapp_app_adapter::Result<bool> {
            if id.as_str().ends_with(":token-source-prepared") {
                return Err(AdapterError::Storage(
                    "simulated prepared marker delete failure".to_string(),
                ));
            }
            self.inner.delete(id)
        }
    }

    fn make_token_source_script(dir: &TempDir, name: &str) -> String {
        let path = dir.path().join(name);
        fs::write(&path, "#!/bin/sh\nprintf 'token'\n").expect("write");
        let mut perms = fs::metadata(&path).expect("metadata").permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&path, perms).expect("chmod");
        path.to_string_lossy().into_owned()
    }

    #[test]
    fn store_binding_secret_preserves_existing_metadata_for_same_target() {
        let dir = TempDir::new().expect("temp dir");
        let bindings = MemoryBindingStore::new();
        let secrets = MemorySecretStore::new();
        let token_source = make_token_source_script(&dir, "token-source");

        let mut record = default_registry_binding().to_binding_record();
        record.metadata.insert(
            "original_line_kind".to_string(),
            "scoped_authToken".to_string(),
        );
        record
            .metadata
            .insert("config_line_origin".to_string(), "source".to_string());
        bindings.upsert(record).expect("upsert");
        secrets
            .set(
                &enclaveapp_app_adapter::BindingId::new("npm:default"),
                "old_secret",
            )
            .expect("secret");

        store_binding_secret(
            Some("default"),
            Some("https://registry.npmjs.org/"),
            "new_secret",
            Some(&token_source),
            &bindings,
            &secrets,
        )
        .expect("store");

        let updated = bindings
            .get(&enclaveapp_app_adapter::BindingId::new("npm:default"))
            .expect("get")
            .expect("record");
        assert_eq!(
            updated.metadata.get("original_line_kind"),
            Some(&"scoped_authToken".to_string())
        );
        assert_eq!(
            updated.metadata.get("config_line_origin"),
            Some(&"source".to_string())
        );
        assert_eq!(
            updated.metadata.get("token_provider"),
            Some(&"command".to_string())
        );
        assert_eq!(updated.metadata.get("token_handle"), None);
        assert!(token_source_display(&updated)
            .expect("display")
            .expect("display value")
            .starts_with("command:token-source#"));
        assert_eq!(
            secrets
                .get(&enclaveapp_app_adapter::BindingId::new("npm:default"))
                .expect("get secret"),
            Some("new_secret".to_string())
        );
        assert!(snapshot_token_source_state(
            &enclaveapp_app_adapter::BindingId::new("npm:default"),
            &secrets
        )
        .expect("snapshot")
        .is_some());
    }

    #[test]
    fn store_binding_secret_resets_install_provenance_when_target_changes() {
        let dir = TempDir::new().expect("temp dir");
        let bindings = MemoryBindingStore::new();
        let secrets = MemorySecretStore::new();
        let token_source = make_token_source_script(&dir, "manual-source");

        let mut record =
            RegistryBinding::new("mycompany", "https://registry.npmjs.org/").to_binding_record();
        record.metadata.insert(
            "original_line_kind".to_string(),
            "scoped_authToken".to_string(),
        );
        record
            .metadata
            .insert("config_line_origin".to_string(), "source".to_string());
        bindings.upsert(record).expect("upsert");

        store_binding_secret(
            Some("mycompany"),
            Some("https://artifactory.example.com/api/npm/npm/"),
            "new_secret",
            Some(&token_source),
            &bindings,
            &secrets,
        )
        .expect("store");

        let updated = bindings
            .get(&enclaveapp_app_adapter::BindingId::new("npm:mycompany"))
            .expect("get")
            .expect("record");
        assert_eq!(
            updated.metadata.get("registry_url"),
            Some(&"https://artifactory.example.com/api/npm/npm/".to_string())
        );
        assert_eq!(updated.metadata.get("original_line_kind"), None);
        assert_eq!(updated.metadata.get("config_line_origin"), None);
        assert_eq!(
            updated.metadata.get("token_provider"),
            Some(&"command".to_string())
        );
        assert_eq!(updated.metadata.get("token_handle"), None);
        assert!(token_source_display(&updated)
            .expect("display")
            .expect("display value")
            .starts_with("command:manual-source#"));
    }

    #[test]
    fn store_binding_secret_clears_existing_token_source_when_not_reprovided() {
        let dir = TempDir::new().expect("temp dir");
        let bindings = MemoryBindingStore::new();
        let secrets = MemorySecretStore::new();
        let token_source = make_token_source_script(&dir, "jwt-source");

        store_binding_secret(
            Some("default"),
            None,
            "secret",
            Some(&token_source),
            &bindings,
            &secrets,
        )
        .expect("initial store");
        store_binding_secret(Some("default"), None, "secret-2", None, &bindings, &secrets)
            .expect("second store");

        let updated = bindings
            .get(&enclaveapp_app_adapter::BindingId::new("npm:default"))
            .expect("get")
            .expect("record");
        assert_eq!(updated.metadata.get("token_provider"), None);
        assert_eq!(updated.metadata.get("token_handle"), None);
        assert_eq!(token_source_display(&updated).expect("display"), None);
    }

    #[test]
    fn delete_binding_label_returns_false_when_binding_does_not_exist() {
        let bindings = MemoryBindingStore::new();
        let secrets = MemorySecretStore::new();

        let deleted =
            delete_binding_label("missing", &bindings, &secrets).expect("delete should succeed");

        assert!(!deleted);
    }

    #[test]
    fn delete_binding_label_rejects_installed_binding() {
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join("user.npmrc");
        let bindings = MemoryBindingStore::new();
        let secrets = MemorySecretStore::new();
        let mut record = default_registry_binding().to_binding_record();
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
        bindings.upsert(record).expect("upsert");

        let error = delete_binding_label("default", &bindings, &secrets)
            .expect_err("installed binding should not be deletable");

        assert!(error.to_string().contains("run uninstall first"));
    }

    #[test]
    fn delete_binding_label_rolls_back_secret_and_token_source_when_binding_delete_fails() {
        let dir = TempDir::new().expect("temp dir");
        let bindings = FailingDeleteBindingStore::default();
        let secrets = MemorySecretStore::new();
        let token_source = make_token_source_script(&dir, "token-source");

        let mut record = default_registry_binding().to_binding_record();
        prepare_token_source_metadata(&mut record, &token_source, &secrets).expect("token source");
        bindings.upsert(record.clone()).expect("upsert");
        secrets.set(&record.id, "secret").expect("secret");

        let error =
            delete_binding_label("default", &bindings, &secrets).expect_err("delete should fail");

        assert!(error.to_string().contains("simulated delete failure"));
        assert_eq!(bindings.get(&record.id).expect("get"), Some(record.clone()));
        assert_eq!(
            secrets.get(&record.id).expect("secret after rollback"),
            Some("secret".to_string())
        );
        assert!(snapshot_token_source_state(&record.id, &secrets)
            .expect("snapshot")
            .is_some());
    }

    #[test]
    fn store_binding_secret_rolls_back_token_source_when_secret_write_fails() {
        let dir = TempDir::new().expect("temp dir");
        let bindings = MemoryBindingStore::new();
        let secrets = FailingSetSecretStore::default();
        let token_source = make_token_source_script(&dir, "token-source");

        let error = store_binding_secret(
            Some("default"),
            None,
            "secret",
            Some(&token_source),
            &bindings,
            &secrets,
        )
        .expect_err("store should fail");

        assert!(error.to_string().contains("simulated secret set failure"));
        assert!(snapshot_token_source_state(
            &enclaveapp_app_adapter::BindingId::new("npm:default"),
            &secrets
        )
        .expect("snapshot")
        .is_none());
    }

    #[test]
    fn store_binding_secret_preserves_previous_token_source_artifacts_when_preparation_fails() {
        let dir = TempDir::new().expect("temp dir");
        let bindings = MemoryBindingStore::new();
        let secrets = FailingPreparedMarkerDeleteSecretStore::default();
        let original_source = make_token_source_script(&dir, "original-source");

        let mut record = default_registry_binding().to_binding_record();
        prepare_token_source_metadata(&mut record, &original_source, &secrets.inner)
            .expect("original token source");
        bindings.upsert(record.clone()).expect("upsert");
        secrets.inner.set(&record.id, "secret").expect("secret");
        let before =
            snapshot_token_source_artifacts(&record.id, &secrets.inner).expect("snapshot before");

        let error = store_binding_secret(
            Some("default"),
            None,
            "secret",
            Some("provider:unknown-provider:corp"),
            &bindings,
            &secrets,
        )
        .expect_err("store should fail");

        assert!(error
            .to_string()
            .contains("simulated prepared marker delete failure"));
        assert_eq!(
            snapshot_token_source_artifacts(&record.id, &secrets.inner).expect("snapshot after"),
            before
        );
    }

    #[test]
    fn store_binding_secret_preserves_previous_token_source_artifacts_when_clear_fails() {
        let dir = TempDir::new().expect("temp dir");
        let bindings = MemoryBindingStore::new();
        let secrets = FailingPreparedMarkerDeleteSecretStore::default();
        let original_source = make_token_source_script(&dir, "original-source");

        let mut record = default_registry_binding().to_binding_record();
        prepare_token_source_metadata(&mut record, &original_source, &secrets.inner)
            .expect("original token source");
        bindings.upsert(record.clone()).expect("upsert");
        secrets.inner.set(&record.id, "secret").expect("secret");
        let before =
            snapshot_token_source_artifacts(&record.id, &secrets.inner).expect("snapshot before");

        let error =
            store_binding_secret(Some("default"), None, "secret", None, &bindings, &secrets)
                .expect_err("store should fail");

        assert!(error
            .to_string()
            .contains("simulated prepared marker delete failure"));
        assert_eq!(
            snapshot_token_source_artifacts(&record.id, &secrets.inner).expect("snapshot after"),
            before
        );
    }

    #[test]
    fn delete_binding_label_rolls_back_token_source_artifacts_when_cleanup_fails() {
        let dir = TempDir::new().expect("temp dir");
        let bindings = MemoryBindingStore::new();
        let secrets = FailingPreparedMarkerDeleteSecretStore::default();
        let token_source = make_token_source_script(&dir, "token-source");

        let mut record = default_registry_binding().to_binding_record();
        prepare_token_source_metadata(&mut record, &token_source, &secrets.inner)
            .expect("token source");
        bindings.upsert(record.clone()).expect("upsert");
        secrets.inner.set(&record.id, "secret").expect("secret");
        let before =
            snapshot_token_source_artifacts(&record.id, &secrets.inner).expect("snapshot before");

        let error =
            delete_binding_label("default", &bindings, &secrets).expect_err("delete should fail");

        assert!(error
            .to_string()
            .contains("simulated prepared marker delete failure"));
        assert_eq!(bindings.get(&record.id).expect("get"), Some(record.clone()));
        assert_eq!(
            secrets
                .inner
                .get(&record.id)
                .expect("secret after rollback"),
            Some("secret".to_string())
        );
        assert_eq!(
            snapshot_token_source_artifacts(&record.id, &secrets.inner).expect("snapshot after"),
            before
        );
    }

    #[test]
    fn store_binding_secret_rejects_non_npm_registry_default_binding() {
        let bindings = MemoryBindingStore::new();
        let secrets = MemorySecretStore::new();

        let error = store_binding_secret(
            Some("default"),
            Some("https://corp.example.com/npm/"),
            "secret",
            None,
            &bindings,
            &secrets,
        )
        .expect_err("default binding URL should be fixed");

        assert!(error.to_string().contains("default` binding is reserved"));
    }

    #[test]
    fn store_binding_secret_rejects_duplicate_registry_auth_key_across_labels() {
        let bindings = MemoryBindingStore::new();
        let secrets = MemorySecretStore::new();

        store_binding_secret(
            Some("first"),
            Some("https://artifactory.example.com/api/npm/npm/"),
            "secret-a",
            None,
            &bindings,
            &secrets,
        )
        .expect("first store");

        let error = store_binding_secret(
            Some("second"),
            Some("https://artifactory.example.com/api/npm/npm/"),
            "secret-b",
            None,
            &bindings,
            &secrets,
        )
        .expect_err("duplicate registry should be rejected");

        assert!(error
            .to_string()
            .contains("already managed by binding `first`"));
    }

    #[test]
    fn store_binding_secret_without_token_source_clears_existing_token_source_metadata() {
        let dir = TempDir::new().expect("temp dir");
        let bindings = MemoryBindingStore::new();
        let secrets = MemorySecretStore::new();
        let token_source = make_token_source_script(&dir, "token-source");

        store_binding_secret(
            Some("default"),
            None,
            "first-secret",
            Some(&token_source),
            &bindings,
            &secrets,
        )
        .expect("initial store");

        store_binding_secret(
            Some("default"),
            None,
            "second-secret",
            None,
            &bindings,
            &secrets,
        )
        .expect("replace without token source");

        let record = bindings
            .get(&enclaveapp_app_adapter::BindingId::new("npm:default"))
            .expect("get")
            .expect("record");
        assert!(!record.metadata.contains_key("token_provider"));
        assert!(!record.metadata.contains_key("token_display"));
        assert_eq!(
            snapshot_token_source_artifacts(&record.id, &secrets).expect("snapshot"),
            crate::token_source::TokenSourceArtifactsSnapshot {
                state: None,
                prepared: false,
            }
        );
    }

    #[test]
    fn store_binding_secret_rejects_empty_secret() {
        let bindings = MemoryBindingStore::new();
        let secrets = MemorySecretStore::new();

        let error = store_binding_secret(Some("default"), None, "", None, &bindings, &secrets)
            .expect_err("empty secret should be rejected");

        assert!(error.to_string().contains("cannot use an empty secret"));
    }

    #[test]
    fn list_binding_records_rejects_duplicate_auth_keys_in_state() {
        let bindings = MemoryBindingStore::new();
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

        let error = list_binding_records(&bindings).expect_err("duplicates should be rejected");
        assert!(error.to_string().contains("managed by multiple bindings"));
    }
}
