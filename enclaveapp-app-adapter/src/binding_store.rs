#![cfg_attr(test, allow(clippy::panic, clippy::unwrap_used))]

use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::{AdapterError, Result};
use crate::types::{BindingId, BindingRecord};
use fs4::fs_std::FileExt;

pub trait BindingStore {
    fn list(&self) -> Result<Vec<BindingRecord>>;
    fn get(&self, id: &BindingId) -> Result<Option<BindingRecord>>;
    fn upsert(&self, record: BindingRecord) -> Result<()>;
    fn delete(&self, id: &BindingId) -> Result<bool>;
    fn mutate<T, F>(&self, update: F) -> Result<T>
    where
        F: FnOnce(&mut Vec<BindingRecord>) -> Result<T>;
}

#[derive(Debug, Clone)]
pub struct JsonFileBindingStore {
    path: PathBuf,
}

impl JsonFileBindingStore {
    pub fn for_app(app_name: &str) -> Result<Self> {
        let path = app_data_dir(app_name)?.join("bindings.json");
        Ok(Self { path })
    }

    pub fn at_path(path: PathBuf) -> Self {
        Self { path }
    }

    fn lock_path(&self) -> PathBuf {
        self.path.with_extension("lock")
    }

    fn read_all_unlocked(&self) -> Result<Vec<BindingRecord>> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }

        let contents = fs::read_to_string(&self.path)?;
        if contents.trim().is_empty() {
            return Ok(Vec::new());
        }

        Ok(serde_json::from_str(&contents)?)
    }

    fn write_all_unlocked(&self, records: &[BindingRecord]) -> Result<()> {
        ensure_parent_dir(&self.path)?;
        let json = serde_json::to_string_pretty(records)?;
        let temp_path = temp_path_for(&self.path);
        fs::write(&temp_path, json)?;
        set_file_permissions(&temp_path)?;
        fs::rename(&temp_path, &self.path)?;
        Ok(())
    }

    fn with_shared_lock<T>(&self, work: impl FnOnce(&Self) -> Result<T>) -> Result<T> {
        let lock_path = self.lock_path();
        if !lock_path.exists() {
            return work(self);
        }

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .truncate(false)
            .open(lock_path)?;
        FileExt::lock_shared(&file).map_err(|error| AdapterError::Storage(error.to_string()))?;
        let result = work(self);
        let unlock_result =
            FileExt::unlock(&file).map_err(|error| AdapterError::Storage(error.to_string()));
        match (result, unlock_result) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), _) | (Ok(_), Err(error)) => Err(error),
        }
    }

    fn with_exclusive_lock<T>(&self, work: impl FnOnce(&Self) -> Result<T>) -> Result<T> {
        ensure_parent_dir(&self.lock_path())?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(self.lock_path())?;
        FileExt::lock_exclusive(&file).map_err(|error| AdapterError::Storage(error.to_string()))?;
        let result = work(self);
        let unlock_result =
            FileExt::unlock(&file).map_err(|error| AdapterError::Storage(error.to_string()));
        match (result, unlock_result) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), _) | (Ok(_), Err(error)) => Err(error),
        }
    }
}

#[derive(Debug, Default)]
pub struct MemoryBindingStore {
    records: Mutex<Vec<BindingRecord>>,
}

impl MemoryBindingStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl BindingStore for MemoryBindingStore {
    fn list(&self) -> Result<Vec<BindingRecord>> {
        Ok(self
            .records
            .lock()
            .map_err(|_| AdapterError::Storage("binding store mutex poisoned".to_string()))?
            .clone())
    }

    fn get(&self, id: &BindingId) -> Result<Option<BindingRecord>> {
        Ok(self
            .records
            .lock()
            .map_err(|_| AdapterError::Storage("binding store mutex poisoned".to_string()))?
            .iter()
            .find(|record| &record.id == id)
            .cloned())
    }

    fn upsert(&self, record: BindingRecord) -> Result<()> {
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

    fn delete(&self, id: &BindingId) -> Result<bool> {
        let mut records = self
            .records
            .lock()
            .map_err(|_| AdapterError::Storage("binding store mutex poisoned".to_string()))?;
        let before = records.len();
        records.retain(|record| &record.id != id);
        Ok(before != records.len())
    }

    fn mutate<T, F>(&self, update: F) -> Result<T>
    where
        F: FnOnce(&mut Vec<BindingRecord>) -> Result<T>,
    {
        let mut records = self
            .records
            .lock()
            .map_err(|_| AdapterError::Storage("binding store mutex poisoned".to_string()))?;
        update(&mut records)
    }
}

/// Default environment variable name used to override the config directory.
const DEFAULT_CONFIG_DIR_ENV: &str = "NPMENC_CONFIG_DIR";

/// Resolve the application data directory.
///
/// When `env_override` is `Some`, that environment variable name is checked
/// first.  Otherwise the default `NPMENC_CONFIG_DIR` variable is consulted.
/// Falls back to the platform-standard config directory.
pub fn app_data_dir(app_name: &str) -> Result<PathBuf> {
    app_data_dir_with_env(app_name, None)
}

pub fn app_data_dir_with_env(app_name: &str, env_override: Option<&str>) -> Result<PathBuf> {
    let env_key = env_override.unwrap_or(DEFAULT_CONFIG_DIR_ENV);
    if let Some(path) = std::env::var_os(env_key) {
        let dir = PathBuf::from(path).join(app_name);
        return Ok(dir);
    }

    let config_dir = dirs::config_dir().ok_or(AdapterError::MissingConfigDir)?;
    Ok(config_dir.join(app_name))
}

impl BindingStore for JsonFileBindingStore {
    fn list(&self) -> Result<Vec<BindingRecord>> {
        self.with_shared_lock(|store| store.read_all_unlocked())
    }

    fn get(&self, id: &BindingId) -> Result<Option<BindingRecord>> {
        self.with_shared_lock(|store| {
            Ok(store
                .read_all_unlocked()?
                .into_iter()
                .find(|record| &record.id == id))
        })
    }

    fn upsert(&self, record: BindingRecord) -> Result<()> {
        self.with_exclusive_lock(|store| {
            let mut records = store.read_all_unlocked()?;
            if let Some(existing) = records.iter_mut().find(|entry| entry.id == record.id) {
                *existing = record;
            } else {
                records.push(record);
            }
            store.write_all_unlocked(&records)
        })
    }

    fn delete(&self, id: &BindingId) -> Result<bool> {
        self.with_exclusive_lock(|store| {
            let mut records = store.read_all_unlocked()?;
            let before = records.len();
            records.retain(|record| &record.id != id);
            if before == records.len() {
                return Ok(false);
            }

            store.write_all_unlocked(&records)?;
            Ok(true)
        })
    }

    fn mutate<T, F>(&self, update: F) -> Result<T>
    where
        F: FnOnce(&mut Vec<BindingRecord>) -> Result<T>,
    {
        self.with_exclusive_lock(|store| {
            let mut records = store.read_all_unlocked()?;
            let result = update(&mut records)?;
            store.write_all_unlocked(&records)?;
            Ok(result)
        })
    }
}

fn temp_path_for(path: &Path) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    let pid = std::process::id();
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("state");
    path.with_file_name(format!(".{file_name}.{pid}.{nonce}.tmp"))
}

fn ensure_parent_dir(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
        set_dir_permissions(parent)?;
    }
    Ok(())
}

#[cfg(unix)]
fn set_dir_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_dir_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_file_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_file_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use tempfile::TempDir;

    use super::*;

    #[test]
    fn upserts_and_reads_records() {
        let dir = TempDir::new().expect("temp dir");
        let store = JsonFileBindingStore::at_path(dir.path().join("bindings.json"));

        let record = BindingRecord {
            id: BindingId::new("npm:default"),
            label: "default".into(),
            target: "https://registry.npmjs.org/".into(),
            secret_env_var: "NPM_TOKEN_DEFAULT".into(),
            metadata: BTreeMap::new(),
        };

        store.upsert(record.clone()).expect("write");
        let loaded = store.get(&record.id).expect("get").expect("record");
        assert_eq!(loaded, record);
    }

    #[test]
    fn memory_store_round_trip() {
        let store = MemoryBindingStore::new();
        let record = BindingRecord {
            id: BindingId::new("npm:default"),
            label: "default".into(),
            target: "https://registry.npmjs.org/".into(),
            secret_env_var: "NPM_TOKEN_DEFAULT".into(),
            metadata: BTreeMap::new(),
        };

        store.upsert(record.clone()).expect("upsert");
        assert_eq!(store.list().expect("list"), vec![record.clone()]);
        assert!(store.delete(&record.id).expect("delete"));
    }
}
