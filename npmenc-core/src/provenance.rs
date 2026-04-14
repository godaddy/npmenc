use std::collections::BTreeMap;
use std::path::Path;

use anyhow::Result;
use enclaveapp_app_adapter::BindingRecord;
use serde::{Deserialize, Serialize};

const INSTALL_PROVENANCE_KEY: &str = "install_provenance";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstallProvenance {
    pub config_line_origin: String,
    pub installed_from_npmrc: bool,
    pub original_line_kind: Option<String>,
}

pub fn applies_to_config_path(record: &BindingRecord, path: &str) -> bool {
    provenance_for_path(record, path).is_some()
}

pub fn has_any_install_provenance(record: &BindingRecord) -> bool {
    !load_install_provenance(record).is_empty()
        || record.metadata.contains_key("original_config_path")
        || record.metadata.contains_key("config_line_origin")
        || record.metadata.contains_key("installed_from_npmrc")
}

pub fn provenance_for_path(record: &BindingRecord, path: &str) -> Option<InstallProvenance> {
    load_install_provenance(record)
        .get(path)
        .cloned()
        .or_else(|| legacy_provenance_for_path(record, path))
}

pub fn set_provenance_for_path(
    record: &mut BindingRecord,
    path: &Path,
    provenance: InstallProvenance,
) -> Result<()> {
    let path_string = path.to_string_lossy().into_owned();
    let mut all = load_install_provenance(record);
    all.insert(path_string.clone(), provenance.clone());
    store_install_provenance(record, &all)?;
    set_legacy_provenance(record, &path_string, &provenance);
    Ok(())
}

pub fn remove_provenance_for_path(record: &mut BindingRecord, path: &str) -> Result<bool> {
    let mut all = load_install_provenance(record);
    let removed_from_map = all.remove(path).is_some();
    if removed_from_map {
        if all.is_empty() {
            record.metadata.remove(INSTALL_PROVENANCE_KEY);
            clear_legacy_provenance(record);
            return Ok(false);
        }

        store_install_provenance(record, &all)?;
        if let Some((remaining_path, remaining)) = all.iter().next() {
            set_legacy_provenance(record, remaining_path, remaining);
        }
        return Ok(true);
    }

    if record
        .metadata
        .get("original_config_path")
        .is_some_and(|stored| stored == path)
    {
        clear_legacy_provenance(record);
        return Ok(false);
    }

    Ok(!all.is_empty())
}

fn load_install_provenance(record: &BindingRecord) -> BTreeMap<String, InstallProvenance> {
    record
        .metadata
        .get(INSTALL_PROVENANCE_KEY)
        .and_then(|serialized| serde_json::from_str(serialized).ok())
        .unwrap_or_default()
}

fn store_install_provenance(
    record: &mut BindingRecord,
    all: &BTreeMap<String, InstallProvenance>,
) -> Result<()> {
    record.metadata.insert(
        INSTALL_PROVENANCE_KEY.to_string(),
        serde_json::to_string(all)?,
    );
    Ok(())
}

fn legacy_provenance_for_path(record: &BindingRecord, path: &str) -> Option<InstallProvenance> {
    let original_path = record.metadata.get("original_config_path")?;
    if original_path != path {
        return None;
    }

    let config_line_origin = record.metadata.get("config_line_origin")?.clone();
    let installed_from_npmrc = record
        .metadata
        .get("installed_from_npmrc")
        .is_some_and(|value| value == "true");
    let original_line_kind = record.metadata.get("original_line_kind").cloned();
    Some(InstallProvenance {
        config_line_origin,
        installed_from_npmrc,
        original_line_kind,
    })
}

fn set_legacy_provenance(record: &mut BindingRecord, path: &str, provenance: &InstallProvenance) {
    record.metadata.insert(
        "config_line_origin".to_string(),
        provenance.config_line_origin.clone(),
    );
    record
        .metadata
        .insert("original_config_path".to_string(), path.to_string());
    record.metadata.insert(
        "installed_from_npmrc".to_string(),
        provenance.installed_from_npmrc.to_string(),
    );
    match &provenance.original_line_kind {
        Some(kind) => {
            record
                .metadata
                .insert("original_line_kind".to_string(), kind.clone());
        }
        None => {
            record.metadata.remove("original_line_kind");
        }
    }
}

fn clear_legacy_provenance(record: &mut BindingRecord) {
    record.metadata.remove("config_line_origin");
    record.metadata.remove("original_config_path");
    record.metadata.remove("installed_from_npmrc");
    record.metadata.remove("original_line_kind");
}
