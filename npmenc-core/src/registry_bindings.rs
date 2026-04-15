use enclaveapp_app_adapter::{BindingId, BindingRecord};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryBinding {
    pub id: BindingId,
    pub label: String,
    pub registry_url: String,
    pub auth_key: String,
    pub placeholder_env_var: String,
}

impl RegistryBinding {
    pub fn new(label: impl Into<String>, registry_url: impl Into<String>) -> Self {
        let label = label.into();
        let registry_url = registry_url.into();
        let auth_key = normalize_registry_url_to_auth_key(&registry_url);
        let placeholder_env_var = placeholder_env_var_for_label(&label);
        let id = BindingId::new(format!("npm:{label}"));

        Self {
            id,
            label,
            registry_url,
            auth_key,
            placeholder_env_var,
        }
    }

    pub fn to_binding_record(&self) -> BindingRecord {
        let mut metadata = std::collections::BTreeMap::new();
        metadata.insert("auth_key".to_string(), self.auth_key.clone());
        metadata.insert("registry_url".to_string(), self.registry_url.clone());
        metadata.insert("managed_by".to_string(), "npmenc".to_string());

        BindingRecord {
            id: self.id.clone(),
            label: self.label.clone(),
            target: self.registry_url.clone(),
            secret_env_var: self.placeholder_env_var.clone(),
            metadata,
        }
    }

    pub fn from_binding_record(record: &BindingRecord) -> Self {
        let auth_key = record
            .metadata
            .get("auth_key")
            .cloned()
            .unwrap_or_else(|| normalize_registry_url_to_auth_key(&record.target));
        Self {
            id: record.id.clone(),
            label: record.label.clone(),
            registry_url: record.target.clone(),
            auth_key,
            placeholder_env_var: record.secret_env_var.clone(),
        }
    }
}

pub fn default_registry_binding() -> RegistryBinding {
    RegistryBinding::new("default", "https://registry.npmjs.org/")
}

pub fn normalize_registry_url_to_auth_key(registry_url: &str) -> String {
    let without_scheme = registry_url
        .strip_prefix("https://")
        .or_else(|| registry_url.strip_prefix("http://"))
        .unwrap_or(registry_url);
    let trimmed = without_scheme.trim_end_matches('/');
    format!("//{trimmed}/:_authToken")
}

/// Reconstruct a registry URL from an `.npmrc` auth key.
///
/// Auth keys in `.npmrc` do not carry the scheme (they start with `//`), so
/// the original `http://` vs `https://` distinction is lost.  This function
/// always assumes HTTPS.  When the caller has a [`RegistryBinding`] record
/// available it should prefer `registry_url` from that record instead, as it
/// preserves the scheme supplied at registration time.
pub fn auth_key_to_registry_url(auth_key: &str) -> Option<String> {
    let host_and_path = auth_key.strip_prefix("//")?.strip_suffix("/:_authToken")?;
    Some(format!("https://{host_and_path}/"))
}

pub fn derive_label_from_auth_key(auth_key: &str) -> String {
    auth_key
        .trim_start_matches("//")
        .trim_end_matches("/:_authToken")
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .split('-')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>()
        .join("-")
}

pub fn unique_label(
    base_label: String,
    seen_labels: &mut std::collections::BTreeSet<String>,
) -> String {
    if seen_labels.insert(base_label.clone()) {
        return base_label;
    }

    let mut counter = 2_usize;
    loop {
        let candidate = format!("{base_label}-{counter}");
        if seen_labels.insert(candidate.clone()) {
            return candidate;
        }
        counter += 1;
    }
}

pub fn binding_for_auth_key(
    auth_key: &str,
    seen_labels: &mut std::collections::BTreeSet<String>,
) -> RegistryBinding {
    if auth_key == normalize_registry_url_to_auth_key("https://registry.npmjs.org/") {
        seen_labels.insert("default".to_string());
        return default_registry_binding();
    }

    let registry_url = auth_key_to_registry_url(auth_key)
        .unwrap_or_else(|| "https://registry.npmjs.org/".to_string());
    let base_label = derive_label_from_auth_key(auth_key);
    let label = unique_label(base_label, seen_labels);
    RegistryBinding::new(label, registry_url)
}

pub fn placeholder_env_var_for_label(label: &str) -> String {
    let normalized = label
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect::<String>();
    format!("NPM_TOKEN_{normalized}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_registry_urls() {
        assert_eq!(
            normalize_registry_url_to_auth_key("https://registry.npmjs.org/"),
            "//registry.npmjs.org/:_authToken"
        );
        assert_eq!(
            normalize_registry_url_to_auth_key("https://artifactory.example.com/api/npm/npm/"),
            "//artifactory.example.com/api/npm/npm/:_authToken"
        );
    }

    #[test]
    fn converts_auth_key_back_to_registry_url() {
        assert_eq!(
            auth_key_to_registry_url("//registry.npmjs.org/:_authToken"),
            Some("https://registry.npmjs.org/".to_string())
        );
    }

    #[test]
    fn builds_placeholder_name_from_label() {
        assert_eq!(
            placeholder_env_var_for_label("default"),
            "NPM_TOKEN_DEFAULT"
        );
        assert_eq!(
            placeholder_env_var_for_label("my-company/path"),
            "NPM_TOKEN_MY_COMPANY_PATH"
        );
    }

    #[test]
    fn derives_label_from_auth_key() {
        assert_eq!(
            derive_label_from_auth_key("//artifactory.example.com/api/npm/npm/:_authToken"),
            "artifactory-example-com-api-npm-npm"
        );
    }

    // ── auth_key_to_registry_url ──────────────────────────────────────

    #[test]
    fn auth_key_to_registry_url_standard() {
        let url = auth_key_to_registry_url("//registry.npmjs.org/:_authToken");
        assert_eq!(url, Some("https://registry.npmjs.org/".to_string()));
    }

    #[test]
    fn auth_key_to_registry_url_custom_registry() {
        let url = auth_key_to_registry_url("//npm.internal.corp:4873/:_authToken");
        assert_eq!(url, Some("https://npm.internal.corp:4873/".to_string()));
    }

    #[test]
    fn auth_key_to_registry_url_with_path() {
        let url = auth_key_to_registry_url("//artifactory.example.com/api/npm/npm/:_authToken");
        assert_eq!(
            url,
            Some("https://artifactory.example.com/api/npm/npm/".to_string())
        );
    }

    #[test]
    fn auth_key_to_registry_url_invalid_no_prefix() {
        assert!(auth_key_to_registry_url("not-an-auth-key").is_none());
    }

    #[test]
    fn auth_key_to_registry_url_invalid_empty() {
        assert!(auth_key_to_registry_url("").is_none());
    }

    #[test]
    fn auth_key_to_registry_url_invalid_unscoped() {
        assert!(auth_key_to_registry_url("_authToken=foo").is_none());
    }

    #[test]
    fn auth_key_to_registry_url_missing_suffix() {
        // Has the prefix but no :_authToken suffix
        assert!(auth_key_to_registry_url("//registry.npmjs.org/").is_none());
    }

    // ── Round-trip: normalize -> auth_key_to_registry_url ─────────────

    #[test]
    fn round_trip_normalize_and_back() {
        let original = "https://registry.npmjs.org/";
        let auth_key = normalize_registry_url_to_auth_key(original);
        let reconstructed = auth_key_to_registry_url(&auth_key);
        assert_eq!(reconstructed, Some(original.to_string()));
    }

    #[test]
    fn round_trip_custom_registry() {
        let original = "https://npm.pkg.github.com/";
        let auth_key = normalize_registry_url_to_auth_key(original);
        let reconstructed = auth_key_to_registry_url(&auth_key);
        assert_eq!(reconstructed, Some(original.to_string()));
    }

    // ── unique_label ──────────────────────────────────────────────────

    #[test]
    fn unique_label_first_use() {
        let mut seen = std::collections::BTreeSet::new();
        assert_eq!(unique_label("default".to_string(), &mut seen), "default");
    }

    #[test]
    fn unique_label_deduplicates() {
        let mut seen = std::collections::BTreeSet::new();
        seen.insert("default".to_string());
        assert_eq!(unique_label("default".to_string(), &mut seen), "default-2");
    }

    #[test]
    fn unique_label_increments_further() {
        let mut seen = std::collections::BTreeSet::new();
        seen.insert("default".to_string());
        seen.insert("default-2".to_string());
        assert_eq!(unique_label("default".to_string(), &mut seen), "default-3");
    }

    // ── RegistryBinding construction ──────────────────────────────────

    #[test]
    fn registry_binding_new_default() {
        let binding = RegistryBinding::new("default", "https://registry.npmjs.org/");
        assert_eq!(binding.label, "default");
        assert_eq!(binding.registry_url, "https://registry.npmjs.org/");
        assert_eq!(binding.auth_key, "//registry.npmjs.org/:_authToken");
        assert_eq!(binding.placeholder_env_var, "NPM_TOKEN_DEFAULT");
        assert_eq!(binding.id, BindingId::new("npm:default"));
    }

    #[test]
    fn registry_binding_round_trip_to_record() {
        let binding = RegistryBinding::new("custom", "https://npm.pkg.github.com/");
        let record = binding.to_binding_record();
        let restored = RegistryBinding::from_binding_record(&record);
        assert_eq!(binding.label, restored.label);
        assert_eq!(binding.registry_url, restored.registry_url);
        assert_eq!(binding.auth_key, restored.auth_key);
        assert_eq!(binding.placeholder_env_var, restored.placeholder_env_var);
    }

    // ── binding_for_auth_key ──────────────────────────────────────────

    #[test]
    fn binding_for_auth_key_default_registry() {
        let mut seen = std::collections::BTreeSet::new();
        let binding = binding_for_auth_key("//registry.npmjs.org/:_authToken", &mut seen);
        assert_eq!(binding.label, "default");
        assert!(seen.contains("default"));
    }

    #[test]
    fn binding_for_auth_key_custom_registry() {
        let mut seen = std::collections::BTreeSet::new();
        let binding = binding_for_auth_key("//npm.pkg.github.com/:_authToken", &mut seen);
        assert_eq!(binding.registry_url, "https://npm.pkg.github.com/");
        assert!(!binding.label.is_empty());
    }
}
