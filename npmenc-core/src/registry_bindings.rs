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
}
