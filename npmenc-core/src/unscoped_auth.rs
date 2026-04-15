#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnscopedAuthState {
    None,
    Empty,
    ManagedPlaceholder,
    RawAllowed,
    RawProtectedByManagedDefault,
    RawUnsupported,
}

pub fn effective_unscoped_token(values: &[String]) -> Option<&str> {
    values.last().map(String::as_str)
}

pub fn looks_like_placeholder(value: &str) -> bool {
    let trimmed = value.trim();
    trimmed.starts_with("${") && trimmed.ends_with('}')
}

pub fn looks_like_empty_secret(value: &str) -> bool {
    value.trim().is_empty()
}

pub fn classify_unscoped_auth(
    value: Option<&str>,
    allow_unscoped_auth: bool,
    managed_default_binding_active: bool,
) -> UnscopedAuthState {
    match value {
        None => UnscopedAuthState::None,
        Some(value) if looks_like_placeholder(value) => UnscopedAuthState::ManagedPlaceholder,
        Some(value) if looks_like_empty_secret(value) => UnscopedAuthState::Empty,
        Some(_) if allow_unscoped_auth => UnscopedAuthState::RawAllowed,
        Some(_) if managed_default_binding_active => {
            UnscopedAuthState::RawProtectedByManagedDefault
        }
        Some(_) => UnscopedAuthState::RawUnsupported,
    }
}

impl UnscopedAuthState {
    pub fn requires_warning_or_strict(self) -> bool {
        matches!(self, Self::RawUnsupported)
    }

    pub fn should_rewrite(self) -> bool {
        matches!(
            self,
            Self::ManagedPlaceholder | Self::RawAllowed | Self::RawProtectedByManagedDefault
        )
    }

    pub fn source_line_kind(self) -> Option<&'static str> {
        match self {
            Self::ManagedPlaceholder | Self::RawAllowed | Self::RawProtectedByManagedDefault => {
                Some("unscoped_authToken")
            }
            Self::None | Self::Empty | Self::RawUnsupported => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_unscoped_auth_returns_none_when_no_value() {
        assert_eq!(
            classify_unscoped_auth(None, false, false),
            UnscopedAuthState::None
        );
    }

    #[test]
    fn classify_unscoped_auth_detects_managed_placeholder() {
        assert_eq!(
            classify_unscoped_auth(Some("${NPM_TOKEN_DEFAULT}"), false, false),
            UnscopedAuthState::ManagedPlaceholder
        );
    }

    #[test]
    fn classify_unscoped_auth_detects_empty() {
        assert_eq!(
            classify_unscoped_auth(Some("  "), false, false),
            UnscopedAuthState::Empty
        );
    }

    #[test]
    fn classify_unscoped_auth_allows_raw_when_flag_set() {
        assert_eq!(
            classify_unscoped_auth(Some("real-token"), true, false),
            UnscopedAuthState::RawAllowed
        );
    }

    #[test]
    fn classify_unscoped_auth_protected_by_managed_default() {
        assert_eq!(
            classify_unscoped_auth(Some("real-token"), false, true),
            UnscopedAuthState::RawProtectedByManagedDefault
        );
    }

    #[test]
    fn classify_unscoped_auth_raw_unsupported() {
        assert_eq!(
            classify_unscoped_auth(Some("real-token"), false, false),
            UnscopedAuthState::RawUnsupported
        );
    }
}
