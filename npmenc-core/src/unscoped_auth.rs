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

    // ── Additional edge cases ─────────────────────────────────────────

    #[test]
    fn effective_unscoped_token_returns_last() {
        let values = vec!["first".to_string(), "second".to_string()];
        assert_eq!(effective_unscoped_token(&values), Some("second"));
    }

    #[test]
    fn effective_unscoped_token_returns_none_for_empty() {
        let values: Vec<String> = vec![];
        assert_eq!(effective_unscoped_token(&values), None);
    }

    #[test]
    fn effective_unscoped_token_returns_single() {
        let values = vec!["only".to_string()];
        assert_eq!(effective_unscoped_token(&values), Some("only"));
    }

    #[test]
    fn looks_like_placeholder_recognizes_env_var_syntax() {
        assert!(looks_like_placeholder("${NPM_TOKEN_DEFAULT}"));
        assert!(looks_like_placeholder("${MY_CUSTOM_TOKEN}"));
    }

    #[test]
    fn looks_like_placeholder_rejects_partial() {
        assert!(!looks_like_placeholder("NPM_TOKEN_DEFAULT}"));
        assert!(!looks_like_placeholder("${NPM_TOKEN_DEFAULT"));
        assert!(!looks_like_placeholder("real-token"));
        assert!(!looks_like_placeholder(""));
    }

    #[test]
    fn looks_like_placeholder_with_whitespace() {
        assert!(looks_like_placeholder("  ${NPM_TOKEN_DEFAULT}  "));
    }

    #[test]
    fn looks_like_empty_secret_various() {
        assert!(looks_like_empty_secret(""));
        assert!(looks_like_empty_secret("  "));
        assert!(looks_like_empty_secret("\t"));
        assert!(!looks_like_empty_secret("x"));
    }

    #[test]
    fn classify_empty_string_value() {
        assert_eq!(
            classify_unscoped_auth(Some(""), false, false),
            UnscopedAuthState::Empty
        );
    }

    #[test]
    fn classify_whitespace_only_value() {
        assert_eq!(
            classify_unscoped_auth(Some("   \t  "), false, false),
            UnscopedAuthState::Empty
        );
    }

    #[test]
    fn classify_allow_overrides_managed_default() {
        // When both allow_unscoped_auth and managed_default_binding_active are true,
        // RawAllowed takes precedence (it is checked first)
        assert_eq!(
            classify_unscoped_auth(Some("real-token"), true, true),
            UnscopedAuthState::RawAllowed
        );
    }

    #[test]
    fn requires_warning_or_strict_only_for_raw_unsupported() {
        assert!(!UnscopedAuthState::None.requires_warning_or_strict());
        assert!(!UnscopedAuthState::Empty.requires_warning_or_strict());
        assert!(!UnscopedAuthState::ManagedPlaceholder.requires_warning_or_strict());
        assert!(!UnscopedAuthState::RawAllowed.requires_warning_or_strict());
        assert!(!UnscopedAuthState::RawProtectedByManagedDefault.requires_warning_or_strict());
        assert!(UnscopedAuthState::RawUnsupported.requires_warning_or_strict());
    }

    #[test]
    fn should_rewrite_for_managed_states() {
        assert!(UnscopedAuthState::ManagedPlaceholder.should_rewrite());
        assert!(UnscopedAuthState::RawAllowed.should_rewrite());
        assert!(UnscopedAuthState::RawProtectedByManagedDefault.should_rewrite());
        assert!(!UnscopedAuthState::None.should_rewrite());
        assert!(!UnscopedAuthState::Empty.should_rewrite());
        assert!(!UnscopedAuthState::RawUnsupported.should_rewrite());
    }

    #[test]
    fn source_line_kind_values() {
        assert_eq!(
            UnscopedAuthState::ManagedPlaceholder.source_line_kind(),
            Some("unscoped_authToken")
        );
        assert_eq!(
            UnscopedAuthState::RawAllowed.source_line_kind(),
            Some("unscoped_authToken")
        );
        assert_eq!(
            UnscopedAuthState::RawProtectedByManagedDefault.source_line_kind(),
            Some("unscoped_authToken")
        );
        assert_eq!(UnscopedAuthState::None.source_line_kind(), None);
        assert_eq!(UnscopedAuthState::Empty.source_line_kind(), None);
        assert_eq!(UnscopedAuthState::RawUnsupported.source_line_kind(), None);
    }
}
