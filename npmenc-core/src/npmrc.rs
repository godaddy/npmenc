use std::collections::{BTreeMap, BTreeSet};

use crate::registry_bindings::RegistryBinding;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopedAuthToken {
    pub auth_key: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AuthDiagnostics {
    pub unscoped_auth_tokens: Vec<String>,
    pub legacy_auth_keys: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RewriteOptions {
    pub append_missing_bindings: bool,
    pub allow_unscoped_auth: bool,
}

impl Default for RewriteOptions {
    fn default() -> Self {
        Self {
            append_missing_bindings: true,
            allow_unscoped_auth: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RewriteResult {
    pub contents: String,
    pub used_bindings: Vec<String>,
    pub appended_bindings: Vec<String>,
    pub untouched_auth_keys: Vec<String>,
}

pub fn discover_scoped_auth_tokens(source: &str) -> Vec<ScopedAuthToken> {
    split_lines_preserving_endings(source)
        .into_iter()
        .filter_map(|line| {
            let (body, _) = split_line_ending(line);
            if is_comment_line(body) {
                return None;
            }
            let (lhs, rhs) = body.split_once('=')?;
            let key = lhs.trim();
            if !is_registry_scoped_auth_token(key) {
                return None;
            }

            Some(ScopedAuthToken {
                auth_key: key.to_string(),
                value: rhs.to_string(),
            })
        })
        .collect()
}

pub fn discover_unscoped_auth_tokens(source: &str) -> Vec<String> {
    split_lines_preserving_endings(source)
        .into_iter()
        .filter_map(|line| {
            let (body, _) = split_line_ending(line);
            if is_comment_line(body) {
                return None;
            }
            let (lhs, rhs) = body.split_once('=')?;
            (lhs.trim() == "_authToken").then(|| rhs.to_string())
        })
        .collect()
}

pub fn analyze_auth_entries(source: &str) -> AuthDiagnostics {
    let mut diagnostics = AuthDiagnostics::default();

    for line in split_lines_preserving_endings(source) {
        let (body, _) = split_line_ending(line);
        if is_comment_line(body) {
            continue;
        }
        let Some((lhs, _rhs)) = body.split_once('=') else {
            continue;
        };
        let key = lhs.trim();

        if key == "_authToken" {
            diagnostics.unscoped_auth_tokens.push(key.to_string());
            continue;
        }

        if matches!(key, "_auth" | "_password" | "username")
            || (key.starts_with("//")
                && (key.ends_with(":_auth")
                    || key.ends_with(":_password")
                    || key.ends_with(":username")))
        {
            diagnostics.legacy_auth_keys.push(key.to_string());
        }
    }

    diagnostics
}

pub fn rewrite_with_bindings(
    source: &str,
    bindings: &[RegistryBinding],
    options: RewriteOptions,
) -> RewriteResult {
    let binding_map = bindings
        .iter()
        .map(|binding| (binding.auth_key.as_str(), binding))
        .collect::<BTreeMap<_, _>>();

    let mut contents = String::with_capacity(source.len() + (bindings.len() * 64));
    let mut used_bindings = BTreeSet::new();
    let mut untouched_auth_keys = BTreeSet::new();

    for line in split_lines_preserving_endings(source) {
        let (body, line_ending) = split_line_ending(line);
        if is_comment_line(body) {
            contents.push_str(line);
            continue;
        }
        if let Some((lhs, rhs)) = body.split_once('=') {
            let key = lhs.trim();
            if key == "_authToken" && options.allow_unscoped_auth {
                if let Some(binding) = bindings.iter().find(|binding| binding.label == "default") {
                    contents.push_str(&binding.auth_key);
                    contents.push('=');
                    contents.push_str("${");
                    contents.push_str(&binding.placeholder_env_var);
                    contents.push('}');
                    contents.push_str(line_ending);
                    used_bindings.insert(binding.label.clone());
                    continue;
                }
            }
            if is_registry_scoped_auth_token(key) {
                if let Some(binding) = binding_map.get(key) {
                    contents.push_str(lhs);
                    contents.push('=');
                    contents.push_str("${");
                    contents.push_str(&binding.placeholder_env_var);
                    contents.push('}');
                    contents.push_str(line_ending);
                    used_bindings.insert(binding.label.clone());
                    continue;
                }

                let _ = rhs;
                untouched_auth_keys.insert(key.to_string());
            }
        }

        contents.push_str(line);
    }

    let mut appended_bindings = Vec::new();
    if options.append_missing_bindings {
        let newline = dominant_newline(source);
        for binding in bindings {
            if used_bindings.contains(&binding.label) {
                continue;
            }

            if !contents.is_empty() && !contents.ends_with('\n') {
                contents.push_str(newline);
            }

            contents.push_str(&binding.auth_key);
            contents.push('=');
            contents.push_str("${");
            contents.push_str(&binding.placeholder_env_var);
            contents.push('}');
            contents.push_str(newline);

            used_bindings.insert(binding.label.clone());
            appended_bindings.push(binding.label.clone());
        }
    }

    RewriteResult {
        contents,
        used_bindings: used_bindings.into_iter().collect(),
        appended_bindings,
        untouched_auth_keys: untouched_auth_keys.into_iter().collect(),
    }
}

pub fn materialize_with_secrets(
    source: &str,
    bindings: &[RegistryBinding],
    secrets: &BTreeMap<String, String>,
) -> RewriteResult {
    let binding_map = bindings
        .iter()
        .map(|binding| (binding.auth_key.as_str(), binding))
        .collect::<BTreeMap<_, _>>();

    let mut contents = String::with_capacity(source.len());
    let mut used_bindings = BTreeSet::new();
    let appended_bindings = Vec::new();
    let untouched_auth_keys = Vec::new();

    for line in split_lines_preserving_endings(source) {
        let (body, line_ending) = split_line_ending(line);
        if is_comment_line(body) {
            contents.push_str(line);
            continue;
        }
        if let Some((lhs, _rhs)) = body.split_once('=') {
            let key = lhs.trim();
            if let Some(binding) = binding_map.get(key) {
                if let Some(secret) = secrets.get(&binding.label) {
                    contents.push_str(lhs);
                    contents.push('=');
                    contents.push_str(secret);
                    contents.push_str(line_ending);
                    used_bindings.insert(binding.label.clone());
                    continue;
                }
            }
        }

        contents.push_str(line);
    }

    RewriteResult {
        contents,
        used_bindings: used_bindings.into_iter().collect(),
        appended_bindings,
        untouched_auth_keys,
    }
}

fn is_registry_scoped_auth_token(key: &str) -> bool {
    key.starts_with("//") && key.ends_with(":_authToken")
}

/// Returns `true` if the line is a comment (starts with `;` or `#` after
/// optional leading whitespace).  Both prefixes are recognised by npm's
/// `.npmrc` parser.
pub fn is_comment_line(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.starts_with(';') || trimmed.starts_with('#')
}

pub fn split_lines_preserving_endings(source: &str) -> Vec<&str> {
    if source.is_empty() {
        return Vec::new();
    }

    source.split_inclusive('\n').collect()
}

pub fn split_line_ending(line: &str) -> (&str, &str) {
    if let Some(body) = line.strip_suffix("\r\n") {
        (body, "\r\n")
    } else if let Some(body) = line.strip_suffix('\n') {
        (body, "\n")
    } else {
        (line, "")
    }
}

pub fn dominant_newline(source: &str) -> &'static str {
    if source.contains("\r\n") {
        "\r\n"
    } else {
        "\n"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry_bindings::RegistryBinding;

    #[test]
    fn discovers_scoped_auth_tokens() {
        let source = "//registry.npmjs.org/:_authToken=abc\ncolor=true\n";
        let discovered = discover_scoped_auth_tokens(source);
        assert_eq!(discovered.len(), 1);
        assert_eq!(discovered[0].auth_key, "//registry.npmjs.org/:_authToken");
        assert_eq!(discovered[0].value, "abc");
    }

    #[test]
    fn rewrites_existing_binding_and_preserves_other_lines() {
        let binding = RegistryBinding::new("default", "https://registry.npmjs.org/");
        let source = "color=true\n//registry.npmjs.org/:_authToken=abc\n";

        let rewritten = rewrite_with_bindings(source, &[binding], RewriteOptions::default());

        assert_eq!(
            rewritten.contents,
            "color=true\n//registry.npmjs.org/:_authToken=${NPM_TOKEN_DEFAULT}\n"
        );
        assert_eq!(rewritten.used_bindings, vec!["default".to_string()]);
        assert!(rewritten.appended_bindings.is_empty());
    }

    #[test]
    fn appends_missing_binding() {
        let binding = RegistryBinding::new("default", "https://registry.npmjs.org/");
        let rewritten =
            rewrite_with_bindings("color=true\n", &[binding], RewriteOptions::default());

        assert!(rewritten.contents.contains("color=true\n"));
        assert!(rewritten
            .contents
            .contains("//registry.npmjs.org/:_authToken=${NPM_TOKEN_DEFAULT}\n"));
        assert_eq!(rewritten.appended_bindings, vec!["default".to_string()]);
    }

    #[test]
    fn tracks_unknown_auth_key_without_collapsing_it() {
        let binding = RegistryBinding::new("default", "https://registry.npmjs.org/");
        let source = "//custom.example.com/:_authToken=abc\n";
        let rewritten = rewrite_with_bindings(
            source,
            &[binding],
            RewriteOptions {
                append_missing_bindings: false,
                allow_unscoped_auth: false,
            },
        );

        assert_eq!(rewritten.contents, source);
        assert_eq!(
            rewritten.untouched_auth_keys,
            vec!["//custom.example.com/:_authToken".to_string()]
        );
    }

    #[test]
    fn materializes_known_binding() {
        let binding = RegistryBinding::new("default", "https://registry.npmjs.org/");
        let source = "//registry.npmjs.org/:_authToken=${NPM_TOKEN_DEFAULT}\n";
        let secrets = BTreeMap::from([("default".to_string(), "npm_ABC123".to_string())]);

        let materialized = materialize_with_secrets(source, &[binding], &secrets);

        assert_eq!(
            materialized.contents,
            "//registry.npmjs.org/:_authToken=npm_ABC123\n"
        );
    }

    #[test]
    fn analyzes_problematic_auth_entries() {
        let diagnostics = analyze_auth_entries(
            "_authToken=abc\n_auth=def\n//registry.npmjs.org/:username=user\n",
        );
        assert_eq!(
            diagnostics.unscoped_auth_tokens,
            vec!["_authToken".to_string()]
        );
        assert_eq!(
            diagnostics.legacy_auth_keys,
            vec![
                "_auth".to_string(),
                "//registry.npmjs.org/:username".to_string()
            ]
        );
    }

    #[test]
    fn discovers_unscoped_auth_tokens() {
        let discovered = discover_unscoped_auth_tokens("_authToken=abc\n_authToken=def\n");
        assert_eq!(discovered, vec!["abc".to_string(), "def".to_string()]);
    }

    #[test]
    fn rewrites_unscoped_auth_when_allowed() {
        let binding = RegistryBinding::new("default", "https://registry.npmjs.org/");
        let rewritten = rewrite_with_bindings(
            "_authToken=abc\n",
            &[binding],
            RewriteOptions {
                append_missing_bindings: false,
                allow_unscoped_auth: true,
            },
        );
        assert_eq!(
            rewritten.contents,
            "//registry.npmjs.org/:_authToken=${NPM_TOKEN_DEFAULT}\n"
        );
    }

    #[test]
    fn commented_out_auth_token_is_ignored() {
        let content = "; //registry.npmjs.org/:_authToken=secret-token\n";
        let discovered = discover_scoped_auth_tokens(content);
        assert!(
            discovered.is_empty(),
            "semicolon-prefixed comments should be ignored"
        );
    }

    #[test]
    fn hash_comment_auth_token_is_ignored() {
        let content = "# //registry.npmjs.org/:_authToken=secret-token\n";
        let discovered = discover_scoped_auth_tokens(content);
        assert!(
            discovered.is_empty(),
            "hash-prefixed comments should be ignored"
        );
    }

    #[test]
    fn comment_lines_are_ignored_by_analyze_auth_entries() {
        let diagnostics = analyze_auth_entries(
            "; _authToken=abc\n# _auth=def\n//registry.npmjs.org/:_authToken=real\n",
        );
        assert!(diagnostics.unscoped_auth_tokens.is_empty());
        assert!(diagnostics.legacy_auth_keys.is_empty());
    }

    #[test]
    fn comment_lines_are_ignored_by_discover_unscoped_auth_tokens() {
        let discovered = discover_unscoped_auth_tokens("; _authToken=abc\n# _authToken=def\n");
        assert!(discovered.is_empty());
    }

    #[test]
    fn rewrite_preserves_comment_lines() {
        let binding = RegistryBinding::new("default", "https://registry.npmjs.org/");
        let source = "; comment line\n//registry.npmjs.org/:_authToken=abc\n# another comment\n";

        let rewritten = rewrite_with_bindings(source, &[binding], RewriteOptions::default());

        assert!(rewritten.contents.contains("; comment line\n"));
        assert!(rewritten.contents.contains("# another comment\n"));
        assert!(rewritten.contents.contains("${NPM_TOKEN_DEFAULT}"));
    }

    #[test]
    fn crlf_line_endings_are_handled() {
        let source = "//registry.npmjs.org/:_authToken=abc\r\ncolor=true\r\n";
        let discovered = discover_scoped_auth_tokens(source);
        assert_eq!(discovered.len(), 1);
        assert_eq!(discovered[0].auth_key, "//registry.npmjs.org/:_authToken");
        assert_eq!(discovered[0].value, "abc");
    }

    #[test]
    fn crlf_line_endings_preserved_by_rewrite() {
        let binding = RegistryBinding::new("default", "https://registry.npmjs.org/");
        let source = "color=true\r\n//registry.npmjs.org/:_authToken=abc\r\n";

        let rewritten = rewrite_with_bindings(source, &[binding], RewriteOptions::default());

        assert_eq!(
            rewritten.contents,
            "color=true\r\n//registry.npmjs.org/:_authToken=${NPM_TOKEN_DEFAULT}\r\n"
        );
    }
}
