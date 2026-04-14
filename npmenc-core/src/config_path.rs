#![cfg_attr(test, allow(clippy::unwrap_used))]

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Result};

pub fn resolve_effective_userconfig(cli_override: Option<&Path>) -> Result<PathBuf> {
    if let Some(path) = cli_override {
        return normalize_config_path(path);
    }

    if let Some(path) = std::env::var_os("NPM_CONFIG_USERCONFIG") {
        if !path.is_empty() {
            return normalize_config_path(Path::new(&path));
        }
    }

    let home = dirs::home_dir().ok_or_else(|| anyhow!("unable to determine home directory"))?;
    normalize_config_path(&home.join(".npmrc"))
}

fn normalize_config_path(path: &Path) -> Result<PathBuf> {
    if path.exists() {
        return Ok(fs::canonicalize(path)?);
    }

    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }

    Ok(std::env::current_dir()?.join(path))
}

#[cfg(test)]
mod tests {
    use std::fs;

    #[cfg(unix)]
    use std::os::unix::fs::symlink;

    use tempfile::TempDir;

    use super::*;

    #[test]
    fn uses_cli_override_when_present() {
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join("custom.npmrc");
        fs::write(&path, "color=true\n").expect("write");
        assert_eq!(
            resolve_effective_userconfig(Some(&path)).expect("path"),
            path
        );
    }

    #[cfg(unix)]
    #[test]
    fn normalizes_existing_symlink_path() {
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join("real.npmrc");
        let link = dir.path().join("linked.npmrc");
        fs::write(&path, "color=true\n").expect("write");
        symlink(&path, &link).expect("symlink");

        assert_eq!(
            resolve_effective_userconfig(Some(&link)).expect("path"),
            path
        );
    }
}
