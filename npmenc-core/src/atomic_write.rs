#![cfg_attr(test, allow(clippy::unwrap_used))]

//! Atomic file rewrite that preserves the target file's existing mode bits.
//!
//! `.npmrc` rewrites are safety-critical: a partial write caused by power
//! loss or a crash mid-`fs::write` leaves the file in a hybrid state with
//! the raw-token prefix truncated away but the managed placeholder not yet
//! written.  This module writes the new contents to a temporary file in
//! the same parent directory and then `rename`s it into place so the
//! transition is observably atomic.

use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result};

/// Atomically replace the contents of `path` with `contents`.
///
/// If `path` already exists, its Unix mode bits are preserved across the
/// replacement so a pre-existing `0600` `.npmrc` does not get silently
/// widened to the default umask.  On Windows, platform permissions are
/// inherited from the parent directory (matching `fs::write` behavior).
///
/// Implementation: write to a sibling temp file with a unique name, flush,
/// sync, copy the original's mode bits onto the temp file (Unix), then
/// `rename` over the target.  `rename(2)` is atomic within a single
/// filesystem, so readers either see the old contents or the new contents,
/// never a partial mix.
pub fn atomic_write_preserving_mode(path: &Path, contents: &[u8]) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));

    #[cfg(unix)]
    let original_mode = std::fs::metadata(path).ok().map(|meta| {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode()
    });

    let mut temp = tempfile::NamedTempFile::new_in(parent)
        .with_context(|| format!("creating temporary file in {}", parent.display()))?;
    temp.write_all(contents)
        .with_context(|| format!("writing temporary file for {}", path.display()))?;
    temp.flush()
        .with_context(|| format!("flushing temporary file for {}", path.display()))?;
    temp.as_file()
        .sync_all()
        .with_context(|| format!("syncing temporary file for {}", path.display()))?;

    #[cfg(unix)]
    if let Some(mode) = original_mode {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(mode))
            .with_context(|| format!("preserving mode on temp for {}", path.display()))?;
    }

    temp.persist(path)
        .map_err(|e| e.error)
        .with_context(|| format!("renaming temp into place at {}", path.display()))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn writes_new_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("new.txt");
        atomic_write_preserving_mode(&path, b"hello").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"hello");
    }

    #[test]
    fn overwrites_existing_file_atomically() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("file.txt");
        fs::write(&path, "first").unwrap();
        atomic_write_preserving_mode(&path, b"second").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"second");
    }

    #[cfg(unix)]
    #[test]
    fn preserves_existing_mode_bits() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("file.txt");
        fs::write(&path, "first").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        atomic_write_preserving_mode(&path, b"second").unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn new_file_gets_default_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("new.txt");
        atomic_write_preserving_mode(&path, b"hello").unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        // NamedTempFile in tempfile 3.x creates with 0600 on Unix.
        assert_eq!(mode, 0o600);
    }
}
