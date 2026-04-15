use anyhow::Result;
use enclaveapp_app_adapter::{BindingId, SecretStore};

/// Restore a previously-snapshotted secret value (or delete the entry if
/// the snapshot was `None`).  This is the single shared implementation used
/// by management, install, uninstall, and token-source rollback paths.
pub fn restore_previous_secret<S>(
    secret_store: &S,
    id: &BindingId,
    previous_secret: Option<&str>,
) -> Result<()>
where
    S: SecretStore,
{
    match previous_secret {
        Some(secret) => secret_store.set(id, secret)?,
        None => {
            let _ = secret_store.delete(id)?;
        }
    }
    Ok(())
}
