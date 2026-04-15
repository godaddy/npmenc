pub mod cli_common;
pub mod command_kind;
pub mod common;
pub mod config_path;
pub mod install;
pub mod management;
pub mod npmrc;
pub mod passthrough;
pub mod provenance;
pub mod registry_bindings;
mod state_lock;
pub mod token_source;
pub mod uninstall;
mod unscoped_auth;

pub use command_kind::CommandKind;
pub use config_path::resolve_effective_userconfig;
pub use install::{install_userconfig, InstallReport};
pub use management::{
    binding_for_label, delete_binding_label, list_binding_records, list_binding_rows,
    store_binding_secret, BindingListRow,
};
pub use npmrc::{
    analyze_auth_entries, discover_scoped_auth_tokens, discover_unscoped_auth_tokens,
    dominant_newline, is_comment_line, materialize_with_secrets, rewrite_with_bindings,
    split_line_ending, split_lines_preserving_endings, AuthDiagnostics, RewriteOptions,
    RewriteResult, ScopedAuthToken,
};
pub use passthrough::{
    prepare_passthrough, prepare_wrapped_invocation, prepare_wrapped_invocation_read_only,
    PreparedInvocation, WrapperInvocation, WrapperMode,
};
pub use provenance::{
    applies_to_config_path, provenance_for_path, remove_provenance_for_path,
    set_provenance_for_path, InstallProvenance,
};
pub use registry_bindings::{
    auth_key_to_registry_url, binding_for_auth_key, default_registry_binding,
    derive_label_from_auth_key, normalize_registry_url_to_auth_key, unique_label, RegistryBinding,
};
pub use token_source::{
    acquire_secret_from_token_source, clear_token_source_metadata, normalize_cli_token_source_spec,
    token_provider_is_supported, token_provider_is_valid_name, token_source_display,
    token_source_display_for_listing, token_source_display_for_spec,
    token_source_supports_direct_acquisition,
};
pub use uninstall::{uninstall_userconfig, UninstallReport};

#[cfg(test)]
pub(crate) mod test_support {
    use std::cell::Cell;
    use std::ffi::OsString;
    use std::sync::{LazyLock, Mutex, MutexGuard};

    pub(crate) static ENV_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));
    thread_local! {
        static ENV_LOCK_DEPTH: Cell<usize> = const { Cell::new(0) };
    }

    pub(crate) struct EnvLockGuard {
        guard: Option<MutexGuard<'static, ()>>,
    }

    pub(crate) fn lock_env() -> EnvLockGuard {
        let already_held = ENV_LOCK_DEPTH.with(|depth| {
            let current = depth.get();
            depth.set(current + 1);
            current > 0
        });
        let guard = if already_held {
            None
        } else {
            Some(ENV_LOCK.lock().unwrap_or_else(|error| error.into_inner()))
        };
        EnvLockGuard { guard }
    }

    impl Drop for EnvLockGuard {
        fn drop(&mut self) {
            ENV_LOCK_DEPTH.with(|depth| depth.set(depth.get().saturating_sub(1)));
            drop(self.guard.take());
        }
    }

    pub(crate) struct EnvVarGuard {
        key: &'static str,
        previous: Option<OsString>,
    }

    impl EnvVarGuard {
        pub(crate) fn set(key: &'static str, value: impl Into<OsString>) -> Self {
            let previous = std::env::var_os(key);
            std::env::set_var(key, value.into());
            Self { key, previous }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            match &self.previous {
                Some(value) => std::env::set_var(self.key, value),
                None => std::env::remove_var(self.key),
            }
        }
    }
}
