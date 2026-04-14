#![allow(clippy::panic, clippy::unwrap_used)]

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

use tempfile::TempDir;

fn make_executable_script(path: &std::path::Path, body: &str) {
    fs::write(path, body).expect("write script");
    let mut perms = fs::metadata(path).expect("metadata").permissions();
    perms.set_mode(0o755);
    fs::set_permissions(path, perms).expect("chmod");
}

fn write_default_binding_with_token_source(config_root: &std::path::Path, token_source: &str) {
    let app_dir = config_root.join("npmenc");
    fs::create_dir_all(&app_dir).expect("create app dir");
    fs::write(app_dir.join("state.lock"), "").expect("write state lock");
    fs::write(
        app_dir.join("bindings.json"),
        format!(
            concat!(
                "[{{",
                "\"id\":\"npm:default\",",
                "\"label\":\"default\",",
                "\"target\":\"https://registry.npmjs.org/\",",
                "\"secret_env_var\":\"NPM_TOKEN_DEFAULT\",",
                "\"metadata\":{{",
                "\"auth_key\":\"//registry.npmjs.org/:_authToken\",",
                "\"registry_url\":\"https://registry.npmjs.org/\",",
                "\"managed_by\":\"npmenc\",",
                "\"token_source\":\"{}\"",
                "}}",
                "}}]"
            ),
            token_source
        ),
    )
    .expect("write bindings");
}

#[test]
fn executes_target_with_transient_fallback_env_and_placeholder_config() {
    let dir = TempDir::new().expect("temp dir");
    let config_root = dir.path().join("config");
    let npmrc = dir.path().join("user.npmrc");
    let target = dir.path().join("mock-npm");
    let capture = dir.path().join("capture.txt");

    fs::write(
        &npmrc,
        "//registry.npmjs.org/:_authToken=file_token\n//artifactory.example.com/api/npm/npm/:_authToken=company_token\n",
    )
    .expect("write npmrc");

    make_executable_script(
        &target,
        &format!(
            "#!/bin/sh\nprintf 'default=%s\\ncompany=%s\\nconfig=%s\\n' \"$NPM_TOKEN_DEFAULT\" \"$NPM_TOKEN_ARTIFACTORY_EXAMPLE_COM_API_NPM_NPM\" \"$NPM_CONFIG_USERCONFIG\" > \"{}\"\ncat \"$NPM_CONFIG_USERCONFIG\" >> \"{}\"\n",
            capture.display(),
            capture.display()
        ),
    );

    let output = Command::new(env!("CARGO_BIN_EXE_npmenc"))
        .env("NPMENC_CONFIG_DIR", &config_root)
        .arg("--userconfig")
        .arg(&npmrc)
        .arg("--npm-bin")
        .arg(&target)
        .arg("--")
        .arg("ping")
        .output()
        .expect("run npmenc");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let captured = fs::read_to_string(&capture).expect("capture");
    assert!(captured.contains("default=file_token"));
    assert!(captured.contains("company=company_token"));
    assert!(captured.contains("//registry.npmjs.org/:_authToken=${NPM_TOKEN_DEFAULT}"));
    assert!(captured.contains("//artifactory.example.com/api/npm/npm/:_authToken=${NPM_TOKEN_ARTIFACTORY_EXAMPLE_COM_API_NPM_NPM}"));
    assert!(!captured.contains("file_token\n//registry"));
}

#[test]
fn managed_binding_overrides_materialized_file_token() {
    let dir = TempDir::new().expect("temp dir");
    let config_root = dir.path().join("config");
    let npmrc = dir.path().join("user.npmrc");
    let target = dir.path().join("mock-npm");
    let capture = dir.path().join("capture.txt");

    fs::write(&npmrc, "//registry.npmjs.org/:_authToken=file_token\n").expect("write npmrc");

    make_executable_script(
        &target,
        &format!(
            "#!/bin/sh\nprintf 'default=%s\\n' \"$NPM_TOKEN_DEFAULT\" > \"{}\"\n",
            capture.display()
        ),
    );

    let set_output = Command::new(env!("CARGO_BIN_EXE_npmenc"))
        .env("NPMENC_CONFIG_DIR", &config_root)
        .args(["token", "set", "--secret", "stored_token"])
        .output()
        .expect("token set");
    assert!(
        set_output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&set_output.stderr)
    );

    let run_output = Command::new(env!("CARGO_BIN_EXE_npmenc"))
        .env("NPMENC_CONFIG_DIR", &config_root)
        .arg("--userconfig")
        .arg(&npmrc)
        .arg("--npm-bin")
        .arg(&target)
        .arg("--")
        .arg("ping")
        .output()
        .expect("run npmenc");
    assert!(
        run_output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&run_output.stderr)
    );

    let captured = fs::read_to_string(&capture).expect("capture");
    assert!(captured.contains("default=stored_token"));
    assert!(String::from_utf8_lossy(&run_output.stderr).contains("using stored managed secret"));
}

#[test]
fn dry_run_does_not_invoke_token_source_for_managed_binding() {
    let dir = TempDir::new().expect("temp dir");
    let config_root = dir.path().join("config");
    let npmrc = dir.path().join("user.npmrc");
    let target = dir.path().join("mock-npm");
    let token_source = dir.path().join("source-token");
    let marker = dir.path().join("token-source-ran");

    fs::write(
        &npmrc,
        "//registry.npmjs.org/:_authToken=${NPM_TOKEN_DEFAULT}\n",
    )
    .expect("write npmrc");
    make_executable_script(&target, "#!/bin/sh\n");
    make_executable_script(
        &token_source,
        &format!(
            "#!/bin/sh\nprintf x > \"{}\"\nprintf 'token-from-source\\n'\n",
            marker.display()
        ),
    );
    write_default_binding_with_token_source(&config_root, &token_source.to_string_lossy());

    let output = Command::new(env!("CARGO_BIN_EXE_npmenc"))
        .env("NPMENC_CONFIG_DIR", &config_root)
        .arg("--userconfig")
        .arg(&npmrc)
        .arg("--npm-bin")
        .arg(&target)
        .arg("--dry-run")
        .arg("--")
        .arg("ping")
        .output()
        .expect("run npmenc");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!marker.exists());
    assert!(String::from_utf8_lossy(&output.stdout).contains("env NPM_TOKEN_DEFAULT=<redacted>"));
}

#[test]
fn dry_run_does_not_create_managed_state_directory() {
    let dir = TempDir::new().expect("temp dir");
    let config_root = dir.path().join("config");
    let npmrc = dir.path().join("user.npmrc");
    let target = dir.path().join("mock-npm");

    fs::write(&npmrc, "color=true\n").expect("write npmrc");
    make_executable_script(&target, "#!/bin/sh\n");

    let output = Command::new(env!("CARGO_BIN_EXE_npmenc"))
        .env("NPMENC_CONFIG_DIR", &config_root)
        .arg("--userconfig")
        .arg(&npmrc)
        .arg("--npm-bin")
        .arg(&target)
        .arg("--dry-run")
        .arg("--")
        .arg("ping")
        .output()
        .expect("run npmenc");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!config_root.join("npmenc").exists());
}

#[test]
fn install_and_uninstall_round_trip_unscoped_auth_shape() {
    let dir = TempDir::new().expect("temp dir");
    let config_root = dir.path().join("config");
    let npmrc = dir.path().join("user.npmrc");
    fs::write(&npmrc, "_authToken=npm_ABC123\n").expect("write npmrc");

    let install_output = Command::new(env!("CARGO_BIN_EXE_npmenc"))
        .env("NPMENC_CONFIG_DIR", &config_root)
        .arg("--userconfig")
        .arg(&npmrc)
        .arg("--allow-unscoped-auth")
        .arg("install")
        .output()
        .expect("install");
    assert!(
        install_output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&install_output.stderr)
    );

    let installed = fs::read_to_string(&npmrc).expect("read installed");
    assert_eq!(
        installed,
        "//registry.npmjs.org/:_authToken=${NPM_TOKEN_DEFAULT}\n"
    );

    let uninstall_output = Command::new(env!("CARGO_BIN_EXE_npmenc"))
        .env("NPMENC_CONFIG_DIR", &config_root)
        .arg("--userconfig")
        .arg(&npmrc)
        .arg("uninstall")
        .output()
        .expect("uninstall");
    assert!(
        uninstall_output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&uninstall_output.stderr)
    );

    let restored = fs::read_to_string(&npmrc).expect("read restored");
    assert_eq!(restored, "_authToken=npm_ABC123\n");
}

#[test]
fn auto_install_converts_source_and_continues_execution() {
    let dir = TempDir::new().expect("temp dir");
    let config_root = dir.path().join("config");
    let npmrc = dir.path().join("user.npmrc");
    let target = dir.path().join("mock-npm");
    let capture = dir.path().join("capture.txt");

    fs::write(&npmrc, "//registry.npmjs.org/:_authToken=file_token\n").expect("write npmrc");

    make_executable_script(
        &target,
        &format!(
            "#!/bin/sh\nprintf 'default=%s\\nconfig=%s\\n' \"$NPM_TOKEN_DEFAULT\" \"$NPM_CONFIG_USERCONFIG\" > \"{}\"\ncat \"$NPM_CONFIG_USERCONFIG\" >> \"{}\"\n",
            capture.display(),
            capture.display()
        ),
    );

    let output = Command::new(env!("CARGO_BIN_EXE_npmenc"))
        .env("NPMENC_CONFIG_DIR", &config_root)
        .arg("--userconfig")
        .arg(&npmrc)
        .arg("--npm-bin")
        .arg(&target)
        .arg("--auto-install")
        .arg("--")
        .arg("ping")
        .output()
        .expect("run npmenc");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let persisted = fs::read_to_string(&npmrc).expect("read persisted");
    assert_eq!(
        persisted,
        "//registry.npmjs.org/:_authToken=${NPM_TOKEN_DEFAULT}\n"
    );

    let captured = fs::read_to_string(&capture).expect("capture");
    assert!(captured.contains("default=file_token"));
    assert!(captured.contains("//registry.npmjs.org/:_authToken=${NPM_TOKEN_DEFAULT}"));
    assert!(String::from_utf8_lossy(&output.stderr).contains("install activated 1 managed binding"));
}

#[test]
fn uninstall_removes_placeholder_line_that_install_appended_for_managed_binding() {
    let dir = TempDir::new().expect("temp dir");
    let config_root = dir.path().join("config");
    let npmrc = dir.path().join("user.npmrc");
    fs::write(&npmrc, "color=true\n").expect("write npmrc");

    let set_output = Command::new(env!("CARGO_BIN_EXE_npmenc"))
        .env("NPMENC_CONFIG_DIR", &config_root)
        .args(["token", "set", "--secret", "stored_token"])
        .output()
        .expect("token set");
    assert!(
        set_output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&set_output.stderr)
    );

    let install_output = Command::new(env!("CARGO_BIN_EXE_npmenc"))
        .env("NPMENC_CONFIG_DIR", &config_root)
        .arg("--userconfig")
        .arg(&npmrc)
        .arg("install")
        .output()
        .expect("install");
    assert!(
        install_output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&install_output.stderr)
    );
    let installed = fs::read_to_string(&npmrc).expect("read installed");
    assert_eq!(
        installed,
        "color=true\n//registry.npmjs.org/:_authToken=${NPM_TOKEN_DEFAULT}\n"
    );

    let uninstall_output = Command::new(env!("CARGO_BIN_EXE_npmenc"))
        .env("NPMENC_CONFIG_DIR", &config_root)
        .arg("--userconfig")
        .arg(&npmrc)
        .arg("uninstall")
        .output()
        .expect("uninstall");
    assert!(
        uninstall_output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&uninstall_output.stderr)
    );

    let restored = fs::read_to_string(&npmrc).expect("read restored");
    assert_eq!(restored, "color=true\n");
}

#[test]
fn token_add_alias_and_uninstall_keep_secrets_work() {
    let dir = TempDir::new().expect("temp dir");
    let config_root = dir.path().join("config");
    let npmrc = dir.path().join("user.npmrc");
    fs::write(&npmrc, "color=true\n").expect("write npmrc");

    let add_output = Command::new(env!("CARGO_BIN_EXE_npmenc"))
        .env("NPMENC_CONFIG_DIR", &config_root)
        .args(["token", "add", "--secret", "stored_token"])
        .output()
        .expect("token add");
    assert!(
        add_output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&add_output.stderr)
    );

    let install_output = Command::new(env!("CARGO_BIN_EXE_npmenc"))
        .env("NPMENC_CONFIG_DIR", &config_root)
        .arg("--userconfig")
        .arg(&npmrc)
        .arg("install")
        .output()
        .expect("install");
    assert!(
        install_output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&install_output.stderr)
    );

    let uninstall_output = Command::new(env!("CARGO_BIN_EXE_npmenc"))
        .env("NPMENC_CONFIG_DIR", &config_root)
        .arg("--userconfig")
        .arg(&npmrc)
        .args(["uninstall", "--keep-secrets"])
        .output()
        .expect("uninstall");
    assert!(
        uninstall_output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&uninstall_output.stderr)
    );

    let restored = fs::read_to_string(&npmrc).expect("read restored");
    assert_eq!(restored, "color=true\n");
    let bindings_json = fs::read_to_string(config_root.join("npmenc").join("bindings.json"))
        .expect("read bindings");
    assert!(!bindings_json.contains(&*npmrc.to_string_lossy()));

    let list_output = Command::new(env!("CARGO_BIN_EXE_npmenc"))
        .env("NPMENC_CONFIG_DIR", &config_root)
        .args(["token", "list"])
        .output()
        .expect("token list");
    assert!(
        list_output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&list_output.stderr)
    );
    assert!(String::from_utf8_lossy(&list_output.stdout).contains("default"));
}

#[test]
fn duplicate_registry_binding_for_same_url_is_rejected() {
    let dir = TempDir::new().expect("temp dir");
    let config_root = dir.path().join("config");

    let first = Command::new(env!("CARGO_BIN_EXE_npmenc"))
        .env("NPMENC_CONFIG_DIR", &config_root)
        .args([
            "registry",
            "add",
            "--label",
            "first",
            "--url",
            "https://artifactory.example.com/api/npm/npm/",
            "--secret",
            "token-a",
        ])
        .output()
        .expect("first registry add");
    assert!(
        first.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&first.stderr)
    );

    let second = Command::new(env!("CARGO_BIN_EXE_npmenc"))
        .env("NPMENC_CONFIG_DIR", &config_root)
        .args([
            "registry",
            "add",
            "--label",
            "second",
            "--url",
            "https://artifactory.example.com/api/npm/npm/",
            "--secret",
            "token-b",
        ])
        .output()
        .expect("second registry add");
    assert!(!second.status.success());
    assert!(String::from_utf8_lossy(&second.stderr).contains("already managed by binding `first`"));
}

#[test]
fn dry_run_prints_effective_config_contents() {
    let dir = TempDir::new().expect("temp dir");
    let config_root = dir.path().join("config");
    let npmrc = dir.path().join("user.npmrc");
    fs::write(
        &npmrc,
        "//registry.npmjs.org/:_authToken=file_token\ncolor=true\n",
    )
    .expect("write npmrc");

    let output = Command::new(env!("CARGO_BIN_EXE_npmenc"))
        .env("NPMENC_CONFIG_DIR", &config_root)
        .arg("--userconfig")
        .arg(&npmrc)
        .arg("--dry-run")
        .arg("--")
        .arg("--version")
        .output()
        .expect("run npmenc");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("effective_config: "));
    assert!(stdout.contains("effective_config_contents:\n"));
    assert!(stdout.contains("//registry.npmjs.org/:_authToken=${NPM_TOKEN_DEFAULT}\n"));
    assert!(stdout.contains("color=true\n"));
}

#[test]
fn print_effective_config_uses_source_path_in_passthrough_mode() {
    let dir = TempDir::new().expect("temp dir");
    let config_root = dir.path().join("config");
    let npmrc = dir.path().join("user.npmrc");
    fs::write(&npmrc, "color=true\n").expect("write npmrc");

    let output = Command::new(env!("CARGO_BIN_EXE_npmenc"))
        .env("NPMENC_CONFIG_DIR", &config_root)
        .arg("--userconfig")
        .arg(&npmrc)
        .arg("--print-effective-config")
        .arg("--")
        .arg("--version")
        .output()
        .expect("run npmenc");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        npmrc.display().to_string()
    );
}

#[test]
fn credential_alias_and_remove_alias_work() {
    let dir = TempDir::new().expect("temp dir");
    let config_root = dir.path().join("config");

    let set_output = Command::new(env!("CARGO_BIN_EXE_npmenc"))
        .env("NPMENC_CONFIG_DIR", &config_root)
        .args(["credential", "set", "--secret", "stored_token"])
        .output()
        .expect("credential set");
    assert!(
        set_output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&set_output.stderr)
    );

    let list_output = Command::new(env!("CARGO_BIN_EXE_npmenc"))
        .env("NPMENC_CONFIG_DIR", &config_root)
        .args(["credential", "list"])
        .output()
        .expect("credential list");
    assert!(
        list_output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&list_output.stderr)
    );
    assert!(String::from_utf8_lossy(&list_output.stdout).contains("default"));

    let delete_output = Command::new(env!("CARGO_BIN_EXE_npmenc"))
        .env("NPMENC_CONFIG_DIR", &config_root)
        .args(["credential", "remove"])
        .output()
        .expect("credential remove");
    assert!(
        delete_output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&delete_output.stderr)
    );
    assert!(String::from_utf8_lossy(&delete_output.stdout).contains("deleted binding `default`"));
}

#[test]
fn token_set_secret_stdin_works() {
    let dir = TempDir::new().expect("temp dir");
    let config_root = dir.path().join("config");

    let mut child = Command::new(env!("CARGO_BIN_EXE_npmenc"))
        .env("NPMENC_CONFIG_DIR", &config_root)
        .args(["token", "set", "--secret-stdin"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn token set");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(b"stdin_secret\n")
        .expect("write stdin");

    let output = child.wait_with_output().expect("wait output");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let list_output = Command::new(env!("CARGO_BIN_EXE_npmenc"))
        .env("NPMENC_CONFIG_DIR", &config_root)
        .args(["token", "list"])
        .output()
        .expect("token list");
    assert!(
        list_output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&list_output.stderr)
    );
    assert!(String::from_utf8_lossy(&list_output.stdout).contains("default"));
}

#[test]
fn token_set_token_source_command_works() {
    let dir = TempDir::new().expect("temp dir");
    let config_root = dir.path().join("config");
    let token_source = dir.path().join("source-token");
    make_executable_script(&token_source, "#!/bin/sh\nprintf 'token_from_source\\n'\n");

    let output = Command::new(env!("CARGO_BIN_EXE_npmenc"))
        .env("NPMENC_CONFIG_DIR", &config_root)
        .args([
            "token",
            "set",
            "--token-source",
            &token_source.to_string_lossy(),
        ])
        .output()
        .expect("token set");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let list_output = Command::new(env!("CARGO_BIN_EXE_npmenc"))
        .env("NPMENC_CONFIG_DIR", &config_root)
        .args(["token", "list"])
        .output()
        .expect("token list");
    let stdout = String::from_utf8_lossy(&list_output.stdout);
    assert!(stdout.contains("default"));
    assert!(stdout.contains("command:source-token#"));
    assert!(!stdout.contains(&token_source.to_string_lossy().to_string()));
}

#[test]
fn registry_set_default_rejects_custom_url() {
    let dir = TempDir::new().expect("temp dir");
    let config_root = dir.path().join("config");

    let output = Command::new(env!("CARGO_BIN_EXE_npmenc"))
        .env("NPMENC_CONFIG_DIR", &config_root)
        .args([
            "registry",
            "set-default",
            "--url",
            "https://corp.example.com/npm/",
            "--secret",
            "corp_token",
        ])
        .output()
        .expect("registry set-default");

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("the `default` binding is reserved"));
}

#[test]
fn uninstall_purges_managed_state_by_default() {
    let dir = TempDir::new().expect("temp dir");
    let config_root = dir.path().join("config");
    let npmrc = dir.path().join("user.npmrc");
    fs::write(&npmrc, "color=true\n").expect("write npmrc");

    let set_output = Command::new(env!("CARGO_BIN_EXE_npmenc"))
        .env("NPMENC_CONFIG_DIR", &config_root)
        .args(["token", "set", "--secret", "stored_token"])
        .output()
        .expect("token set");
    assert!(set_output.status.success());

    let install_output = Command::new(env!("CARGO_BIN_EXE_npmenc"))
        .env("NPMENC_CONFIG_DIR", &config_root)
        .arg("--userconfig")
        .arg(&npmrc)
        .arg("install")
        .output()
        .expect("install");
    assert!(install_output.status.success());

    let uninstall_output = Command::new(env!("CARGO_BIN_EXE_npmenc"))
        .env("NPMENC_CONFIG_DIR", &config_root)
        .arg("--userconfig")
        .arg(&npmrc)
        .arg("uninstall")
        .output()
        .expect("uninstall");
    assert!(uninstall_output.status.success());
    assert!(String::from_utf8_lossy(&uninstall_output.stdout)
        .contains("purged managed bindings and secrets"));

    let list_output = Command::new(env!("CARGO_BIN_EXE_npmenc"))
        .env("NPMENC_CONFIG_DIR", &config_root)
        .args(["token", "list"])
        .output()
        .expect("token list");
    assert!(list_output.status.success());
    assert!(String::from_utf8_lossy(&list_output.stdout)
        .trim()
        .is_empty());
}

#[test]
fn registry_command_family_works() {
    let dir = TempDir::new().expect("temp dir");
    let config_root = dir.path().join("config");

    let add_output = Command::new(env!("CARGO_BIN_EXE_npmenc"))
        .env("NPMENC_CONFIG_DIR", &config_root)
        .args([
            "registry",
            "add",
            "--label",
            "mycompany",
            "--url",
            "https://artifactory.example.com/api/npm/npm/",
            "--secret",
            "company_token",
        ])
        .output()
        .expect("registry add");
    assert!(
        add_output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&add_output.stderr)
    );

    let set_default_output = Command::new(env!("CARGO_BIN_EXE_npmenc"))
        .env("NPMENC_CONFIG_DIR", &config_root)
        .args(["registry", "set-default", "--secret", "default_token"])
        .output()
        .expect("registry set-default");
    assert!(
        set_default_output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&set_default_output.stderr)
    );

    let list_output = Command::new(env!("CARGO_BIN_EXE_npmenc"))
        .env("NPMENC_CONFIG_DIR", &config_root)
        .args(["registry", "list"])
        .output()
        .expect("registry list");
    assert!(
        list_output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&list_output.stderr)
    );
    let stdout = String::from_utf8_lossy(&list_output.stdout);
    assert!(stdout.contains("default"));
    assert!(stdout.contains("mycompany"));

    let remove_output = Command::new(env!("CARGO_BIN_EXE_npmenc"))
        .env("NPMENC_CONFIG_DIR", &config_root)
        .args(["registry", "remove", "--label", "mycompany"])
        .output()
        .expect("registry remove");
    assert!(
        remove_output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&remove_output.stderr)
    );

    let list_after = Command::new(env!("CARGO_BIN_EXE_npmenc"))
        .env("NPMENC_CONFIG_DIR", &config_root)
        .args(["registry", "list"])
        .output()
        .expect("registry list after");
    let stdout_after = String::from_utf8_lossy(&list_after.stdout);
    assert!(stdout_after.contains("default"));
    assert!(!stdout_after.contains("mycompany"));
}

#[test]
fn token_set_rejects_unsupported_provider_without_secret() {
    let dir = TempDir::new().expect("temp dir");
    let config_root = dir.path().join("config");

    let output = Command::new(env!("CARGO_BIN_EXE_npmenc"))
        .env("NPMENC_CONFIG_DIR", &config_root)
        .args(["token", "set", "--token-provider", "unknown-provider"])
        .output()
        .expect("token set");

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("metadata only; specify --secret or --secret-stdin alongside it"));
}

#[test]
fn token_set_with_supported_provider_acquires_and_lists_safe_metadata() {
    let dir = TempDir::new().expect("temp dir");
    let config_root = dir.path().join("config");
    let bin_dir = dir.path().join("bin");
    fs::create_dir_all(&bin_dir).expect("bin dir");
    let provider = bin_dir.join("sso-jwt");
    make_executable_script(&provider, "#!/bin/sh\nprintf 'provider-token'\n");
    let path_env = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );

    let output = Command::new(env!("CARGO_BIN_EXE_npmenc"))
        .env("NPMENC_CONFIG_DIR", &config_root)
        .env("PATH", &path_env)
        .env("NPMENC_TOKEN_PROVIDER_SSO_JWT_BIN", &provider)
        .args(["token", "set", "--token-provider", "sso-jwt"])
        .output()
        .expect("token set");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let list_output = Command::new(env!("CARGO_BIN_EXE_npmenc"))
        .env("NPMENC_CONFIG_DIR", &config_root)
        .args(["token", "list"])
        .output()
        .expect("token list");
    let stdout = String::from_utf8_lossy(&list_output.stdout);
    assert!(stdout.contains("default"));
    assert!(stdout.contains("sso-jwt"));
    assert!(!stdout.contains("provider-token"));
}

#[test]
fn token_set_with_secret_can_store_supported_provider_metadata_without_provider_binary() {
    let dir = TempDir::new().expect("temp dir");
    let config_root = dir.path().join("config");

    let output = Command::new(env!("CARGO_BIN_EXE_npmenc"))
        .env("NPMENC_CONFIG_DIR", &config_root)
        .env("NPMENC_TOKEN_PROVIDER_SSO_JWT_BIN", "/definitely/missing")
        .args([
            "token",
            "set",
            "--secret",
            "stored_token",
            "--token-provider",
            "sso-jwt",
            "--token-handle",
            "corp/prod",
        ])
        .output()
        .expect("token set");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let list_output = Command::new(env!("CARGO_BIN_EXE_npmenc"))
        .env("NPMENC_CONFIG_DIR", &config_root)
        .args(["token", "list"])
        .output()
        .expect("token list");
    let stdout = String::from_utf8_lossy(&list_output.stdout);
    assert!(stdout.contains("default"));
    assert!(stdout.contains("sso-jwt"));
}

#[test]
fn token_set_with_supported_provider_persists_prepared_state_for_later_reacquisition() {
    let dir = TempDir::new().expect("temp dir");
    let config_root = dir.path().join("config");
    let userconfig = dir.path().join("user.npmrc");
    let bin1 = dir.path().join("bin1");
    let bin2 = dir.path().join("bin2");
    fs::create_dir_all(&bin1).expect("bin1");
    fs::create_dir_all(&bin2).expect("bin2");
    let provider1 = bin1.join("sso-jwt");
    let provider2 = bin2.join("sso-jwt");
    make_executable_script(&provider1, "#!/bin/sh\nprintf 'token-one'\n");
    make_executable_script(&provider2, "#!/bin/sh\nprintf 'token-two'\n");
    let target = dir.path().join("npm");
    make_executable_script(&target, "#!/bin/sh\nprintf '%s' \"$NPM_TOKEN_DEFAULT\"\n");
    fs::write(
        &userconfig,
        "//registry.npmjs.org/:_authToken=${NPM_TOKEN_DEFAULT}\n",
    )
    .expect("write npmrc");

    let set_output = Command::new(env!("CARGO_BIN_EXE_npmenc"))
        .env("NPMENC_CONFIG_DIR", &config_root)
        .env("NPMENC_TOKEN_PROVIDER_SSO_JWT_BIN", &provider1)
        .args(["token", "set", "--token-provider", "sso-jwt"])
        .output()
        .expect("token set");
    assert!(
        set_output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&set_output.stderr)
    );

    let binding_secret = config_root
        .join("npmenc/secrets/045354396ae3d13dd5b0d7adfd7e1cee14c7b7b60e35b141e5d3f73fe2ca6fe8");
    fs::remove_file(&binding_secret).expect("remove cached binding secret");

    let run_output = Command::new(env!("CARGO_BIN_EXE_npmenc"))
        .env("NPMENC_CONFIG_DIR", &config_root)
        .env("NPMENC_TOKEN_PROVIDER_SSO_JWT_BIN", &provider2)
        .arg("--userconfig")
        .arg(&userconfig)
        .arg("--npm-bin")
        .arg(&target)
        .arg("--")
        .arg("--version")
        .output()
        .expect("run npmenc");
    assert!(
        run_output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&run_output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&run_output.stdout), "token-one");
}

#[test]
fn dry_run_still_recognizes_provider_managed_binding_after_secret_eviction() {
    let dir = TempDir::new().expect("temp dir");
    let config_root = dir.path().join("config");
    let userconfig = dir.path().join("user.npmrc");
    let bin = dir.path().join("bin");
    fs::create_dir_all(&bin).expect("bin");
    let provider = bin.join("sso-jwt");
    make_executable_script(&provider, "#!/bin/sh\nprintf 'token-one'\n");
    let target = dir.path().join("npm");
    make_executable_script(&target, "#!/bin/sh\nprintf '%s' \"$NPM_TOKEN_DEFAULT\"\n");
    fs::write(
        &userconfig,
        "//registry.npmjs.org/:_authToken=${NPM_TOKEN_DEFAULT}\n",
    )
    .expect("write npmrc");

    let set_output = Command::new(env!("CARGO_BIN_EXE_npmenc"))
        .env("NPMENC_CONFIG_DIR", &config_root)
        .env("NPMENC_TOKEN_PROVIDER_SSO_JWT_BIN", &provider)
        .args(["token", "set", "--token-provider", "sso-jwt"])
        .output()
        .expect("token set");
    assert!(set_output.status.success());

    let warm_output = Command::new(env!("CARGO_BIN_EXE_npmenc"))
        .env("NPMENC_CONFIG_DIR", &config_root)
        .env("NPMENC_TOKEN_PROVIDER_SSO_JWT_BIN", &provider)
        .arg("--userconfig")
        .arg(&userconfig)
        .arg("--npm-bin")
        .arg(&target)
        .arg("--")
        .arg("--version")
        .output()
        .expect("warm run");
    assert!(warm_output.status.success());

    let binding_secret = config_root
        .join("npmenc/secrets/045354396ae3d13dd5b0d7adfd7e1cee14c7b7b60e35b141e5d3f73fe2ca6fe8");
    fs::remove_file(&binding_secret).expect("remove cached binding secret");

    let dry_run = Command::new(env!("CARGO_BIN_EXE_npmenc"))
        .env("NPMENC_CONFIG_DIR", &config_root)
        .arg("--userconfig")
        .arg(&userconfig)
        .arg("--npm-bin")
        .arg(&target)
        .arg("--dry-run")
        .arg("--")
        .arg("--version")
        .output()
        .expect("dry run");
    assert!(
        dry_run.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&dry_run.stderr)
    );
    let stdout = String::from_utf8_lossy(&dry_run.stdout);
    assert!(stdout.contains("mode: ManagedBindings"));
}

#[test]
fn token_source_metadata_is_listed() {
    let dir = TempDir::new().expect("temp dir");
    let config_root = dir.path().join("config");

    let set_output = Command::new(env!("CARGO_BIN_EXE_npmenc"))
        .env("NPMENC_CONFIG_DIR", &config_root)
        .args([
            "token",
            "set",
            "--token-source",
            "sso-jwt",
            "--secret",
            "stored_token",
        ])
        .output()
        .expect("token set");
    assert!(
        set_output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&set_output.stderr)
    );

    let list_output = Command::new(env!("CARGO_BIN_EXE_npmenc"))
        .env("NPMENC_CONFIG_DIR", &config_root)
        .args(["token", "list"])
        .output()
        .expect("token list");
    assert!(
        list_output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&list_output.stderr)
    );

    let stdout = String::from_utf8_lossy(&list_output.stdout);
    assert!(stdout.contains("default"));
    assert!(stdout.contains("sso-jwt"));
}

#[test]
fn deleting_missing_binding_reports_cleanly() {
    let dir = TempDir::new().expect("temp dir");
    let config_root = dir.path().join("config");

    let output = Command::new(env!("CARGO_BIN_EXE_npmenc"))
        .env("NPMENC_CONFIG_DIR", &config_root)
        .args(["token", "delete", "--label", "missing"])
        .output()
        .expect("token delete");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("no binding found for `missing`"));
}

#[test]
fn deleting_installed_binding_is_rejected() {
    let dir = TempDir::new().expect("temp dir");
    let config_root = dir.path().join("config");
    let npmrc = dir.path().join("user.npmrc");
    fs::write(&npmrc, "color=true\n").expect("write npmrc");

    let set_output = Command::new(env!("CARGO_BIN_EXE_npmenc"))
        .env("NPMENC_CONFIG_DIR", &config_root)
        .args(["token", "set", "--secret", "stored_token"])
        .output()
        .expect("token set");
    assert!(
        set_output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&set_output.stderr)
    );

    let install_output = Command::new(env!("CARGO_BIN_EXE_npmenc"))
        .env("NPMENC_CONFIG_DIR", &config_root)
        .arg("--userconfig")
        .arg(&npmrc)
        .arg("install")
        .output()
        .expect("install");
    assert!(
        install_output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&install_output.stderr)
    );

    let delete_output = Command::new(env!("CARGO_BIN_EXE_npmenc"))
        .env("NPMENC_CONFIG_DIR", &config_root)
        .args(["token", "delete"])
        .output()
        .expect("token delete");
    assert!(!delete_output.status.success());
    assert!(String::from_utf8_lossy(&delete_output.stderr).contains("run uninstall first"));
}

#[test]
fn managed_custom_registry_binding_is_appended_during_wrapped_execution() {
    let dir = TempDir::new().expect("temp dir");
    let config_root = dir.path().join("config");
    let npmrc = dir.path().join("user.npmrc");
    let target = dir.path().join("mock-npm");
    let capture = dir.path().join("capture.txt");

    fs::write(&npmrc, "color=true\n").expect("write npmrc");
    make_executable_script(
        &target,
        &format!(
            "#!/bin/sh\nprintf 'company=%s\\nconfig=%s\\n' \"$NPM_TOKEN_MYCOMPANY\" \"$NPM_CONFIG_USERCONFIG\" > \"{}\"\ncat \"$NPM_CONFIG_USERCONFIG\" >> \"{}\"\n",
            capture.display(),
            capture.display()
        ),
    );

    let set_output = Command::new(env!("CARGO_BIN_EXE_npmenc"))
        .env("NPMENC_CONFIG_DIR", &config_root)
        .args([
            "registry",
            "add",
            "--label",
            "mycompany",
            "--url",
            "https://artifactory.example.com/api/npm/npm/",
            "--secret",
            "company_token",
        ])
        .output()
        .expect("registry add");
    assert!(
        set_output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&set_output.stderr)
    );

    let run_output = Command::new(env!("CARGO_BIN_EXE_npmenc"))
        .env("NPMENC_CONFIG_DIR", &config_root)
        .arg("--userconfig")
        .arg(&npmrc)
        .arg("--npm-bin")
        .arg(&target)
        .arg("--")
        .arg("ping")
        .output()
        .expect("run npmenc");
    assert!(
        run_output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&run_output.stderr)
    );

    let captured = fs::read_to_string(&capture).expect("capture");
    assert!(captured.contains("company=company_token"));
    assert!(captured.contains("color=true\n"));
    assert!(captured
        .contains("//artifactory.example.com/api/npm/npm/:_authToken=${NPM_TOKEN_MYCOMPANY}\n"));
}
