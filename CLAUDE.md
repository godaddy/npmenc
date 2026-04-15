# CLAUDE.md

## Project Overview

`npmenc` and `npxenc` are [**Type 2 (EnvInterpolation)**](https://github.com/godaddy/libenclaveapp/blob/main/DESIGN.md#type-2-envinterpolation) enclave apps that secure npm registry authentication tokens. They wrap the `npm` and `npx` commands, replacing plaintext tokens in `.npmrc` with `${ENV_VAR}` placeholders and injecting decrypted tokens as environment variables at execution time via `execve()`.

## Integration Type

[Type 2 (EnvInterpolation)](https://github.com/godaddy/libenclaveapp/blob/main/DESIGN.md#type-2-envinterpolation) — npm supports `${ENV_VAR}` interpolation in `.npmrc` files. npmenc rewrites `.npmrc` to use placeholders like `${NPM_TOKEN_DEFAULT}` and sets these env vars when launching npm/npx. Secrets never touch disk in plaintext. See [libenclaveapp DESIGN.md](https://github.com/godaddy/libenclaveapp/blob/main/DESIGN.md#application-integration-types) for the full integration type taxonomy.

## Build & Development

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

## Architecture

Rust workspace with 4 crates:
- **npmenc** — CLI binary wrapping `npm`
- **npxenc** — CLI binary wrapping `npx`
- **npmenc-core** — Shared npm-specific logic (`.npmrc` parsing, registry bindings, token source management, install/uninstall lifecycle)
- Uses **enclaveapp-app-adapter** from libenclaveapp for generic secret delivery (BindingStore, SecretStore, program resolution, process launch)
- Uses **enclaveapp-app-storage** from libenclaveapp for hardware-backed encryption

## Commits

Do not add Co-Authored-By lines for Claude Code in commit messages.
