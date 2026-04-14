# `npmenc`

`npmenc` and `npxenc` are direct-launch wrappers for `npm` and `npx` that adapt tools which
expect credentials to live on disk.

They keep ordinary wrapped execution ephemeral, support an explicit `install` / `uninstall`
lifecycle for persistent `.npmrc` conversion, and incubate a reusable application-adaptation
library (`enclaveapp-app-adapter`) inside this repo before that abstraction is promoted back into
`libenclaveapp`.

## What This Repo Contains

This workspace has four crates:

- `enclaveapp-app-adapter`
  - generic executable resolution, direct launch, temp-config handling, binding storage, and
    encrypted secret storage
- `npmenc-core`
  - npm-specific `.npmrc` parsing, token-source policy, wrapper preparation, install, and
    uninstall
- `npmenc`
  - CLI wrapper for `npm`
- `npxenc`
  - CLI wrapper for `npx`

## Security Model

The main security properties are:

- the final `npm` / `npx` process is always direct-launched by the wrapper
- the shell may be used as a resolution oracle, but never as the secret-bearing launcher
- temp config files for wrapped execution contain placeholders like `${NPM_TOKEN_DEFAULT}`, not
  raw secrets
- secrets are stored encrypted at rest
- `token list` shows metadata only
- there is no `token get`
- ambiguous or corrupted managed state fails fast instead of being heuristically reinterpreted

## Current Command Surface

Both `npmenc` and `npxenc` expose the same management commands against the same state:

- `install`
- `uninstall`
- `token set`
- `token add`
- `token list`
- `token delete`
- `registry add`
- `registry set-default`
- `registry list`
- `registry remove`

Wrapper flags:

- `--userconfig`
- `--shell`
- `--resolve-mode auto|path-only|command-v`
- `--npm-bin` / `--npx-bin`
- `--dry-run`
- `--print-effective-config`
- `--strict`
- `--allow-unscoped-auth`
- `--auto-install`

## Build

Requirements:

- Rust 1.75+
- access to the sibling `../crates/enclaveapp-app-storage` crate from `libenclaveapp`

Build everything:

```bash
cargo build
```

Run tests and linting:

```bash
cargo test
cargo clippy --workspace --all-targets
```

## Quick Start

Store a default npm registry token as managed state:

```bash
cargo run -p npmenc -- token set --secret 'npm_...'
```

Wrap an `npm` invocation:

```bash
cargo run -p npmenc -- -- install
```

Wrap an `npx` invocation:

```bash
cargo run -p npxenc -- -- cowsay hello
```

Inspect the effective rewritten config without launching:

```bash
cargo run -p npmenc -- --dry-run -- --version
```

## Managing Bindings

Default registry binding:

```bash
npmenc token set --secret 'npm_...'
```

Custom registry binding:

```bash
npmenc registry add \
  --label mycompany \
  --url https://artifactory.example.com/api/npm/npm/ \
  --secret 'eyJ...'
```

List metadata:

```bash
npmenc token list
```

`token list` and `registry list` validate token-source state against persisted sidecars. Corrupt
managed token-source state is reported as an error instead of being shown as healthy metadata.

Delete a binding that is not currently installed into any config:

```bash
npmenc token delete --label mycompany
```

Important invariants:

- `default` is reserved for `https://registry.npmjs.org/`
- only one binding may target a normalized registry auth key
- installed bindings cannot be deleted until they are uninstalled from every attached config

## Token Sources

There are two token-source classes:

- command sources
- provider sources

Preferred CLI forms:

```bash
npmenc token set --token-command 'source-token --audience npm'
npmenc token set --token-provider sso-jwt
npmenc token set --token-provider sso-jwt --token-handle corp/prod
```

Raw `--token-source` is still supported for explicit or otherwise unambiguous forms:

```bash
npmenc token set --token-source 'command:source-token --audience npm'
npmenc token set --token-source 'provider:sso-jwt:corp/prod'
npmenc token set --token-source '/opt/bin/source-token'
```

Ambiguous bare one-token values are intentionally rejected:

```bash
# rejected
npmenc token set --token-source sso-jwt
```

Why: bare one-token specs were historically ambiguous between command and provider semantics.
The CLI now forces that distinction to be explicit.

### Provider support

Built-in provider:

- `sso-jwt`

Generic provider helpers are also supported through the generic provider runtime. Those helpers are
invoked with:

- `NPMENC_TOKEN_PROVIDER_PROTOCOL=v1`
- `NPMENC_TOKEN_PROVIDER_REQUEST_JSON=<json>`

The request JSON contains `provider` and `handle`.

### Metadata-only providers

If a provider cannot directly reacquire a token in the current environment, you can still store it
as metadata together with an explicit secret:

```bash
npmenc token set \
  --secret 'stored_token' \
  --token-source 'provider:corp-provider:prod'
```

## Wrapped Execution

Ordinary wrapped execution does **not** rewrite your real `.npmrc`.

Instead, `npmenc` / `npxenc`:

1. resolve the effective `.npmrc`
2. parse auth entries
3. build an effective config
4. prepare the least-secret-exposing launch plan
5. inject env vars and launch the real target directly

Observed wrapper modes:

- `Passthrough`
- `ManagedBindings`
- `TransientFallback`

`TransientFallback` means raw token material was discovered in `.npmrc` and used for this
invocation even though managed install state is not yet in place.

## Install / Uninstall

`install` intentionally rewrites the persistent effective `.npmrc` into managed placeholder form.

Typical install behavior:

- import scoped `:_authToken` lines
- optionally import unscoped `_authToken` with `--allow-unscoped-auth`
- leave unsupported legacy auth forms unchanged with warnings
- record per-config provenance for later uninstall

Example:

```bash
npmenc --userconfig ~/.npmrc install
```

`uninstall` restores away from placeholder-managed config:

- source-origin managed entries are materialized back into `.npmrc`
- appended managed auth lines are removed
- `uninstall` purges managed bindings and secrets by default
- `uninstall --keep-secrets` removes config integration but keeps the managed secret state

Examples:

```bash
npmenc --userconfig ~/.npmrc uninstall
npmenc --userconfig ~/.npmrc uninstall --keep-secrets
```

## Strictness and Diagnostics

`--strict` turns warnings about unsupported or unsafe auth state into failures.

Current policy highlights:

- registry-scoped `:_authToken` is the primary supported auth form
- legacy auth forms like `_auth`, `_password`, and `username` are diagnosed but not migrated
- managed placeholder state without matching managed storage is treated as invalid / corrupt state
- old ambiguous legacy token-source state is treated as corruption and must be repaired explicitly

## Read-Only Inspection

Inspection commands are read-only:

- `--dry-run`
- `--print-effective-config`

They do not:

- acquire secrets
- initialize the encrypted secret backend
- create managed state as a side effect

If the managed state is dirty or inconsistent, inspection fails instead of guessing through it.

## State Directory

State is stored under the app name `npmenc`.

Default:

- platform config dir, usually `~/.config/npmenc`

Override for testing or isolation:

```bash
export NPMENC_CONFIG_DIR=/tmp/npmenc-dev
```

Primary files:

- `bindings.json`
- `secrets/`
- `state.lock`
- `state.version`

## Development Notes

This repo deliberately incubates the reusable adapter layer locally first. The intended next
architectural step is to promote `enclaveapp-app-adapter` back into `libenclaveapp` once the
abstraction is considered stable across more consumers.

For the detailed current implementation design, see [DESIGN.md](./DESIGN.md).
