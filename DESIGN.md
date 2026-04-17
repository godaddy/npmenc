# Design: `npmenc`

**Status:** Implemented design and current behavior  
**Updated:** 2026-04-14

## Overview

`npmenc` and `npxenc` are direct-launch wrappers for `npm` and `npx` that adapt tools which
expect credentials to live on disk.

This repository layers on top of the reusable adapter library in `libenclaveapp`:

- `enclaveapp-app-adapter` (in `libenclaveapp`): generic application-adaptation substrate
- `npmenc-core`: npm-specific `.npmrc` parsing, install/uninstall, and wrapper policy
- `npmenc`: thin CLI for `npm`
- `npxenc`: thin CLI for `npx`

The adapter was incubated in this repo and has since been promoted into `libenclaveapp`.

## Goals

The implemented design has these core goals:

1. Never launch the secret-bearing target through a shell.
2. Preserve the user's effective `npm` / `npx` resolution behavior as closely as possible.
3. Prefer lower secret exposure:
   - helper/plugin integration
   - environment interpolation
   - temporary materialized config only as a last resort
4. Keep ordinary wrapped execution ephemeral.
5. Make `install` / `uninstall` explicit lifecycle transitions for persistent `.npmrc` changes.
6. Treat managed-state corruption as a real error, not a heuristic fallback case.

## Application Classes

`enclaveapp-app-adapter` models three integration classes:

1. `HelperTool`
   - the target application supports an auth helper or plugin command
2. `EnvInterpolation`
   - the target application supports environment-variable interpolation in config
3. `TempMaterializedConfig`
   - the target application requires secrets materialized into a temporary config file

`npm` and `npx` are `EnvInterpolation` applications. Their rewritten temp config should contain
placeholders like `${NPM_TOKEN_DEFAULT}`, not raw token material.

## Workspace Layout

Current workspace crates (all npm-specific; the shared adapter substrate lives
upstream in `libenclaveapp/crates/enclaveapp-app-adapter`):

- `npmenc-core`
  - `.npmrc` parsing and rewrite rules
  - install / uninstall lifecycle
  - wrapper preparation
  - token-source policy
  - global state coordination
- `npmenc`
  - `npm` wrapper CLI
- `npxenc`
  - `npx` wrapper CLI

## State Layout

Managed state lives under the application config directory for app name `npmenc`.

Default location:

- `$XDG_CONFIG_HOME/npmenc` when available
- otherwise the platform config dir returned by `dirs::config_dir()`

Test / override location:

- `NPMENC_CONFIG_DIR`

On disk, the main state is:

- `bindings.json`
- `secrets/`
- `state.lock`
- `state.version`

`bindings.json` stores binding metadata. Secrets and token-source sidecars are encrypted files in
`secrets/`.

## Binding Model

Each binding has:

- a stable binding id
- a user-facing label
- a registry URL target
- a normalized auth key
- a secret env var name
- metadata

Important invariants:

- the `default` label is reserved for `https://registry.npmjs.org/`
- only one binding may exist for a normalized auth key
- installed bindings cannot be deleted while still attached to any config provenance

## Wrapper Execution Model

Normal wrapper execution does **not** rewrite the user's real `.npmrc`.

The implemented flow is:

1. Resolve the effective `.npmrc` path.
2. Parse auth entries and diagnostics from the source file.
3. Resolve the target executable directly.
4. Build the effective config contents.
5. Prepare the least-secret-exposing launch plan through `enclaveapp-app-adapter`.
6. Launch the target directly.

The final target process is always direct-exec launched by the wrapper. The shell may be used only
as a resolution oracle.

### Wrapper Modes

`npmenc-core` exposes three observed wrapper modes:

- `Passthrough`
  - no managed bindings are active
- `ManagedBindings`
  - managed secrets are being injected
- `TransientFallback`
  - raw `.npmrc` token material was used transiently because install has not happened yet

### Resolution

Supported resolution modes:

- `auto`
  - shell-assisted resolution first, then PATH fallback as needed
- `path-only`
  - current-process PATH only
- `command-v`
  - explicit shell resolution query

Resolution supports:

- explicit binary override
- PATH lookup
- shell `command -v`
- simple alias / function / wrapper-chain reduction
- direct execution of the resolved program plus fixed wrapper args

The final target is never run as `$SHELL -c ...`.

## `.npmrc` Handling

### Effective config path

Resolution order:

1. `--userconfig`
2. `NPM_CONFIG_USERCONFIG`
3. `$HOME/.npmrc`

Missing config files are treated as empty.

### Supported auth forms

Primary supported auth form:

- registry-scoped `:_authToken`

Diagnosed but not automatically migrated:

- `_auth`
- `_password`
- `username`
- related legacy auth shapes

Unscoped `_authToken` is supported with explicit policy:

- managed unscoped placeholder state is recognized always
- raw unscoped secret migration is gated by `--allow-unscoped-auth`
- `--strict` can fail on unsupported auth forms

### Rewrite rules

Registry-scoped auth lines are rewritten to placeholders mapped from bindings:

- `//registry.npmjs.org/:_authToken=${NPM_TOKEN_DEFAULT}`
- `//artifactory.example.com/api/npm/npm/:_authToken=${NPM_TOKEN_MYCOMPANY}`

If a managed binding exists but the config has no corresponding auth line, the wrapper or install
path may append the minimal scoped auth entry.

The parser is line-oriented and preserves unrelated settings and comments as much as practical.

### Atomic rewrite

All `.npmrc` rewrites go through `npmenc_core::atomic_write::atomic_write_preserving_mode`:
a temp file is written alongside the target in the same directory, then
`rename`d into place. On Unix the original file mode is read with
`symlink_metadata()` before the rewrite and restored on the replacement so
user-applied `chmod 600` persists. This closes the observable-partial-write
window described in THREAT_MODEL.md.

### Placeholder rules

Managed placeholder state is treated as first-class managed state, not as raw input to be imported
again.

Placeholder-only config with missing matching managed state is treated as corruption or invalid
state, not a silent passthrough case.

## Install Lifecycle

`install` intentionally rewrites the persistent effective `.npmrc`.

Implemented behavior:

1. Resolve the effective config file.
2. Scan scoped and optionally unscoped auth tokens.
3. Import raw token material into managed encrypted storage.
4. Reuse or activate existing bindings where possible.
5. Record per-config install provenance.
6. Rewrite the persistent config into managed placeholder form.

### Install provenance

Per-config provenance records:

- whether the line came from source config or was appended
- whether it was installed from `.npmrc`
- original line kind, for example:
  - `scoped_authToken`
  - `unscoped_authToken`

Provenance is tracked per config path, not as a single sticky install flag.

### Install properties

`install` is intended to be idempotent.

It does not:

- duplicate existing bindings
- duplicate existing auth-key mappings
- rewrite placeholder-managed entries into new unrelated state

It does:

- import raw scoped tokens
- optionally import raw unscoped `_authToken`
- activate existing stored bindings into config
- leave unsupported legacy auth entries unchanged with warnings

## Uninstall Lifecycle

`uninstall` restores the config away from wrapper-managed placeholder form.

Current semantics:

- source-origin managed bindings are restored to materialized auth
- appended managed lines are removed, not materialized back
- `uninstall` purges managed bindings and secrets by default
- `uninstall --keep-secrets` removes config integration but preserves managed secret state

The uninstall engine now uses explicit uninstall actions:

- `RestoreMaterialized`
- `RemoveManagedLine`
- `None`

This avoids requiring secrets for cases where uninstall only needs to delete an appended managed
line.

## Token-Source Model

The token-source subsystem was refactored into a strict model so wrapper, install, uninstall, and
inspection all use the same interpretation.

### Supported source kinds

1. Command source
   - direct-exec command plan
2. Provider source
   - provider name plus optional handle, optionally upgraded to a prepared adapter state

### Stored state

A managed binding can have:

- safe metadata on the binding record
- encrypted token-source sidecar state
- a prepared marker

Prepared state is durable and is what removes PATH drift after first successful command or
provider preparation.

### CLI contract

Preferred CLI forms:

- `--token-command ...`
- `--token-provider ...`
- `--token-handle ...`

Raw `--token-source` is still supported, but only for explicit or unambiguous forms:

- `command:...`
- `provider:...`
- path-like command specs
- multi-token command specs

Ambiguous bare one-token `--token-source` values are rejected. Example:

- rejected: `--token-source sso-jwt`
- accepted: `--token-provider sso-jwt`
- accepted: `--token-source provider:sso-jwt`
- accepted: `--token-command source-token`

### Legacy handling

Legacy token-source state is intentionally strict now:

- ambiguous bare legacy specs are corruption
- legacy prepared raw command state must be canonical direct-exec form
- missing or mismatched modern metadata / sidecar state is corruption

This is deliberate. Old ambiguous state now fails fast instead of changing meaning across machines
or over time.

### Token-source display

List output shows safe metadata only:

- command sources render as `command:<name>#<handle>`
- provider sources render as provider names

Raw argv, handles, and secrets are not displayed.

List/reporting paths validate token-source state against persisted sidecars. They do not treat
binding metadata alone as authoritative when managed token-source state exists.

## Provider Runtime

The provider path now uses a registry-style runtime adapter layer.

Implemented provider behavior:

- built-in provider adapter: `sso-jwt`
- generic provider adapter:
  - helper binary configured by provider-specific env override
  - request delivered through a versioned environment protocol

### Generic provider request protocol

Generic provider helpers receive:

- `NPMENC_TOKEN_PROVIDER_PROTOCOL=v1`
- `NPMENC_TOKEN_PROVIDER_REQUEST_JSON=<json>`

The JSON request contains:

- `provider`
- `handle`

Generic provider binary override env vars are collision-resistant and hash-suffixed, not simple
sanitized names.

## Inspection Semantics

Inspection commands are:

- `--dry-run`
- `--print-effective-config`

These are implemented as read-only operations:

- no secret acquisition
- no encrypted secret backend initialization
- no managed-dir creation as a side effect

Read-only inspection refuses clearly inconsistent global managed state rather than silently reading
through it.

## Global State Coordination

Managed-state writes are coordinated through a global lock and state-version protocol.

Important properties:

- stateful operations are serialized
- panics mark state dirty rather than leaving a stale mutating marker
- read-only inspection rejects dirty or mutating state
- stale mutating markers are recovered into dirty state when possible

This lock sits above per-file binding/secret locking and exists to coordinate cross-store
operations transactionally.

## Security Properties

Implemented security boundaries:

- final target process is direct-launched
- wrapper temp config for npm/npx contains placeholders, not raw tokens
- raw token material is stored encrypted at rest
- `token list` shows metadata only
- there is no `token get`
- legacy or corrupted managed state is surfaced as an error instead of guessed through heuristics

## CLI Surface

Both binaries expose the same management surface against the same shared state:

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
- `--resolve-mode`
- `--npm-bin` / `--npx-bin`
- `--dry-run`
- `--print-effective-config`
- `--strict`
- `--allow-unscoped-auth`
- `--auto-install`
- `--publish-only`

`npxenc` shares the same state directory and binding set as `npmenc`.

### `--publish-only`

When set, `npmenc` narrows the set of `NPM_TOKEN_*` environment variables
injected into the child process to the subcommands that actually need registry
authentication (e.g. `publish`, `unpublish`, `access`, `owner`, `token`,
`deprecate`, `adduser`, `whoami`, `profile`, `hook`, `org`). Subcommands on the
non-auth allowlist (e.g. `run`, `install`, `ci`, `test`, `view`, `search`,
`init`) run with the `NPM_TOKEN_*` variables stripped from the child env. This
limits token exposure for day-to-day invocations that do not need credentials.

Implementation: `npmenc_core::cli_common::subcommand_needs_registry_auth`
classifies the subcommand; `strip_token_env_overrides` removes the variables
for subcommands that do not need them.

## Current Implementation Status

Implemented in this repository:

- npm-specific core crate built on `enclaveapp-app-adapter` (upstream)
- separate `npmenc` and `npxenc` binaries
- encrypted secret storage
- managed binding metadata
- transient fallback wrapper execution
- install / uninstall lifecycle
- read-only inspection
- strict legacy-state corruption handling
- provider and command token-source handling
- adapter-level support for helper / env / temp-config integration classes
- atomic `.npmrc` rewrites preserving Unix mode
- `--publish-only` subcommand-scoped token exposure

