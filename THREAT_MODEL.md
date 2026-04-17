# Threat Model: npmenc / npxenc

## Scope

`npmenc` (and its sibling `npxenc`) is a
[Type 2 (EnvInterpolation)](https://github.com/godaddy/libenclaveapp/blob/main/DESIGN.md#type-2-envinterpolation)
wrapper around `npm` and `npx`. Registry auth tokens are encrypted at rest
under a hardware-bound P-256 key (Secure Enclave / TPM 2.0 / keyring
fallback). At run time the wrapper rewrites `.npmrc` so registry-auth
entries are `${NPM_TOKEN_*}` placeholders, decrypts the bindings in
memory, and `execve()`s the real `npm` / `npx` binary with the decrypted
values in its environment.

This document names what npmenc does and does not defend against in that
delivery model. Foundational threats shared with other libenclaveapp
consumers are documented in
[libenclaveapp/THREAT_MODEL.md](https://github.com/godaddy/libenclaveapp/blob/main/THREAT_MODEL.md);
this file focuses on the npm-specific layer.

## Assets

| Asset | Where it lives | Sensitivity |
|---|---|---|
| Registry auth token (ciphertext) | `$NPMENC_CONFIG_DIR/secrets/<sha256>`, ECIES under hardware key | Medium — useless without the hardware key |
| Registry auth token (in env) | `execve()`'d `npm` process's environment; `/proc/<pid>/environ` | **High — readable by same-UID processes for npm's full lifetime** |
| `.npmrc` | Managed form after install uses `${NPM_TOKEN_*}` placeholders; no plaintext tokens | Medium — reveals registry names |
| `bindings.json` | Non-secret metadata (auth keys, labels, registry URLs, provenance) | Low |
| Hardware P-256 private key | Secure Enclave / TPM / keyring | Critical — same as all libenclaveapp apps |

## Trust boundaries

| Boundary | Trusted side | Untrusted side |
|---|---|---|
| Hardware key | SE / TPM chip | Everything else |
| Encrypted secret file | Ciphertext bytes on disk (opaque) | Same-user processes that can read the ciphertext |
| Decrypted token in npmenc's RAM | npmenc process (mlock + zeroize around spawn) | Processes that can `ptrace` / read `/proc/<npmenc-pid>/mem` |
| `execve()` to npm | npmenc | **npm and every descendant process (lifecycle scripts, node-gyp, helper children)** |
| `.npmrc` on disk | Owning user | Anyone who can read the file (only placeholders after install) |
| Token-source helper subprocess | The helper | npmenc receives its stdout |

## What npmenc protects

With a hardware backend:

- **The encrypted token file is useless on another machine.** ECIES
  ciphertext is bound to the SE/TPM on the machine that created the key.
- **Plaintext never touches disk.** `.npmrc` contains only placeholders
  after install; the decrypted value lives only in the launcher's memory
  and in the child `npm` process's environment.
- **State transitions are atomic.** `.npmrc` rewrites and bindings-store
  mutations go through tmp-then-rename (`npmenc-core/src/atomic_write.rs`
  for `.npmrc`, `enclaveapp-app-adapter` for bindings). A power loss or
  crash mid-operation leaves either the old file or the new file, never
  a partial mix, and original mode bits on `.npmrc` are preserved.
- **Direct exec, no shell.** The target `npm` / `npx` binary is launched
  via `Command::new(path).env(...)` — no `sh -c`, no shell history, no
  env-value splitting into argv.
- **Secret lifecycle is bounded in npmenc's process.** The launcher
  `mlock`s env-var bytes and zeroizes them after the child exits.

## What npmenc cannot protect (Type 2 fundamentals)

Once `execve()` hands `NPM_TOKEN_*` to npm, the following threats apply
until that child and all its descendants exit. **These are inherent to
Type 2 delivery and cannot be fixed inside npmenc.** They are the
operator's responsibility.

### Threat: Malicious npm lifecycle script exfiltrates the token

`npm install` runs `preinstall`, `install`, and `postinstall` scripts for
every transitive dependency. These scripts inherit the `npm` process's
environment — including `NPM_TOKEN_*`. A malicious dep (typosquat,
compromised maintainer, or a dep of a dep) can read
`process.env.NPM_TOKEN_*` and exfiltrate the token.

**This is the single largest threat specific to npm as a Type 2 target.**

**Mitigations** (user-side; npmenc cannot enforce them):

- Prefer granular / short-lived npm automation tokens scoped to publish
  rights for specific packages, not long-lived global tokens.
- Use `npm install --ignore-scripts` in untrusted trees, or use lock-file-
  driven `npm ci` with known-good trees only.
- Rotate tokens promptly when exposure is suspected.

### Threat: Same-UID reader of `/proc/<npm-PID>/environ`

Any process the user runs while `npm install` is live can read
`/proc/<npm-pid>/environ` and learn the current `NPM_TOKEN_*` values.
`npm install` can take minutes; the window is large.

**Mitigations:** none possible at the npmenc layer. `mlock` + zeroize
apply to the npmenc process's copy, not npm's copy.

### Threat: Core dump / swap of the npm process

npmenc calls `harden_process()` to disable core dumps of itself, but the
target `npm` process is a separate PID. npmenc does not set rlimits on
the target. A system-wide coredump policy can still capture `npm`'s env.

**Mitigations:** operator-level `sysctl kernel.core_pattern=` or
`ulimit -c 0` in the user's shell environment.

### Threat: npm's own logging / telemetry leaks the token

npm can log, send telemetry, or persist crash reports that include env
vars. Any such leak is outside npmenc's control.

**Mitigations:** disable npm telemetry / crash reporting at the npm
config level; treat the token as compromised if npm logs full env on
error.

## npmenc-specific threats (non-fundamental)

### Threat: Rollback of `.npmrc` to plaintext

After `npmenc install`, the user's VCS / backup system may still contain
a pre-install `.npmrc` with raw tokens. Restoring from backup or
reverting a commit resurrects plaintext tokens in the working tree.

**Mitigations:** user-side hygiene. Operators who backed up a plaintext
`.npmrc` should rotate the stashed token after running `npmenc install`.

### Threat: Partial `.npmrc` rewrite on crash

`.npmrc` rewrites in `npmenc-core/src/install.rs` and `uninstall.rs` now
use `atomic_write_preserving_mode` — tmp-then-rename with preserved mode
bits. A crash or power loss during rewrite cannot leave a half-stripped
file on disk.

**Residual risk:** the tmp file in the `.npmrc`'s parent directory lives
briefly (typically milliseconds) during the write. Named with
`tempfile::NamedTempFile` randomization so collisions are not a concern.

### Threat: Concurrent `npm config set` racing `npmenc install`

`npm` itself can rewrite `.npmrc` while `npmenc install` is running. The
state lock (`npmenc-core/src/state_lock.rs`) coordinates npmenc vs.
npmenc, not npmenc vs. npm.

**Residual risk:** last writer wins on `.npmrc`; users should avoid
running `npm config` commands concurrently with `npmenc install` /
`uninstall`. Outcome is data loss at worst, not a security issue.

### Threat: `auth_key_to_registry_url` reconstructs every URL as `https://`

`.npmrc` auth keys start with `//` and carry no scheme
(`//registry.npmjs.org/:_authToken=...`). The URL reconstructor in
`npmenc-core/src/registry_bindings.rs` hardcodes `https://`. A user with
an internal `http://` registry will see a wrong reconstructed URL if
they use the auth-key-only code path.

**Mitigations:** documented in-source as deliberate secure-by-default;
callers are steered toward `RegistryBinding::registry_url`, which
preserves the scheme supplied at registration.

**Residual risk:** low; wrong URL typically manifests as a connect
failure against an internal HTTP registry, not a token leak.

### Threat: `NPM_TOKEN_*` injection when it is not needed

Every `npmenc <cmd>` invocation injects `NPM_TOKEN_*` into the target
process's environment by default. Most npm subcommands (`install`,
`ci`, `run-script`, `publish`) do need the token, but many (`version`,
`init`, local-only scripts) do not.

**Mitigation: `npmenc --publish-only`.** When this flag is set, npmenc
strips `NPM_TOKEN*` from the child env unless the subcommand is in a
known registry-auth list (`publish`, `unpublish`, `deprecate`,
`access`, `owner`, `team`, `dist-tag`, `whoami`, `profile`, `token`,
`hook`, `org`, `adduser`, `login`, `signup`, `logout`, `star`). This
materially reduces the lifecycle-script exposure window on `install`
and `ci` runs — at the cost of breaking private-registry reads. The
flag is opt-in and never default; users who read from private
registries should leave it off.

The subcommand detection uses a known-vocabulary scanner: unknown args
are treated as flag values and skipped until a recognized subcommand
is found. A value that happens to collide with a subcommand name (e.g.
`--loglevel info`) is an edge case — use `--flag=value` form or omit
`--publish-only` for such invocations. Unrecognized subcommands fall
back to "needs auth" to avoid silently breaking user workflows.

`npxenc` always injects — npx invokes package code whose registry-auth
needs cannot be predicted.

**Residual risk (without `--publish-only`):** full env injection for
every subcommand is the default. Users who accept the private-registry
tradeoff should set `--publish-only`; otherwise the Type-2
lifecycle-script risk applies in full.

### Threat: Token-source subprocess hang

`npmenc` can fetch tokens from external helpers (sso-jwt, gh CLI, custom
scripts) via `token_source`. A wedged helper would hang the `npmenc`
process indefinitely.

**Mitigations:** the token-source subprocess acquisition enforces a
30-second timeout (`npmenc-core/src/token_source.rs`) using a reader
thread plus `mpsc::recv_timeout`, matching the sso-jwt `gh` pattern.

**Residual risk:** a cooperating-but-slow helper can still block up to
the timeout. Legitimate interactive helpers that need to prompt the
user must complete within 30 seconds.

### Threat: `<redacted>` sentinel collision

`enclaveapp-app-adapter::secret_store` returns the literal string
`"<redacted>"` from read-only stores (the `REDACTED_PLACEHOLDER`
constant). If a real npm token were literally the string `<redacted>` a
consumer comparing against `REDACTED_PLACEHOLDER` would be confused.
npm tokens start with `npm_` by convention so the collision is
theoretical.

**Residual risk:** negligible for npm. Documented upstream.

### Threat: Binary planting on `npm` / `npx` resolution

npmenc resolves the real `npm` / `npx` binary via the adapter's program
resolver. Default mode (`auto`) consults `command -v` in the user's
login shell; `path-only` and an explicit `--npm-bin` flag are available
escape hatches. PATH-inserted lookalikes (or shims installed by asdf /
volta / Volta-style wrappers) are followed.

**Mitigations:** `--npm-bin=/absolute/path/to/npm` is the hardened
mode. Alias / function resolution has an 8-deep recursion cap.

**Residual risk:** default mode trusts whatever the user's shell
resolves. PATH-hijack is a user-side compromise that defeats many
defenses at once.

### Threat: `.handle` plaintext on macOS

Inherited from libenclaveapp: the macOS Secure Enclave `.handle` file
is currently plaintext on disk (0600). Keychain-wrapped AES-GCM is a
planned hardening (`libenclaveapp/fix-macos.md`). Same-UID handle theft
is possible on macOS until that lands — an attacker who copies the
handle can replay SE signing on that user's device, defeating npmenc's
"token on another host is useless" guarantee at the local level.

### Threat: Multi-user machines

`npmenc` config paths are per-user (`dirs::config_dir()`-based). File
permissions (0700 dir, 0600 files) block user B from reading user A's
ciphertext.

**Residual risk:** on Windows, `set_dir_permissions` /
`set_file_permissions` in the adapter are no-ops; file ACLs are
inherited from the parent directory. On a well-configured per-user
profile this matches the OS-expected security, but it is not
defense-in-depth against an attacker who has already stolen the user's
Windows credentials.

### Threat: WSL bridge

Same as libenclaveapp — the bridge binary is discovered by a fixed-path
list under `/mnt/c/Program Files/npmenc/`, with a `which` fallback that
accepts any user-writable directory earlier on `$PATH`. PE signature
validation is a tracked hardening gap. See the
[libenclaveapp threat model](https://github.com/godaddy/libenclaveapp/blob/main/THREAT_MODEL.md)
for details.

## Top residual risks (cannot be fixed inside npmenc)

Ranked by realistic impact on an npm user today:

1. **Malicious dependency lifecycle script exfiltrates `NPM_TOKEN_*`.**
   `npm install` runs untrusted JavaScript with the token in the
   environment. No defense possible at the npmenc layer.
2. **Same-UID process reads `/proc/<npm-PID>/environ`.** Any concurrently
   running same-user process sees the token for npm's full lifetime.
3. **npm itself leaks the token** through telemetry, crash dumps, or
   verbose logging modes the user opts into.
4. **`.handle` plaintext on macOS** until `fix-macos.md` lands —
   same-UID handle theft allows local SE replay.
5. **Token replay** within the npm automation token's validity window —
   rotate suspect tokens, prefer short-lived granular tokens.

## Out of scope

- Physical attacks on SE / TPM hardware.
- Kernel / hypervisor exploits.
- Server-side issues at the npm registry.
- Supply chain attacks on npmenc's own Rust dependencies (deferred to
  [libenclaveapp/THREAT_MODEL.md](https://github.com/godaddy/libenclaveapp/blob/main/THREAT_MODEL.md)).
- Denial of service — an attacker who can delete the config or secret
  files can force re-authentication but cannot recover the token.
