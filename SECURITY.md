# Security Policy

## Reporting Vulnerabilities

If you discover a security vulnerability in npmenc, report it privately.

**Do not open a public GitHub issue for security vulnerabilities.**

Email: Report via GitHub's private vulnerability reporting feature on the
[npmenc repository](https://github.com/godaddy/npmenc/security/advisories/new),
or contact the maintainer directly.

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if you have one)

You will receive an acknowledgment within 72 hours. A fix will be developed
and released as quickly as possible, with credit given to the reporter
(unless anonymity is requested).

## Supported Versions

| Version | Supported |
|---|---|
| 0.1.x | Yes |

Only the latest release receives security fixes.

## Security Model Summary

`npmenc` / `npxenc` are [Type 2 (EnvInterpolation)](https://github.com/godaddy/libenclaveapp/blob/main/DESIGN.md#type-2-envinterpolation)
wrappers around `npm` and `npx`. Registry auth tokens are encrypted at
rest under a hardware-bound P-256 key; at run time, `.npmrc` placeholders
are resolved to `${NPM_TOKEN_*}` env vars that are passed to the real
npm binary via `execve()`.

- **Hardware-backed encryption at rest.** Tokens are ECIES-encrypted
  under a Secure Enclave (macOS), TPM 2.0 (Windows / Linux), or
  keyring-wrapped software key. The private key never leaves the
  hardware on SE / TPM backends.
- **No plaintext tokens on disk after install.** `.npmrc` contains only
  `${NPM_TOKEN_*}` placeholders; the encrypted token lives in
  `$NPMENC_CONFIG_DIR/secrets/<sha256>`.
- **Atomic rewrites.** `.npmrc` rewrites go through tmp-then-rename with
  preserved mode bits (`npmenc-core::atomic_write`). A crash or power
  loss cannot leave a partially-written config.
- **Direct exec, no shell.** npm / npx are launched via
  `Command::new(path).env(...)`, never via `sh -c`.
- **In-memory secret hygiene.** The launcher `mlock`s env-var bytes and
  zeroizes them after the child exits (`enclaveapp-app-adapter`).
- **Core dumps disabled.** `harden_process()` sets `RLIMIT_CORE = 0` for
  the npmenc process.
- **Type-2-limit fundamental risks are documented**, not mitigated. See
  `THREAT_MODEL.md`.

### What npmenc does NOT protect against

- **Malicious npm lifecycle scripts.** `npm install` runs arbitrary JS
  from every transitive dep with the token in its environment. This is
  the single biggest risk when using npm with any authentication
  mechanism, and is outside npmenc's control. Users should prefer
  granular / short-lived publish tokens and `--ignore-scripts` on
  untrusted trees.
- Same-UID processes reading `/proc/<npm-pid>/environ`.
- npm's own telemetry / crash reports that include env vars.
- Root / kernel compromise.
- Physical attacks on the Secure Enclave or TPM hardware.
- On macOS, same-UID theft of the Secure Enclave `.handle` file while
  Keychain-backed wrapping is still a planned hardening (see
  [libenclaveapp/fix-macos.md](https://github.com/godaddy/libenclaveapp/blob/main/fix-macos.md)).

See [THREAT_MODEL.md](THREAT_MODEL.md) for detailed analysis and
[libenclaveapp/THREAT_MODEL.md](https://github.com/godaddy/libenclaveapp/blob/main/THREAT_MODEL.md)
for the shared foundation.

## Dependencies

npmenc uses a conservative set of dependencies. Key external crates:

- `enclaveapp-*`: Shared hardware-backed key management (libenclaveapp)
- `anyhow`, `clap`: Error handling and CLI
- `serde`, `serde_json`, `toml`: Serialization
- `sha2`: Hashing for secret-file naming
- `shlex`: Safe shell-word tokenization for token-source helpers
- `fs4`: File locking for state coordination
- `tempfile`: Atomic file writes (named-temp-file + persist)

All dependencies are published on crates.io and are widely used in the
Rust ecosystem.
