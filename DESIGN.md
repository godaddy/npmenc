# Design: `npmenc`

**Status:** Draft  
**Updated:** 2026-04-13

This document describes `npmenc` and `npxenc` as the first consumers of a reusable
application-adaptation library for tools that are not designed to obtain credentials
from a secure external helper.

The important refinement relative to earlier drafts is that `npmenc` and `npxenc` do
not need to be the same binary, and their shared behavior should live in a reusable
library rather than being embedded directly in one npm-specific implementation.

That library will be built inside `npmenc` first. Once the abstraction is proven and
the API stabilizes, it can be promoted into `libenclaveapp` for reuse by other projects.

⸻

Architecture direction

The implementation should be split into three layers:
	•	a reusable wrapper/adaptation library built inside the `npmenc` project first,
	•	an npm-specific core layer that understands `.npmrc`,
	•	two thin binaries, `npmenc` and `npxenc`, that differ only in target command kind and help text.

The reusable library exists to support a broader class of libenclaveapp-backed tools that
must adapt applications with poor native credential-integration support.

The intended lifecycle is:
	•	incubate the adapter library locally inside `npmenc`,
	•	refine the abstraction based on the npm and npx implementation,
	•	then promote that library into `libenclaveapp` once it is demonstrated to work well for multiple application classes.

That library should facilitate three classes of application:
	•	Type 1: helper/plugin/tool integration
	•	the target app supports an auth helper, plugin, or callback command
	•	the wrapper configures that integration rather than rewriting config files
	•	Type 2: environment interpolation integration
	•	the target app supports environment-variable interpolation in config or arguments
	•	the wrapper launches the target with direct `execve()` and injects secret-bearing environment variables
	•	Type 3: temporary materialized config integration
	•	the target app cannot use a helper and cannot interpolate environment variables
	•	the wrapper materializes a temporary config file containing real secrets, launches the target with a config override, then destroys the temp file afterward

`npm` and `npx` are Type 2 applications.

That means:
	•	they still benefit from an ephemeral rewritten config file,
	•	but that file should normally contain `${NPM_TOKEN_*}` placeholders rather than materialized tokens,
	•	and the real token values should enter only through the environment passed at direct process launch.

The reusable library should therefore own the common pattern:
	•	resolve what executable the user’s shell context would effectively run,
	•	launch the real target directly rather than via the shell,
	•	choose the least-secret-exposing integration mode the target application supports,
	•	inject secrets by helper/plugin first if available,
	•	otherwise inject them by environment interpolation,
	•	and only fall back to temporary secret-bearing config files when no better integration exists.

⸻

Goal

The shared application-adaptation library should:
	1.	model the three integration types described above,
	2.	provide a direct-launch execution substrate that never uses the shell as the secret-bearing launcher,
	3.	provide secret/binding storage and lifecycle primitives suitable for app-specific wrappers,
	4.	provide temporary-config creation and cleanup primitives for Type 3 integrations,
	5.	provide executable-resolution support that can honor PATH, shims, wrappers, and `command -v` discovery.

`npmenc`, as the first consumer of that library, should:
	1.	determine the effective user .npmrc path using npm-like rules,
	2.	allow explicit override via:
	•	--userconfig <path>
	•	NPM_CONFIG_USERCONFIG
	3.	read that file,
	4.	rewrite any registry-scoped :_authToken= entry so the value becomes the appropriate ${NPM_TOKEN...} placeholder for the matching registry,
	5.	write the rewritten config to a private temp file when running wrapped commands, or update persistent user config during install as appropriate,
	6.	obtain one or more tokens through libenclaveapp,
	7.	launch npm with a subprocess environment containing:
	•	the inherited environment,
	•	one or more NPM_TOKEN... environment variables,
	•	NPM_CONFIG_USERCONFIG=<temp rewritten file> when using the ephemeral wrapper path,
	8.	clean up the temp file after the child exits.

In addition, v1 must support multiple labeled token targets, including:
	•	the default npm registry as the implicit/default label when none is specified,
	•	additional user-defined labels such as mycompany,
	•	each label bound to a specific registry URL,
	•	each label mapped to its own token source or token material managed through libenclaveapp.

In addition, v1 must also include npxenc for npx invocations using the same model and storage.

The design goal is that the experience is as transparent as possible to the user: their existing npm/npx setup, version-manager selection, and normal command behavior should continue to work.

In addition, npmenc must support lifecycle operations:
	•	install
	•	uninstall

where:
	•	install securely interns existing .npmrc auth tokens into managed libenclaveapp storage and updates the user configuration into the protected placeholder form,
	•	uninstall restores the user’s persistent .npmrc to the pre-npmenc style with materialized secrets, effectively returning the system to the way it was before npmenc became involved.

In addition, as a security/product UX principle:
	•	the CLI should generally support add/set and delete semantics for secrets,
	•	but should not provide a normal get operation for secret values.

This keeps the product aligned with a secret-manager model: secrets go in, are used, and can be rematerialized through uninstall or indirect execution, but are not trivially dumped through a convenience command.

⸻

Important design choice

Do not mutate the user’s real .npmrc in place during ordinary wrapped invocation.

Instead:
	•	parse the user-selected .npmrc,
	•	create a rewritten ephemeral copy,
	•	point npm or npx at that copy with NPM_CONFIG_USERCONFIG.

There is still no reason to touch ~/.npmrc directly for normal per-command execution.

However, install and uninstall are the explicit lifecycle operations that do intentionally update the user’s persistent .npmrc.

Also, do not use the shell to actually launch the target npm or npx process. The shell may be used as a resolution oracle via command -v to determine what command path or command form the current shell would resolve, but the final target process must always be launched directly so that the wrapper controls the exact execve() boundary where secrets enter the environment.

That means:
	•	no $SHELL -c 'npm ...' as the actual execution path,
	•	no shell-launched secret-bearing child process,
	•	but yes, shell-assisted resolution such as command -v npm or command -v npx is acceptable and desirable as the standard way to determine what the shell would do.

Transparency therefore has to be achieved through:
	•	command -v-based resolution,
	•	PATH scanning,
	•	filesystem/runtime resolution,
	•	shim handling,
	•	and then direct launch by npmenc/npxenc itself.

⸻

Scope of “same rules as npm”

For npmenc, “same rules as npm” still needs to be interpreted in two layers, but the executable-resolution layer is now precisely defined.

Layer 1: config-path and file-syntax behavior

npmenc should intentionally mirror npm-like behavior for:
	•	default user config path,
	•	explicit --userconfig,
	•	NPM_CONFIG_USERCONFIG,
	•	INI-like .npmrc syntax,
	•	preserving comments and unrelated settings.

Layer 2: practical transparency of executable resolution without shell-launched execution

The earlier revision had drifted into “no shell under any circumstances.” That is now corrected.

You want users who rely on:
	•	asdf
	•	nvm
	•	mise
	•	volta
	•	PATH-based shims
	•	wrappers
	•	whatever their environment currently resolves for npm or npx

to have things continue working.

You also want zero shell-launched execution of the secret-bearing target process.

So the design must now support transparent command resolution using shell-standard discovery, while still ensuring that the final target executable is launched directly by us.

That means resolution can and should be based on:
	•	current process environment,
	•	PATH scanning,
	•	filesystem inspection,
	•	direct executable probing,
	•	shim chain following,
	•	and command -v as the canonical way to ask “what would the shell invoke?”

Then the resolved result must still be interpreted and executed directly with execve() or equivalent by npmenc/npxenc.

This gives transparency while preserving the direct process-boundary secret injection property.

⸻

New v1 feature: labeled registry/token model

This remains a v1 requirement and is not deferred.

npmenc and npxenc must support multiple registry/token bindings identified by labels.

Required concepts

Each binding has:
	•	a label
	•	a registry URL
	•	a normalized registry auth key
	•	a token record in libenclaveapp
	•	optional installation provenance metadata so uninstall can restore prior state cleanly

Example logical bindings:
	•	default
	•	registry URL: https://registry.npmjs.org/
	•	implied if user does not specify a label
	•	mycompany
	•	registry URL: https://artifactory.example.com/api/npm/npm/

User-facing behavior

Users must be able to:
	•	set/add a binding for the default registry
	•	set/add a binding for a labeled custom registry
	•	update an existing binding
	•	list configured bindings
	•	delete a binding

The command surface should generally be secret-manager-like:
	•	set/add
	•	list metadata
	•	delete/remove
	•	install
	•	uninstall

but not “get me the token value.”

Example management UX

Illustrative interface:

npmenc token set --token-source sso-jwt
npmenc token set --label mycompany --url https://artifactory.example.com/api/npm/npm/ --token-source sso-jwt
npmenc token list
npmenc token delete --label mycompany
npmenc install
npmenc uninstall

Or, if you want explicit registry wording:

npmenc registry add --label mycompany --url https://artifactory.example.com/api/npm/npm/ --token-source sso-jwt
npmenc registry set-default --url https://registry.npmjs.org/ --token-source npm-login
npmenc uninstall

The exact CLI shape is still flexible, but the underlying model is not.

Storage model

libenclaveapp should persist metadata for each binding:
	•	label
	•	registry URL
	•	normalized registry auth key form used in .npmrc matching
	•	optional descriptive name
	•	token acquisition method
	•	token secret / refresh material / handle as appropriate
	•	installation provenance needed for uninstall/restore
	•	original auth-line form if migrated from .npmrc

Example internal record:

label = "mycompany"
registry_url = "https://artifactory.example.com/api/npm/npm/"
auth_key = "//artifactory.example.com/api/npm/npm/:_authToken"
token_provider = "sso-jwt"
installed_from_npmrc = true
original_line_kind = "scoped_authToken"

Default label semantics

If no label is provided, treat it as:

label = "default"
registry_url = "https://registry.npmjs.org/"
auth_key = "//registry.npmjs.org/:_authToken"

This default registry binding is the implied binding for unqualified cases.

⸻

High-level flow

1. Resolve target invocation mode

There are now two families of launch target:
	•	npmenc for npm commands
	•	npxenc for npx commands

Each must support:
	•	transparent direct resolution of the target executable path
	•	shell-assisted discovery via command -v
	•	direct executable launch only

2. Resolve user config source

Resolution order remains:
	•	--userconfig <path>
	•	NPM_CONFIG_USERCONFIG
	•	$HOME/.npmrc

3. Read source .npmrc
	•	If missing, treat as empty.
	•	Read raw bytes as text.
	•	Preserve comments and formatting as much as practical.

4. Parse and rewrite auth token lines

This step remains registry-aware and multi-token-aware.

For every line matching a registry-scoped token assignment like:

//registry.npmjs.org/:_authToken=abcdef
//artifactory.example.com/api/npm/npm/:_authToken=eyJhbGciOi...

rewrite the value portion to the correct placeholder for the matching configured binding.

Examples:

//registry.npmjs.org/:_authToken=${NPM_TOKEN_DEFAULT}
//artifactory.example.com/api/npm/npm/:_authToken=${NPM_TOKEN_MYCOMPANY}

The earlier single ${NPM_TOKEN} design is still not sufficient because v1 must support multiple registries.

5. Ensure missing configured registry entries can be injected

It is still not enough just to rewrite existing entries.

If the user has stored a labeled registry binding in npmenc, but their .npmrc does not yet contain the corresponding registry auth line, npmenc should be able to append the minimal necessary auth entry for that registry into the temp config.

That means v1 should support two cases:

Case A: existing line found
Rewrite it.

Case B: no existing line found for a configured binding
Append a generated line at the end of the temp config:

//artifactory.example.com/api/npm/npm/:_authToken=${NPM_TOKEN_MYCOMPANY}

Whether to also append @scope:registry=... is still a separate policy choice. The recommendation remains:
	•	do not invent or modify scope mappings automatically unless explicitly requested,
	•	but do inject the auth token line for configured registries.

That keeps the wrapper focused on auth rather than package-routing semantics.

6. Write rewritten temp userconfig
	•	Create a private temp directory with mode 0700.
	•	Create a temp file inside it with mode 0600.
	•	Write the rewritten config there.
	•	Never write actual token values into the file.
	•	Only write ${NPM_TOKEN_*} placeholders.

7. Obtain tokens through libenclaveapp

npmenc must obtain all tokens needed for the registries participating in this invocation model, not just one token.

At minimum:
	•	fetch the default token if the default registry binding exists,
	•	fetch every configured labeled token whose registry line is present or injected into the rewritten config.

8. Build child environment

Start with inherited environment, then add:
	•	NPM_CONFIG_USERCONFIG=<temp path>
	•	NPM_TOKEN_DEFAULT=<token for default registry>
	•	NPM_TOKEN_MYCOMPANY=<token for mycompany registry>
	•	etc.

The earlier single NPM_TOKEN variable remains generalized.

You may still choose to also populate plain NPM_TOKEN as an alias for the default token for compatibility with existing conventions:

NPM_TOKEN=<default token>
NPM_TOKEN_DEFAULT=<default token>

That is useful because many npm setups already expect NPM_TOKEN specifically.

9. Resolve npm or npx path, then launch directly

This section is now revised precisely rather than broadly.

The launcher should still never invoke the shell to actually run npm or npx.

Instead it should:
	1.	determine what executable or command form the user’s current shell context would resolve for npm or npx,
	2.	use command -v as the primary shell-standard discovery mechanism for that,
	3.	interpret the result,
	4.	do the equivalent itself with direct process execution,
	5.	inject the secret-bearing environment only into the final directly launched target process.

10. Cleanup

After child exits:
	•	zero/token-burn best effort in memory buffers,
	•	unlink temp userconfig,
	•	remove temp directory,
	•	return child exit code.

11. Auto-detect non-installed state during normal invocation

If the user runs npmenc or npxenc and:
	•	there are no saved managed tokens in libenclaveapp,
	•	but there are materialized auth tokens in the effective .npmrc,

then npmenc should infer that the user likely has not yet run install.

In that case:
	•	npmenc may prompt the user asking whether they want to “secure” the tokens,
	•	which is effectively the same as running install,
	•	if the user says yes, perform install and continue,
	•	if the user says no, still run the requested command transparently using the existing .npmrc-derived secrets for that invocation without disruption.

This preserves drop-in, non-disruptive behavior.

The key requirement is that the system should not suddenly fail or become annoying just because the user has not explicitly run install yet.

⸻

Install lifecycle

Purpose of install

npmenc install should:
	1.	locate the effective user .npmrc,
	2.	parse all supported registry-scoped auth token entries,
	3.	infer labels for those entries,
	4.	securely intern those secrets into libenclaveapp,
	5.	record sufficient metadata for future use and future uninstall,
	6.	rewrite the persistent user .npmrc so that token values are replaced by ${NPM_TOKEN_*} placeholders or otherwise converted into the protected managed form,
	7.	preserve unrelated settings and formatting as much as practical.

Token discovery during install

install should scan for registry-scoped entries such as:

//registry.npmjs.org/:_authToken=npm_ABC123
//artifactory.example.com/api/npm/npm/:_authToken=eyJhbGciOi...

Each discovered token should become a managed binding.

Label derivation during install

If the original .npmrc does not already contain an obvious label, install should derive labels from the hostname and path in a stable deterministic way.

Examples:
	•	//registry.npmjs.org/:_authToken=... → default
	•	//artifactory.example.com/api/npm/npm/:_authToken=... → artifactory-example-com-api-npm-npm
	•	or a more human-friendly shortened version such as artifactory-example-com

You specifically noted that duplication can be handled as a rare case. So the design should be:
	•	derive a deterministic default label from hostname/path,
	•	if that label conflicts, append a numeric suffix or prompt only in the rare ambiguous case,
	•	preserve an internal immutable binding ID regardless of the user-visible label.

Install provenance

install must store enough provenance to later perform uninstall accurately.

That should include:
	•	original config path,
	•	original line forms,
	•	original registry URL/auth key mappings,
	•	whether the token came from a real persistent .npmrc,
	•	whether the config line was rewritten or appended,
	•	optionally a backup snapshot of the relevant pre-install auth lines.

Install rewrite behavior

After interning the tokens, install should rewrite the persistent .npmrc into managed placeholder form.

Example:

Before:

//registry.npmjs.org/:_authToken=npm_ABC123
//artifactory.example.com/api/npm/npm/:_authToken=eyJhbGciOi...

After:

//registry.npmjs.org/:_authToken=${NPM_TOKEN_DEFAULT}
//artifactory.example.com/api/npm/npm/:_authToken=${NPM_TOKEN_ARTIFACTORY_EXAMPLE_COM_API_NPM_NPM}

This means normal direct npm invocation without npmenc would no longer work unless the environment variables were present, which is acceptable after install because the system has now been intentionally converted into managed mode.

If you want a gentler install mode, you could support:
	•	install --managed-placeholders as the default,
	•	install --leave-materialized only for migration/testing,

but the design target should still be that install converts the user into the protected model.

⸻

Uninstall lifecycle

Purpose of uninstall

npmenc uninstall should restore the system to the way it was before npmenc became involved.

That means:
	1.	locate the effective managed .npmrc,
	2.	materialize the currently stored tokens back into the persistent config,
	3.	reverse placeholder lines back into materialized :_authToken=... values,
	4.	remove only the npmenc-managed state that should be removed,
	5.	preserve unrelated config,
	6.	optionally remove the managed token records if the user confirms that they want full deprovisioning.

Uninstall restore behavior

If install converted:

//registry.npmjs.org/:_authToken=${NPM_TOKEN_DEFAULT}

backed by a managed secret, uninstall should restore:

//registry.npmjs.org/:_authToken=<materialized-secret>

The same applies for every managed labeled registry binding.

Uninstall state policy

There are two sensible variants:

Variant A: uninstall restores config and removes managed secret state
This is the cleanest semantic meaning of uninstall.

Variant B: uninstall restores config but leaves managed secret state unless --purge is specified
This is more forgiving.

I would recommend:
	•	default uninstall restores config and removes wrapper integration state,
	•	uninstall --keep-secrets can preserve internal state if desired,
	•	uninstall --purge explicitly removes everything.

But if you want strict “restore system to pre-npmenc state,” then default uninstall should probably remove the managed secret records too.

⸻

Secret-manager command surface

This section now becomes explicit.

You want the CLI to behave like a secret manager, not a secret dumper.

Supported secret operations
	•	set
	•	add
	•	delete
	•	list for metadata only
	•	install
	•	uninstall

Unsupported secret operation
	•	no normal get

So:

npmenc token set --label mycompany --url https://artifactory.example.com/api/npm/npm/
npmenc token delete --label mycompany
npmenc token list

is fine, but:

npmenc token get --label mycompany

should not exist.

Rationale

Yes, a user could still:
	•	run uninstall,
	•	write a Node.js script,
	•	inspect requests at runtime,
	•	dump their own environment,

but the CLI itself should not make exfiltration into a first-class convenience path.

That is still a worthwhile product boundary even if it is not absolute.

⸻

Rewrite rules

The rewrite rules remain expanded.

Rewrite these

Any registry-scoped token line:

//host/:_authToken=whatever
//host/path/:_authToken=whatever

becomes the placeholder associated with the matching configured binding.

Examples:

//registry.npmjs.org/:_authToken=${NPM_TOKEN_DEFAULT}
//artifactory.example.com/api/npm/npm/:_authToken=${NPM_TOKEN_MYCOMPANY}

Binding resolution rule

To determine which placeholder to use, normalize the line’s registry key and compare it to the configured binding keys.

Example normalized forms:
	•	//registry.npmjs.org/:_authToken
	•	//artifactory.example.com/api/npm/npm/:_authToken

Preserve these untouched
	•	comments
	•	blank lines
	•	registry mappings like @scope:registry=...
	•	always-auth=...
	•	unrelated config keys
	•	other ${...} placeholders

Support more than just _authToken

You specifically asked about Artifactory and similar systems. Some users may still have legacy auth forms such as:
	•	_auth
	•	username/password combinations
	•	_password
	•	username

For v1, the primary rewrite target should still be registry-scoped :_authToken, but the policy remains:
	•	supported and preferred: :_authToken
	•	detected but not auto-converted: other auth forms
	•	produce a warning explaining that npmenc v1 expects bearer-token style registry auth lines for full protection

Warn or fail on these

Unscoped token lines such as:

_authToken=abcdef

Default behavior should still be configurable:
	•	--strict: fail
	•	default: warn

⸻

Revised requirement: transparent execution honoring PATH, shims, version managers, and shell resolution behavior without shell-launched execution

This is now the explicit corrected requirement.

The earlier “no shell under any circumstances” wording is too strong. The corrected requirement is:
	•	use the shell-standard mechanism command -v to ask what the shell would do
	•	do not use the shell to actually run npm or npx
	•	we must then do those things ourselves

You want to preserve transparency for:
	•	PATH lookup
	•	PATH shims
	•	asdf
	•	nvm-like installed executables once their environment is already present
	•	shell command resolution behavior

But the final process that receives secrets must still be the directly executed target program.

Correct v1 design

Default launch mode should be:
	•	inspect the current execution environment,
	•	determine what path or command form the user’s shell would use for npm or npx,
	•	use command -v as the canonical discovery primitive for that,
	•	then interpret the result and invoke the real target directly.

Resolution strategy hierarchy

This should be explicit and layered.

Resolution strategy 1: direct current-process PATH resolution
Try normal executable resolution using the current process PATH.

This is still the safest and simplest case.

If npmenc itself is launched from the user’s already-initialized shell session, then in many cases the inherited PATH will already contain the correct shim or selected toolchain path from:
	•	asdf
	•	volta
	•	mise
	•	other path-based managers

In those cases, plain PATH resolution is sufficient.

Resolution strategy 2: command -v query
If requested, or if direct PATH resolution does not produce an acceptable result, npmenc may invoke the shell only to ask:

command -v npm
command -v npx

and capture the result.

The shell in this mode is used only as a resolution oracle, not as the final launcher of the secret-bearing target process.

That is materially different from:

$SHELL -lc 'npm ...'

which you do not want.

Important nuance about aliases and shell functions

Aliases and shell functions are not directly executable files.

If command -v npm reports something that corresponds to:
	•	an alias
	•	a function
	•	a shell builtin
	•	a reserved word

then npmenc should not simply fail and give up.

You explicitly want the system to handle this properly and remain transparent.

So the correct rule is:
	•	command -v tells us what kind of resolution the shell would perform,
	•	if it yields a direct executable path, use that directly,
	•	if it yields a shell-level alias/function form, npmenc must continue resolving to the actual underlying executable that the alias/function would ultimately invoke.

That means the implementation must support secondary resolution logic rather than stopping at the shell-level symbolic form.

How to handle alias/function results properly

This is the major corrected detail.

If command -v npm indicates an alias or function, npmenc should:
	1.	inspect the returned alias/function definition text if available,
	2.	parse out the underlying command target,
	3.	continue resolution recursively until a real executable path is identified,
	4.	then launch that real executable directly.

Examples:
	•	alias npm='asdf exec npm'
	•	function npm() { volta run npm "$@"; }

In such cases, npmenc must not launch through the shell, but it can examine what command -v revealed and replicate the command chain itself.

That may require explicit support for common command wrappers such as:
	•	asdf exec
	•	volta run
	•	mise exec
	•	other wrapper forms that still ultimately point to a real executable

If the alias/function is too arbitrary to safely interpret, then the system should still make a strong best effort:
	•	inspect PATH,
	•	inspect shim locations,
	•	inspect current Node/npm installation layout,
	•	identify the effective executable directly.

The goal is transparency, not “fail on complexity.”

Important nuance about asdf and similar managers

For path-shim managers like asdf, the good news is that the resolved npm is often an actual executable shim file on disk. That is perfect for direct execution.

So in those cases, the correct design is:
	•	let current PATH or command -v find the shim path,
	•	then execve() that shim path directly.

That preserves expected tool selection without making the shell the actual launcher.

Important nuance about nvm

If the user depends on nvm in the sense of shell setup that mutates environment during shell startup, then the correct npm binary may only be discoverable because npmenc inherited an already-initialized environment from the user’s shell session.

That is fine.

command -v can still help confirm what the shell would do, but npmenc should ultimately reduce that to an actual filesystem executable path or executable chain it can invoke directly.

Launcher modes

The earlier design had:
	•	shell-mediated mode
	•	direct mode

Then it was revised to:
	•	no shell at all

The corrected final model is:

A. Auto resolution mode — default
	•	try inherited PATH
	•	if needed, query command -v
	•	interpret the result
	•	continue resolution until a real executable or executable chain is identified
	•	launch directly

B. Explicit binary mode
	•	use --npm-bin or --npx-bin
	•	launch directly

Bottom line

To satisfy your transparency requirement and your direct-secret-injection requirement, the default must now be:
	•	PATH resolution first
	•	command -v as the standard shell-resolution oracle
	•	recursive interpretation of alias/function/wrapper results where needed
	•	direct execve() launch of the final target every time
	•	never shell-launched target execution

⸻

New v1 consumers: npmenc and npxenc

These both remain required and are not deferred.

Purpose

`npmenc` and `npxenc` should be separate binaries built on the same npm-specific core.

`npxenc` should behave exactly like `npmenc`, but invoke `npx` instead of `npm`.

Shared behavior

Both binaries must share:
	•	the same registry/token bindings
	•	the same libenclaveapp substrate
	•	the same reusable application-adaptation library
	•	the same .npmrc read/rewrite model
	•	the same temp userconfig model
	•	the same executable-resolution model
	•	the same direct-launch behavior
	•	the same install/uninstall lifecycle behavior where applicable

Why separate commands are still useful

Even though npx is related to npm, users mentally and operationally treat it as a separate command surface. A dedicated npxenc wrapper still makes the experience explicit and natural.

Shared internal implementation

Internally, both binaries should call a common npm-specific engine with a target command kind:

CommandKind::Npm
CommandKind::Npx

The only differences should be:
	•	the resolved command name,
	•	any command-specific defaults,
	•	and help text.

⸻

CLI design

The CLI design remains expanded, and the launcher-related options now need their final corrected meaning.

Invocation wrappers

npmenc [wrapper options] -- [npm args...]
npxenc [wrapper options] -- [npx args...]

Shared wrapper options

--userconfig <path>        Read this source npmrc instead of default
--shell <path>             Explicit shell path for command -v querying
--resolve-mode <mode>      auto | path-only | command-v
--npm-bin <path>           Explicit path to npm executable
--npx-bin <path>           Explicit path to npx executable
--print-effective-config   Print rewritten config path and exit
--dry-run                  Show what would be rewritten, do not launch
--strict                   Fail on malformed/unscoped auth entries
--allow-unscoped-auth      Permit legacy unscoped _authToken rewriting

Meaning of launcher-related options

--resolve-mode auto
Default.
	•	first try current-process PATH resolution
	•	if needed, query command -v
	•	interpret the result
	•	require final reduction to a directly executable target or executable chain

--resolve-mode path-only
	•	use current-process PATH only
	•	no command -v query

--resolve-mode command-v
	•	explicitly query command -v
	•	interpret the result
	•	still launch directly

Registry/token management commands

These should still be available from both binaries or from a shared management binary alias; simplest is still to expose them in both:

npmenc token set [--label <label>] [--url <registry-url>] [provider/options...]
npmenc token list
npmenc token delete [--label <label>]
npmenc install
npmenc uninstall

npxenc token list
npxenc install
npxenc uninstall

If you prefer one management surface, you can keep the authoritative mutation commands on npmenc and let npxenc primarily act as an execution wrapper.

You could also still unify token + registry storage under one command family:

npmenc credential set [--label <label>] --url <registry-url> [provider/options...]
npmenc credential list
npmenc credential delete [--label <label>]
npmenc install
npmenc uninstall

Default label behavior

If --label is omitted:
	•	treat it as default
	•	default URL is https://registry.npmjs.org/ unless explicitly overridden

⸻

Parsing strategy

Do not shell out to npm config to parse.

Do not use regex-only whole-file rewriting.

Use a line-oriented parser that preserves text faithfully.

Recommended parser behavior:
	•	split into lines preserving line endings,
	•	identify key=value or key = value assignments,
	•	trim only around the assignment operator for matching,
	•	preserve original left-hand side text exactly where possible,
	•	only replace the value portion for matching registry-scoped auth entries,
	•	support appending missing auth entries at file end.

This still gives stable, minimal edits.

Matching rule

Treat a line as token-bearing if the effective key is registry-scoped and ends with one of the supported auth keys, primarily:
	•	:_authToken

Then map that normalized key to a configured binding and replace only the value.

⸻

Install parsing and migration strategy

This section becomes explicit because install is now first-class.

Install discovery pass

When npmenc install runs:
	1.	resolve the effective .npmrc,
	2.	parse the file line-by-line,
	3.	identify every registry-scoped :_authToken= entry,
	4.	normalize each registry key,
	5.	derive or assign a label,
	6.	intern each discovered token into libenclaveapp,
	7.	record provenance for uninstall,
	8.	rewrite the persistent .npmrc into managed placeholder form.

Label derivation algorithm

For discovered entries:
	•	//registry.npmjs.org/:_authToken=... → label default
	•	otherwise derive from hostname/path
	•	normalize to a safe label alphabet
	•	if collision occurs, suffix deterministically

Example:

//artifactory.example.com/api/npm/npm/:_authToken=...
→ artifactory-example-com-api-npm-npm

You noted that rare duplication can be dealt with as a corner case, and that is the right model.

Install idempotence

install should be idempotent.

If a token line has already been converted into placeholder form and the corresponding managed binding already exists:
	•	do not duplicate it,
	•	do not create duplicate bindings,
	•	do not unnecessarily rewrite the file again beyond stable formatting preservation.

⸻

Suggested crate and module layout

Initial incubation inside `npmenc`

The reusable adapter library should be implemented here first, as an internal crate or
module set within the `npmenc` project. It is intentionally being incubated locally
before being promoted into `libenclaveapp`.

Suggested package: `npmenc/enclaveapp-app-adapter`

This is the new reusable library for adapting applications that cannot natively use
libenclaveapp as an auth source.

Suggested modules:

`app_spec.rs`
	•	defines the target application contract
	•	declares whether the app is Type 1, Type 2, or Type 3
	•	describes command names, config override behavior, and environment strategy

`binding_store.rs`
	•	manages configured label/url/binding records
	•	add
	•	update
	•	delete
	•	list
	•	store uninstall/install provenance

`secret_store.rs`
	•	libenclaveapp-backed secret persistence and retrieval
	•	memory hygiene
	•	fetch per-label secret values
	•	persist interned migrated token values

`resolver.rs`
	•	resolves the executable path or executable chain
	•	explicit binary override
	•	inherited PATH lookup
	•	optional `command -v` query
	•	interpretation of alias/function/wrapper results
	•	validation that the final execution target can be launched directly

`launcher.rs`
	•	launches only via direct process execution
	•	inherited env handling
	•	secret env injection
	•	exit code propagation

`temp_config.rs`
	•	creates private temp dirs/files
	•	tracks cleanup
	•	supports both placeholder-only temp configs and materialized-secret temp configs

`execution_plan.rs`
	•	selects the least-secret-exposing integration mode supported by the target app
	•	helper/plugin first
	•	env interpolation second
	•	temp materialization last

`types.rs`
	•	common enums and data structures
	•	command kind
	•	integration type
	•	binding identifiers
	•	launch directives

Package 2: `npmenc/npmenc-core`

This is npm-specific logic built on top of the adapter crate.

Suggested modules:

`config_path.rs`
	•	resolves source config path
	•	CLI override
	•	env override
	•	default path

`npmrc.rs`
	•	reads and rewrites `.npmrc`
	•	parse line structure
	•	rewrite token values using per-registry placeholders
	•	preserve formatting
	•	append missing auth entries for configured bindings when appropriate
	•	materialize managed token values during uninstall

`registry_bindings.rs`
	•	npm-specific normalization from registry URL to `.npmrc` auth key
	•	placeholder-name derivation
	•	default-label behavior

`install.rs`
	•	discovery of existing token lines
	•	label derivation
	•	interning into libenclaveapp
	•	persistent config rewrite
	•	idempotence logic

`uninstall.rs`
	•	managed binding lookup
	•	persistent config materialization
	•	restore semantics
	•	state cleanup / purge policy

`command_kind.rs`
	•	defines npm-specific command kinds
	•	`Npm`
	•	`Npx`

`main.rs` in each binary crate
	•	CLI orchestration only
	•	no duplicated business logic between `npmenc` and `npxenc`

This structure keeps the reusable wrapper substrate separate from npm-specific config semantics while still allowing the adapter layer to be extracted later without redesigning the npm-specific code.

⸻

Suggested delivery order

Phase 1: reusable adapter crate
	•	add the adapter library inside `npmenc`
	•	implement resolution, direct launch, temp config handling, and generic secret/binding primitives

Phase 1a: prove the abstraction locally
	•	use the local adapter library for `npmenc` and `npxenc`
	•	adjust names and module boundaries based on real usage before promoting it upstream

Phase 2: npm-specific core
	•	add the npm-specific core layer
	•	implement `.npmrc` parsing, rewrite logic, registry binding normalization, and install/uninstall

Phase 3: `npmenc`
	•	wire the adapter crate and npm core together for end-to-end `npm` execution

Phase 4: `npxenc`
	•	add the second thin binary over the same core

Phase 5: hardening and polish
	•	add migration UX
	•	add test coverage across parser, resolver, lifecycle, and cleanup behavior
	•	verify that Type 2 flows never materialize secrets into temp config files
	•	identify the stable extraction boundary for promotion into `libenclaveapp`

⸻

Security properties

This revised design improves over static .npmrc tokens because:
	•	actual token values are never written into the rewritten temp config file used for wrapped invocations,
	•	the temp config only contains ${NPM_TOKEN_*} placeholders,
	•	real token material is injected only into the directly launched subprocess environment,
	•	the user’s persistent .npmrc is not modified during ordinary wrapped execution,
	•	multiple registries can be handled in a single invocation without collapsing everything into one shared token,
	•	the shell is not the final launch boundary for the secret-bearing process,
	•	install/uninstall give the user a controlled lifecycle rather than forcing an all-or-nothing migration.

It still does not eliminate all ambient exposure:
	•	token values exist in the child environment,
	•	descendant processes may inherit them unless scrubbed,
	•	same-user process inspection risk still exists,
	•	command -v querying may involve a helper shell subprocess, but that subprocess does not need the secret-bearing environment and is not the launcher of the target command.

But it is still substantially cleaner than storing live tokens in .npmrc, and cleaner than shell-launched execution of the secret-bearing target process.

⸻

Example transformation

Input:

registry=https://registry.npmjs.org/
@myco:registry=https://artifactory.example.com/api/npm/npm/
always-auth=true
//registry.npmjs.org/:_authToken=npm_ABC123
//artifactory.example.com/api/npm/npm/:_authToken=eyJhbGciOi...
color=true

Configured bindings:

default   -> https://registry.npmjs.org/
mycompany -> https://artifactory.example.com/api/npm/npm/

Rewritten temp config for wrapped execution:

registry=https://registry.npmjs.org/
@myco:registry=https://artifactory.example.com/api/npm/npm/
always-auth=true
//registry.npmjs.org/:_authToken=${NPM_TOKEN_DEFAULT}
//artifactory.example.com/api/npm/npm/:_authToken=${NPM_TOKEN_MYCOMPANY}
color=true

Child environment additions:

NPM_CONFIG_USERCONFIG=<temp rewritten path>
NPM_TOKEN=<default token>
NPM_TOKEN_DEFAULT=<default token>
NPM_TOKEN_MYCOMPANY=<mycompany token>

Resolved executable example:

command -v npm  -> /Users/jeremiah/.asdf/shims/npm

Final launch:
	•	direct execve() of /Users/jeremiah/.asdf/shims/npm
	•	with the constructed environment above

If command -v npm instead reveals an alias or wrapper form, npmenc continues resolution until it identifies the real executable or executable chain and then launches that directly.

⸻

Recommended behavior for multiple token lines

The earlier design already corrected the single-token model. That remains true.

The rule is still:
	•	rewrite each registry-scoped token line to the placeholder corresponding to its configured binding,
	•	allow multiple distinct placeholders in the same temp config,
	•	inject all corresponding environment variables into the child process.

If a registry-scoped token line is encountered for which no configured binding exists:
	•	default behavior: leave it unchanged and emit a warning, or optionally fail in --strict mode,
	•	safer behavior if you want stronger guarantees: fail in --strict, warn otherwise.

It is still not acceptable to silently collapse unknown registries onto the default token.

⸻

Behavior when not yet installed

This section is now explicit because you wanted drop-in, non-disruptive behavior.

If the user runs npmenc or npxenc and the system observes:
	•	no saved managed tokens in libenclaveapp,
	•	but one or more materialized :_authToken= values in the effective .npmrc,

then npmenc should infer that the user likely has not run install yet.

Recommended behavior
	1.	detect that state,
	2.	inform or prompt the user that the existing tokens can be “secured,”
	3.	if the user accepts, run the equivalent of install,
	4.	if the user declines, proceed transparently with the requested command anyway.

Transparent fallback mode

If the user declines install, npmenc can still:
	•	parse the .npmrc,
	•	extract the currently materialized token values in memory,
	•	build an ephemeral managed temp config for that invocation,
	•	launch the command successfully,
	•	and leave the persistent .npmrc unchanged.

That preserves drop-in behavior without forcing migration.

⸻

Pseudocode

parse argv
determine command kind: npmenc or npxenc

if argv is management command:
  operate on registry/token bindings in libenclaveapp-backed storage
  exit

resolve source userconfig path:
  if --userconfig set -> use it
  else if NPM_CONFIG_USERCONFIG set -> use it
  else -> $HOME/.npmrc

read source config if exists, else empty

if command is install:
  parse existing registry-scoped authToken lines
  derive labels
  intern tokens into libenclaveapp
  record provenance for uninstall
  rewrite persistent config to placeholder form
  exit

if command is uninstall:
  load managed bindings
  materialize secrets back into persistent config
  remove or preserve managed state according to uninstall policy
  exit

load configured registry bindings

if no configured bindings exist and materialized tokens exist in .npmrc:
  prompt to secure them
  if yes:
    run install flow
    reload bindings
  else:
    use transparent one-shot fallback for this invocation

normalize each binding to registry auth key + placeholder name

rewrite source config:
  for each registry-scoped :_authToken line:
    normalize key
    if matching configured binding exists:
      replace value with that binding placeholder
      mark binding as used
    else if transparent one-shot fallback extracted a materialized token:
      synthesize a transient binding and placeholder
      mark it as used
    else:
      warn or fail depending on mode

for each configured binding not already present in file:
  optionally append registry-scoped authToken placeholder line

create private temp dir
write rewritten config to temp dir/npmrc

for each used/appended binding:
  token = libenclaveapp.get_token(binding.label) or transient extracted token
  add env var for placeholder name
  if label == default:
    also set NPM_TOKEN=token

child_env = inherited_env
remove conflicting NPM_CONFIG_USERCONFIG / npm_config_userconfig
add NPM_CONFIG_USERCONFIG=temp_npmrc_path
add token env vars

resolve target executable:
  if explicit --npm-bin / --npx-bin:
    use it
  else:
    try current PATH resolution
    if not found or if resolution policy requires:
      query shell with command -v
    interpret result
    if result is direct path:
      use it
    else if result is alias/function/wrapper:
      continue resolving underlying executable chain
    ensure final execution target can be launched directly

spawn target directly with execve-equivalent
wait for child
best-effort zero token buffers
delete temp_npmrc
delete temp dir
exit with child status


⸻

Revised recommendation on process model

The earlier recommendation was:
	•	wrapper parent process remains mandatory
	•	direct exec child launch becomes the default and standard
	•	shell involvement is limited to optional command-path discovery
	•	no shell-launched target execution

That remains correct, with the following clarification:

1. Wrapper parent process remains mandatory

This still matters because deterministic cleanup matters.

2. Direct child execution remains mandatory

The target npm or npx process should always be launched directly.

3. Shell involvement is allowed only as a command -v discovery oracle

The shell may be queried to determine what command resolution would occur, but it is never the final launcher of the secret-bearing target process.

4. Alias/function/wrapper results must be handled rather than treated as fatal

The resolution subsystem must continue past shell-level symbolic forms and reproduce their effect through direct execution.

So the revised recommendation is:
	•	wrapper parent process remains mandatory
	•	direct exec child launch remains mandatory
	•	command -v is explicitly allowed and useful
	•	shell involvement is limited to resolution discovery
	•	no shell-launched target execution
	•	alias/function/wrapper resolution must be handled, not rejected

⸻

Final bottom line recommendation

Build a reusable application-adaptation library inside `npmenc` first, then build npmenc and npxenc on top of it with:
	•	explicit support for Type 1 helper/plugin integrations,
	•	explicit support for Type 2 environment-interpolation integrations,
	•	explicit support for Type 3 temporary-materialized-config integrations,
	•	labeled registry bindings as a v1 feature,
	•	implicit default label for the standard npm registry,
	•	multiple token placeholders and environment variables in one invocation,
	•	PATH resolution first,
	•	command -v as the standard way to ask what the user’s shell would do,
	•	recursive interpretation of alias/function/wrapper results where needed,
	•	direct execve() launching of the final npm/npx target every time,
	•	install/uninstall lifecycle support,
	•	automatic migration detection when users still have materialized .npmrc tokens,
	•	secret-manager-style add/set/delete semantics without a first-class get,
	•	temp rewritten userconfig files that never contain the actual secrets for normal wrapped execution.

The core mechanism is still:
	•	read effective user .npmrc,
	•	rewrite every registry-scoped auth token line to an environment placeholder,
	•	append missing configured registry auth lines when needed,
	•	resolve the actual executable path or execution chain for npm or npx in a way that matches what the shell would do,
	•	launch that resolved target directly with inherited environment plus the appropriate token variables and overridden userconfig path,
	•	clean up afterward.

That is the correct substrate. The key correction is that the reusable adaptation library is part of v1 architecture, but it should be incubated inside `npmenc` before being promoted into `libenclaveapp`. Multi-registry labeled token support, npxenc, install/uninstall, automatic migration detection, and drop-in transparency remain v1 requirements, and `command -v` is explicitly embraced for shell-standard discovery while shell-launched execution remains forbidden.
