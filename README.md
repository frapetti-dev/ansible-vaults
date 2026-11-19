# ansible-vaults

omp plugin that registers the `ansible_vault` tool: list, add, update and delete top-level keys in Ansible Vault files without ever exposing secret values to the model. The `/vaults` command offers the same operations to the user in a TUI screen.

## What it does

Actions: `list_vaults`, `list_keys`, `add`, `update`, `delete`, `set_password`.

- Values are never returned to the model, only key names and value lengths.
- `add` / `update` / `delete` show a confirmation dialog listing the exact keys. Denying it writes nothing.
- Changes are atomic: all keys are applied or none.
- Vault 1.1 / 1.2 AES256 is implemented natively. No `ansible-vault` binary is needed.

## Install

### From git (recommended)

The repo is private, so git credentials with read access are required (e.g. `gh auth login`).

```sh
omp plugin install github:frapetti-dev/ansible-vaults
```

This installs the default branch HEAD. To pin a release, append a ref: `github:frapetti-dev/ansible-vaults#v0.1.0`.

### From GitHub Packages

Each GitHub Release publishes `@frapetti-dev/ansible-vaults` to GitHub Packages. The package is private, so npm/bun needs the scope mapped to GitHub Packages plus a classic PAT with `read:packages` (fine-grained PATs are not supported). Add to `~/.npmrc`:

```ini
@frapetti-dev:registry=https://npm.pkg.github.com
//npm.pkg.github.com/:_authToken=<PAT with read:packages>
```

Then:

```sh
omp plugin install @frapetti-dev/ansible-vaults
```

Notes:

- Do not use an `npm:` prefix. omp passes the spec to `bun install` as-is, and bun rejects `npm:@frapetti-dev/ansible-vaults` as an invalid dependency name.
- Without the `~/.npmrc` scope mapping, bun queries registry.npmjs.org and fails with a 404.

### From a local clone

```sh
omp plugin link <path-to-clone>
```

## Releasing

1. Bump `version` in `package.json` and merge to `main`.
2. Create a GitHub Release whose tag is `v<version>` (e.g. `gh release create v0.1.1 --generate-notes`). The `Publish` workflow checks that the tag matches `package.json` and the checked-out commit, then runs `npm publish` to GitHub Packages.
3. To republish an existing tag, run the workflow manually: `gh workflow run publish.yml -f tag=v<version>`.

## Per-project config

Create `.omp/ansible-vaults.json` in each project:

```json
{"vaults":{"xion":{"file":"ansible/group_vars/xion/vault.yml","passwordId":"xion","description":"Secrets for the xion VPS"}}}
```

- Vault names and `passwordId` must match `^[A-Za-z0-9_-]+$`.
- `file` resolves relative to the session cwd.
- A `passwordId` is machine-wide: vaults naming the same id, even in different projects, share one password.
- `passwordFile` is no longer supported; see below.

## Vault password

Passwords live in the OS password store, never in a readable file:

| OS      | Store | Unlock |
|---------|-------|--------|
| Windows | Hello-sealed blob in Credential Manager (AES-GCM key derived from a Windows Hello signature) | Hello PIN/biometric prompt |
| macOS   | keychain item that trusts no application | OS access dialog on every read |
| Linux   | Secret Service (libsecret) | none. Weaker: any process running as the user can read it |

Unlock happens once per omp process; the password then stays in memory until omp exits.

> **Not tested:** only the Windows (Hello) implementation has been run. The macOS and Linux backends are implemented but untested.

Enroll a password with `set_password` (shows a confirmation dialog, then verifies the password against the vault before storing it):

- `{"action":"set_password","vault":"xion"}` masks a typed password in the TUI.
- `{"action":"set_password","vault":"xion","passwordSource":"file","passwordPath":".omp/keys/.vault-pass"}` imports the old password file once. Delete the file afterwards; the tool never does.

Windows: a Hello PIN reset destroys the key; run `set_password` again. macOS: never click "Always Allow"; it lets any `security` call read the password silently.

## Value sources

Each entry passed to `add` / `update` has a `source`:

| source     | fields           | notes |
|------------|------------------|-------|
| `generate` | `format`, `length` | `format`: `urlsafe` \| `base64` \| `hex` \| `alnum`; length 8–256; default `urlsafe` 32 |
| `prompt`   | `prompt`         | masked TUI input; TUI mode only |
| `file`     | `path`           | read from a file, e.g. a path produced by `secret_input` |
| `literal`  | `value`          | non-secret values only (visible in chat) |

## `/vaults` command

`/vaults` opens a full-screen manager for the current project (interactive TUI only). Nothing it shows is sent to the model.

- Vault list: `a` declares a vault (creates an empty encrypted file if the file is missing), `e` edits name, file, password id or description, `d` removes the declaration, `p` stores the password, `Enter` unlocks and lists keys.
- Key list: `n` adds a key, `u` overwrites a value, `x` deletes a key, `r` reveals/hides a value, `Tab` goes back. Values can be typed (masked) or generated.
- Removing a declaration leaves the vault file and its stored password alone. If no remaining declaration in the project uses that password id, it offers to delete the password; other projects using the same id would need `set_password` again.
- Edits rewrite `.omp/ansible-vaults.json` atomically and keep fields the plugin does not know about.

## Migrating from a project-local copy

A project that still carries `.omp/extensions/ansible-vault.ts` (e.g. xion) registers the same tool twice. Delete the project-local copy after installing the plugin.
