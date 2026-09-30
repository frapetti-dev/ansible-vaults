# ansible-vaults

omp plugin that registers the `ansible_vault` tool: list, add, update and delete top-level keys in Ansible Vault files without ever exposing secret values to the model.

## What it does

Actions: `list_vaults`, `list_keys`, `add`, `update`, `delete`.

- Values are never returned to the model, only key names and value lengths.
- `add` / `update` / `delete` show a confirmation dialog listing the exact keys. Denying it writes nothing.
- Changes are atomic: all keys are applied or none.
- Vault 1.1 / 1.2 AES256 is implemented natively. No `ansible-vault` binary is needed.

## Install

From git (the repo is private, so gh/git credentials are required):

```sh
omp plugin install git+https://github.com/frapetti-dev/ansible-vaults.git
```

From a local clone:

```sh
omp plugin link <path-to-clone>
```

## Per-project config

Create `.omp/ansible-vaults.json` in each project:

```json
{"vaults":{"xion":{"file":"ansible/group_vars/xion/vault.yml","passwordFile":".omp/keys/.vault-pass","description":"Secrets for the xion VPS"}}}
```

- Vault names must match `^[A-Za-z0-9_-]+$`.
- `file` and `passwordFile` resolve relative to the session cwd.

## Value sources

Each entry passed to `add` / `update` has a `source`:

| source     | fields           | notes |
|------------|------------------|-------|
| `generate` | `format`, `length` | `format`: `urlsafe` \| `base64` \| `hex` \| `alnum`; length 8–256; default `urlsafe` 32 |
| `prompt`   | `prompt`         | masked TUI input; TUI mode only |
| `file`     | `path`           | read from a file, e.g. a path produced by `secret_input` |
| `literal`  | `value`          | non-secret values only (visible in chat) |

## Migrating from a project-local copy

A project that still carries `.omp/extensions/ansible-vault.ts` (e.g. xion) registers the same tool twice. Delete the project-local copy after installing the plugin.
