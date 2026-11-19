# Ansible Vaults

An omp tool that edits Ansible Vault secrets without ever revealing them to the model.

## Language

**Vault**:
An Ansible Vault–encrypted file declared in a project's config and addressed by its vault name.
_Avoid_: secret file

**Vault password**:
The secret that encrypts a vault; several vaults may share one.
_Avoid_: key, master password

**Password id**:
The machine-wide name of a vault password; vaults naming the same id share the same password.
_Avoid_: password file, key name

**Password store**:
The OS-provided place where vault passwords are kept, never as a readable file.
_Avoid_: keyring, vault (ambiguous)

**Enrollment**:
Putting a vault password into the password store, verified against a vault that uses it.
_Avoid_: import, registration

**Unlock**:
Obtaining a vault password from the password store; on Windows and macOS it requires the user's presence.
_Avoid_: login, decrypt
