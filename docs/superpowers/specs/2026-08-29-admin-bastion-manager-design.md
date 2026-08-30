# Admin / Bastion Manager Setup — Design

Status: approved in chat 2026-08-29, pending file review.
Author: Riyaz Walikar (with Claude).
Scope: host bootstrap script, break-glass admin account, root-only tier-user admin binary, and the README section documenting all three.

## Why

Today, standing up an `awsjail` bastion is a manual sequence copy-pasted from the README's "Host setup" section: build the binary by hand, create the `awsjail` group, create directories, hand-edit `/etc/awsjail/roles.json` with `tee`, `useradd` each tier user, drop their key into `authorized_keys`, edit `sshd_config` directly. It works but has no idempotency, no validation, and no audit trail of who changed `roles.json` or when. There is also no answer to "what do I do if `awsjail` itself is broken and I need to get on the box" — every account on the box is either root (disabled login per sshd hardening) or a tier user (jailed to `aws` only).

This design adds:

1. `setup.sh` — an idempotent Ubuntu bootstrap script that does the manual sequence for you, once.
2. A break-glass account (`bastion-admin`) — a normal, sudo-capable SSH account outside the `awsjail` group, for the case where the jail itself needs debugging.
3. `awsjail-admin` — a root-only Go binary that replaces the manual `roles.json`/`useradd`/`authorized_keys` steps with validated, atomic, audited operations.
4. A new README section, "Admin/Bastion Manager Setup," documenting all of the above.

## Non-goals

- No change to `awsjail.go`'s runtime behavior (the jail itself is untouched).
- No config management (Ansible/Terraform) — `setup.sh` is a single-host bootstrap script, not a fleet tool. Terraform for the network/IAM side is still on the v2 roadmap in spec.md, unchanged.
- No automated tests for the new code in this pass — consistent with the "Minimal" scope chosen for the rest of this repo. Flagged as an open question below.
- `awsjail-admin` does not manage the break-glass account or any other sudo-group admin. It only manages tier (bastion) users — the `roles.json` population.
- No key rotation subcommand — rotation is re-running `add-user` with a new `--pubkey-file` (idempotent upsert).

## Repo layout change

```
awsjail.go        # unchanged, package main
admin/
  main.go         # new, package main — the awsjail-admin binary
setup.sh          # new, host bootstrap script
```

Two build targets from the one `go.mod` (module `github.com/riyazwalikar/awsjail`):

```
CGO_ENABLED=0 go build -o awsjail .
CGO_ENABLED=0 go build -o awsjail-admin ./admin
```

Both static, same `CGO_ENABLED=0` rationale as the existing binary (no `LD_PRELOAD` surface).

## Component 1: `setup.sh`

Target: Ubuntu 22.04 LTS and 24.04 LTS. Run as root (`sudo ./setup.sh`) from inside a checkout of this repo — the script does not `git clone` anything itself; you get the repo onto the box however you already do (`git clone`, `scp`, config management), then run the script from that directory. It builds from the working directory's `awsjail.go` and `admin/`.

Idempotency rule: every step checks current state before acting, so re-running the script on an already-provisioned host is a safe no-op except where inputs changed (e.g., a new break-glass pubkey is appended, not required).

Steps, in order:

1. **Preconditions.** Must run as root (`EUID -eq 0`, else exit 1). Warn (not fail) if `/etc/os-release` doesn't report Ubuntu 22.04/24.04 — let the operator decide whether to continue on an untested release.
2. **Go toolchain.** If `go version` is absent or older than the `go` directive in `go.mod`, download the official Go tarball for `linux/amd64` (or `arm64`, detected via `uname -m`) from `https://go.dev/dl/`, extract to `/usr/local/go`, and ensure `/usr/local/go/bin` is on `PATH` for this script's remaining steps. Do not touch the user's shell rc files. Skip entirely if an adequate `go` is already on `PATH`.
3. **AWS CLI v2.** If `/usr/local/bin/aws` is missing, or `aws --version` doesn't report a `2.x` line, download the official AWS CLI v2 installer (`https://awscli.amazonaws.com/awscli-exe-linux-<arch>.zip`), unzip to a temp dir, run its `install` script targeting `/usr/local/bin` and `/usr/local/aws-cli`, then clean up the temp dir.
4. **Group.** `getent group awsjail` — create with `groupadd awsjail` if absent.
5. **Directories and files.**
   - `install -d -m 0755 -o root -g root /etc/awsjail`
   - `install -d -m 0700 -o root -g root /var/lib/awsjail`
   - If `/etc/awsjail/roles.json` doesn't exist, write `{}` to it, `chmod 0644`, `chown root:root`. Never overwrite an existing file.
6. **Login shell registration.** Append `/usr/local/bin/awsjail` to `/etc/shells` if not already present (`grep -qxF` check first).
7. **Build and install binaries.**
   - `CGO_ENABLED=0 go build -o awsjail .` then `install -m 0755 -o root -g root awsjail /usr/local/bin/awsjail`.
   - `CGO_ENABLED=0 go build -o awsjail-admin ./admin` then `install -m 0700 -o root -g root awsjail-admin /usr/local/sbin/awsjail-admin`.
8. **Break-glass account.**
   - If `id bastion-admin` fails, create it: `useradd -m -G sudo -s /bin/bash bastion-admin`.
   - Prompt (interactive `read`, or accept a `--bastion-admin-pubkey-file PATH` script flag for non-interactive runs) for a public key. Validate it parses as `ssh-<type> <base64> [comment]` (same parser used by `awsjail-admin`, see below — extracted as a small shared shell/Go check; for the shell script this is a regex sanity check, not full crypto validation).
   - `install -d -m 0700 -o bastion-admin -g bastion-admin /home/bastion-admin/.ssh`, then **append** the validated key to `/home/bastion-admin/.ssh/authorized_keys` if it's not already the last line present (idempotent append, not overwrite — unlike tier users, the break-glass account may reasonably hold more than one admin's key), `chmod 0600`, `chown bastion-admin:bastion-admin`.
9. **sshd hardening drop-in.** Write `/etc/ssh/sshd_config.d/awsjail.conf` (overwrite — this file is fully owned/generated by this script, safe to regenerate) with:
   ```
   PubkeyAuthentication yes
   PasswordAuthentication no
   PermitRootLogin no
   PermitUserEnvironment no

   Match Group awsjail
       PermitTTY yes
       X11Forwarding no
       AllowTcpForwarding no
       AllowAgentForwarding no
       AllowStreamLocalForwarding no
       PermitTunnel no
       PermitOpen none
   ```
   `bastion-admin` is in group `sudo`, not `awsjail`, so it never matches the restrictive block — full normal SSH, as decided.
10. **sftp subsystem.** Comment out the `Subsystem sftp ...` line in `/etc/ssh/sshd_config` if present and not already commented (idempotent `sed`).
11. **Validate and reload.** `sshd -t`. Only on success, `systemctl reload ssh`. On failure, print the `sshd -t` output and exit non-zero without reloading — never leave sshd in a state where the next restart could fail.
12. **Summary output.** Print what was created/skipped at each step (e.g., "awsjail group: already exists", "roles.json: created empty", "bastion-admin: created, key installed") so a re-run's idempotency is visible, not silent.

Flags: `--bastion-admin-pubkey-file PATH` (skip the interactive prompt), `--skip-sshd-reload` (write the drop-in and validate but don't reload — for review-before-apply workflows). Everything else is zero-config by design; region/role-per-user now lives in `roles.json`, not in this script.

## Component 2: break-glass account details

- Username: `bastion-admin`, fixed (not configurable — one well-known name is easier to audit and document than a variable one; operators who want a *named* second admin add their own account the same way `bastion-admin` was created, manually, since that's rare and high-trust enough not to warrant tooling).
- Group: `sudo` (standard Ubuntu sudo group), home `/home/bastion-admin`, shell `/bin/bash`.
- Not a member of `awsjail` — this is what exempts it from the `Match Group awsjail` sshd block. This must be called out clearly in docs: never add `bastion-admin` to the `awsjail` group.
- Multiple keys allowed in its `authorized_keys` (append, not overwrite) since more than one human may hold break-glass access over the life of the host.
- No `awsjail-admin` special-casing for this account — it's just a regular Ubuntu admin account created by the script. Adding/removing its keys after initial setup is a manual `authorized_keys` edit, same as any Ubuntu box.

## Component 3: `awsjail-admin`

Binary: `/usr/local/sbin/awsjail-admin`, mode `0700`, owner `root:root`. Placed in `sbin` (not `bin`) as a second, weaker signal that this is not a general-user tool; the `0700` mode is the actual control.

Every invocation checks `os.Geteuid() == 0` first; if not root, print `awsjail-admin: must run as root` to stderr and exit 1. This is a defense-in-depth check — the file mode already prevents non-root execution — but makes the failure message clear if it's ever invoked via `sudo -u someone-else` or copied elsewhere.

### Global behavior

- Reads/writes `/etc/awsjail/roles.json` (path is a const, matching `awsjail.go`'s `roleMapPath`).
- Every successful `add-user` or `remove-user` logs one JSON line to syslog facility `authpriv`, tag `awsjail-admin`, at `LOG_NOTICE`:
  ```json
  {"actor": "<SUDO_USER or unix user running the command>", "action": "add_user"|"remove_user", "target": "<username>", "result": "ok"}
  ```
  `actor` is read from the `SUDO_USER` env var if set (i.e., invoked via `sudo`), else falls back to `user.Current()`. This mirrors `awsjail.go`'s existing audit philosophy and gives a record of *who provisioned/deprovisioned* a tier user, closing the "roles.json is a privilege map with no audit trail" gap noted in spec.md's Gotchas section.
- All `roles.json` writes are atomic: read-modify-write via a temp file in `/etc/awsjail/` followed by `os.Rename` onto `roles.json`, preserving `0644 root:root`. This avoids a half-written file if the process is killed mid-write, and it means concurrent `awsjail-admin` invocations can't corrupt the file (last writer wins cleanly, never a torn file).

### `add-user`

```
awsjail-admin add-user --username U --role-arn ARN --region R --pubkey-file PATH
```

- **Validate `--username`**: must match a safe unix username pattern (e.g. `^[a-z_][a-z0-9_-]{0,31}$`, mirroring `useradd`'s own constraints) before it touches `useradd`, `roles.json`, or a filesystem path. Reject and exit 1 on mismatch, no side effects.
- **Validate `--role-arn`**: must match `^arn:aws:iam::\d{12}:role/[\w+=,.@/-]+$` (IAM role ARNs can include a path, e.g. `role/service-role/foo`, so `/` is allowed inside the role-name segment). This is a format sanity check only — `awsjail-admin` does not call AWS or verify the role exists/trusts the instance role. That verification happens naturally the first time the user logs in and `awsjail.go`'s `assume()` either succeeds or fails closed.
- **Validate `--region`**: must match `^[a-z]{2}-[a-z]+-\d$` (e.g. `ap-south-1`, `us-east-1`). Format check only, same reasoning as above.
- **Validate `--pubkey-file`**: file must exist and its content, trimmed, must parse as exactly one `ssh-<type> <base64> [comment]` line (accepted types: `ssh-ed25519`, `ssh-rsa`, `ecdsa-sha2-*`). Reject files with zero or multiple keys, garbage, or a private key (detect and refuse `-----BEGIN` content explicitly, with a clear error, since pasting the wrong file is a realistic mistake).
- **Ensure unix account.** If `user.Lookup(U)` fails, run `useradd -m -G awsjail -s /usr/local/bin/awsjail U`. If it already exists, verify (and correct if wrong) that its login shell is `/usr/local/bin/awsjail` and it is a member of `awsjail` — `usermod -s ... -aG awsjail` if either is off, so re-running `add-user` also heals a drifted account.
- **Upsert `roles.json`.** Load the map (`map[string]roleEntry`), set/overwrite the entry for `U` to `{role_arn: ARN, region: R}`, atomic write.
- **Install the key.** Ensure `~U/.ssh` exists, `0700`, owned by `U:U` (create if missing). Write `~U/.ssh/authorized_keys` containing exactly the one validated key line plus trailing newline — **overwrite**, not append (this is the documented rotation mechanism: re-run `add-user` with a new `--pubkey-file` to rotate). `0600`, owned by `U:U`.
- **Order of operations matters for fail-closed safety**: validate everything first (no side effects on any validation failure), then account, then `roles.json`, then key. If the process dies after account+roles.json but before the key write, the user has no valid key yet — can't SSH in at all, safe. If it dies after account+key but before roles.json — hypothetically possible only if key-write happened before roles.json, which is why roles.json is written *before* the key, not after: worst case is a valid key with no role mapping, and `awsjail.go` already fails that closed with `no_role`. This ordering is deliberate and should be preserved in implementation, not reordered for convenience.
- **Idempotent overall.** Running `add-user` twice with identical arguments is a no-op after the first (except it rewrites `authorized_keys`/`roles.json` with identical content — harmless).
- Exit 0 and a one-line human-readable summary on success (e.g. `added dbbackup: role tier-dbbackup, region ap-south-1, key SHA256:...`). Exit 1 with a specific error on any validation or system failure, nothing silently swallowed.

### `remove-user`

```
awsjail-admin remove-user --username U
```

- Load `roles.json`. If `U` is present, delete the entry and atomic-write. If absent, no-op (not an error) but say so explicitly (`U was not mapped, nothing to remove` — exit 0).
- Overwrite `~U/.ssh/authorized_keys` with empty content (`0600`, preserve ownership) if the file exists; if `~U/.ssh` doesn't exist, nothing to do there.
- Does **not** call `userdel`. The unix account and home directory are left alone — deliberate, per the earlier decision, so a post-incident review has something to look at. Full account deletion remains a manual `userdel -r` if/when an operator decides it's truly done.
- Logs `action: "remove_user"` the same way as `add-user`, including the no-op case (so "someone tried to remove a user that wasn't there" is also on the record).

### `list-users`

```
awsjail-admin list-users
```

- Reads `roles.json`. For each mapped username, also reads `~U/.ssh/authorized_keys` (if present) and computes the SHA256 fingerprint (same algorithm `ssh-keygen -lf` uses) plus the key's comment field, for display only — no crypto verification beyond parsing.
- Prints an aligned plain-text table: `USERNAME  ROLE_ARN  REGION  KEY_FINGERPRINT  STATUS`.
- `STATUS` flags drift: `ok` (mapped and has exactly one valid key), `no-key` (mapped, but no readable/valid key — can't log in, harmless but likely a mistake), or `key-parse-error` (file exists but doesn't parse). Does not attempt to detect the reverse case (a unix account with a key but no `roles.json` entry) in this pass — that would require walking all `awsjail`-group unix accounts, which is a nice-to-have flagged in "Open questions" below, not committed to for v1.
- No mutation, no logging (read-only command, nothing to audit).

## Component 4: README section — "Admin/Bastion Manager Setup"

New top-level section, placed after "Host setup" and before "sshd" in the table of contents (it supersedes the manual steps as the recommended path, but the manual "Host setup" section stays, reframed as "what `setup.sh` and `awsjail-admin` do under the hood" for operators who want to understand or replicate it without the script). Contents:

1. **Prerequisites.** Ubuntu 22.04/24.04, root, a copy of this repo on the box.
2. **Quick start.** `sudo ./setup.sh`, paste the break-glass public key when prompted (or pass `--bastion-admin-pubkey-file`), done.
3. **What `setup.sh` does.** Short bullet list mirroring the steps above — this doc should not require reading the script to understand the host's resulting state.
4. **The break-glass account.** What `bastion-admin` is for, why it's outside the `awsjail` group, how to add a second admin's key (manual `authorized_keys` append), explicit warning never to add it to the `awsjail` group.
5. **Managing tier users with `awsjail-admin`.** Command reference table (`add-user`, `remove-user`, `list-users` with their flags) plus a worked example onboarding a new `dbbackup` user end to end, and one rotating a key, and one offboarding.
6. **Where things live.** A path table matching spec.md's "Interfaces and contracts" section, extended with `/usr/local/sbin/awsjail-admin` and `/etc/ssh/sshd_config.d/awsjail.conf`.
7. **Audit trail note.** Pointer to the `awsjail-admin` syslog schema, tying it to the existing "Logging" section's three-layer model.

## spec.md updates required

- "Interfaces and contracts" gains `awsjail-admin` and its syslog schema, and the sshd drop-in path.
- The Gotchas line about `roles.json` being an unaudited privilege map gets updated: it's still a privilege map, but now has an audit trail when mutated through the sanctioned tool, with a note that direct manual edits (`tee`, an editor) bypass that trail and should be avoided once `awsjail-admin` is in place.
- "Host setup" section (in spec.md, mirroring README) gets a cross-reference to the new section rather than being duplicated.

## Error handling summary

Every new component fails closed, consistent with the existing binary's philosophy:

- `setup.sh`: any step failing (non-zero exit from a command it runs) aborts the script immediately (`set -euo pipefail`) rather than continuing in a half-configured state. `sshd -t` failing never triggers a reload.
- `awsjail-admin`: validation failures produce zero side effects. System-call failures (`useradd`, file writes) abort before later steps in `add-user`'s sequence. Every exit path that isn't success prints a specific, non-generic error to stderr.

## Open questions (not blocking, flagged for the plan/implementation stage)

1. Should `list-users` also scan `awsjail`-group unix accounts for the reverse-drift case (account exists, no `roles.json` entry)? Deferred — not committed to v1.
2. Should there be automated tests for `awsjail-admin`'s validators (username/ARN/region/pubkey regexes, atomic-write helper)? These are pure functions and cheap to test; flagged given the project's general "Minimal" scope choice, but worth a second look since this binary does privileged mutations where a validator bug has real consequences.
3. `setup.sh`'s Go-toolchain-install step assumes `linux/amd64` or `linux/arm64` — no support for other architectures, matching Ubuntu's realistic deployment targets (EC2 x86_64/Graviton).
