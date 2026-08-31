# Setup and administration

Everything needed to provision the bastion host and manage tier users. For
what the design is and why, see the [README](../README.md).

## Contents

- [Build](#build)
- [Host setup](#host-setup)
- [Admin/Bastion Manager Setup](#adminbastion-manager-setup)
- [sshd](#sshd)

## Build

Stdlib only, no external modules. Build static so `LD_PRELOAD` can't touch it.

```
CGO_ENABLED=0 go build -o awsjail .
install -m 0755 awsjail /usr/local/bin/awsjail
```

The box needs the aws CLI at `/usr/local/bin/aws`. Region is per-user, set in
`roles.json` (see [Host setup](#host-setup)), not a build-time const.

## Host setup

```
groupadd awsjail
useradd -m -G awsjail -s /usr/local/bin/awsjail dbbackup   # new user
usermod -s /usr/local/bin/awsjail -aG awsjail existinguser # existing user
echo /usr/local/bin/awsjail >> /etc/shells

install -d -m 0700 -o root -g root /var/lib/awsjail         # session HOME, root-owned
install -d -m 0755 -o root -g root /usr/local/lib/awsjail/bin # the AWS CLI child's only PATH entry; stays empty
install -d -m 0755 /etc/awsjail

# unix user -> tier role ARN + region (like a profile in ~/.aws/config)
tee /etc/awsjail/roles.json >/dev/null <<'JSON'
{
  "dbbackup": {"role_arn": "arn:aws:iam::123456789012:role/tier-dbbackup",     "region": "ap-south-1"},
  "s3ops":    {"role_arn": "arn:aws:iam::123456789012:role/tier-s3-operator", "region": "ap-south-1"},
  "admin1":   {"role_arn": "arn:aws:iam::123456789012:role/tier-admin",       "region": "us-east-1"}
}
JSON
chmod 0644 /etc/awsjail/roles.json
```

Put each user's SSH public key in their `~/.ssh/authorized_keys` as usual.

## Admin/Bastion Manager Setup

The steps in [Host setup](#host-setup) above are what happens under the hood. In practice, do this instead.

### Prerequisites

- Ubuntu 22.04 or 24.04 LTS.
- Root access.
- A copy of this repo on the box (`git clone`, `scp`, or however you already move files there).

### Quick start

```
sudo ./setup.sh
```

You'll be prompted to paste a public key for the break-glass admin account.
Pass `--bastion-admin-pubkey-file /path/to/key.pub` instead if you're running
this non-interactively, and `--skip-sshd-reload` if you want to review
`/etc/ssh/sshd_config.d/00-awsjail.conf` before it takes effect.

### What `setup.sh` does

- Installs Go (official tarball) and the AWS CLI v2 — pinned to an exact
  version (`AWS_CLI_VERSION` in `setup.sh`), downloaded from the
  version-specific AWS URL and verified against an embedded SHA256 — never
  via `apt` and never "whatever is latest". If a different CLI version is on
  the box, it is replaced with the pinned one. To upgrade: bump
  `AWS_CLI_VERSION`, refresh both per-arch SHA256 values, and review the
  release's custom-command changes before rolling out.
- Creates the `awsjail` group, `/etc/awsjail`, `/var/lib/awsjail`, the
  root-owned helper-PATH directory `/usr/local/lib/awsjail/bin`, and an
  empty `/etc/awsjail/roles.json` if one doesn't already exist. Never
  overwrites an existing `roles.json`.
- Registers `/usr/local/bin/awsjail` in `/etc/shells`.
- Builds and installs both binaries: `awsjail` to `/usr/local/bin/awsjail`
  (0755), `awsjail-admin` to `/usr/local/sbin/awsjail-admin` (0700,
  root-only).
- Creates the break-glass account `bastion-admin` and installs the pubkey
  you provide.
- Writes the sshd hardening as a drop-in at
  `/etc/ssh/sshd_config.d/00-awsjail.conf`, comments out the sftp subsystem,
  runs `sshd -t`, and reloads sshd only if that passes.

Every step checks current state first, so re-running `setup.sh` on an
already-provisioned host is safe.

### The break-glass account

`bastion-admin` is a normal, sudo-capable SSH account, deliberately outside
the `awsjail` group — if `awsjail` itself is ever broken, this is how you
get onto the box to fix it. It gets full, unrestricted SSH (no forwarding
lockdown), because it's the account that does real troubleshooting.

**Never add `bastion-admin` to the `awsjail` group** — that would put it
under the `Match Group awsjail` restriction and defeat its purpose.

Its `authorized_keys` accepts multiple keys (append, not overwrite) if more
than one admin needs break-glass access over the life of the host. To add
another admin's key later:

```
echo "ssh-ed25519 AAAA... newadmin@laptop" >> /home/bastion-admin/.ssh/authorized_keys
```

### Managing tier users with `awsjail-admin`

`awsjail-admin` is root-only (0700, `/usr/local/sbin`) and replaces the
manual `useradd`/`roles.json`/`authorized_keys` steps in
[Host setup](#host-setup) with validated, atomic, audited operations. Run
it via `sudo` so its audit log records who ran it.

| Command | Flags | Does |
| --- | --- | --- |
| `add-user` | `--username`, `--role-arn`, `--region`, `--pubkey-file` | Creates the unix account if needed (or heals its shell/group if it drifted), upserts its `roles.json` entry, installs the key. Re-run with a new `--pubkey-file` to rotate a key. |
| `remove-user` | `--username` | Removes the `roles.json` entry and clears `authorized_keys`. Does not delete the unix account or home directory. |
| `list-users` | none | Lists every mapped user with role ARN, region, key fingerprint, and a status flag for drift (`no-key`, `key-parse-error`). |

Onboard a new tier user:

```
sudo awsjail-admin add-user \
  --username dbbackup \
  --role-arn arn:aws:iam::123456789012:role/tier-dbbackup \
  --region ap-south-1 \
  --pubkey-file dbbackup.pub
```

Rotate their key:

```
sudo awsjail-admin add-user \
  --username dbbackup \
  --role-arn arn:aws:iam::123456789012:role/tier-dbbackup \
  --region ap-south-1 \
  --pubkey-file dbbackup-new.pub
```

Offboard them:

```
sudo awsjail-admin remove-user --username dbbackup
```

Check the current state of every tier user:

```
sudo awsjail-admin list-users
```

### Where things live

| Path | Owner:mode | What |
| --- | --- | --- |
| `/usr/local/bin/awsjail` | root:root, 0755 | The jail binary. |
| `/usr/local/sbin/awsjail-admin` | root:root, 0700 | The admin binary. Root-only by path convention and file mode. |
| `/etc/awsjail/roles.json` | root:root, 0644 | Username -> `{role_arn, region}` map. Managed by `awsjail-admin`; manual edits bypass the audit trail. |
| `/var/lib/awsjail` | root:root, 0700 | Session `HOME` for the jail. |
| `/usr/local/lib/awsjail/bin` | root:root, 0755 | The only `PATH` entry the AWS CLI child gets. Empty by default; add only deliberately reviewed helpers. |
| `/etc/ssh/sshd_config.d/00-awsjail.conf` | root:root | sshd hardening drop-in, regenerated by `setup.sh`. |
| `/home/bastion-admin` | bastion-admin:bastion-admin | Break-glass account home. |

### Audit trail

Every `add-user` and `remove-user` writes one JSON line to syslog facility
`authpriv`, tag `awsjail-admin`: `{"actor", "action", "target", "result"}`,
where `actor` is whoever ran `sudo`. This sits alongside the three logging
layers in [Logging](security.md#logging) — it's the record of who provisioned
or deprovisioned access, not of what a session did with that access.

## sshd

This is a dedicated bastion, so kill sftp box-wide and disable all forwarding. sftp uses the ssh subsystem, not the login shell, so leaving it on is a full bypass of the jail.

`/etc/ssh/sshd_config`:

```
PubkeyAuthentication yes
PasswordAuthentication no
PermitRootLogin no
PermitUserEnvironment no

# Remove/comment the sftp subsystem on this host:
#Subsystem sftp /usr/lib/openssh/sftp-server

Match Group awsjail
    PermitTTY yes
    X11Forwarding no
    AllowTcpForwarding no
    AllowAgentForwarding no
    AllowStreamLocalForwarding no
    PermitTunnel no
    PermitOpen none
    PermitUserRC no
```

`PermitUserRC no` matters: OpenSSH would otherwise run `~/.ssh/rc` *before* the login shell starts, and jailed users own their home directories (and can write files there via `aws s3 cp`) — so without this, user-controlled commands could execute before `awsjail` ever runs. It is scoped to the `awsjail` group so `bastion-admin` keeps normal SSH behavior.

`sshd -t && systemctl reload ssh`. Confirm there's no `AcceptEnv *` anywhere; the default accepts no client env, which is what you want (it stops a client setting `LD_PRELOAD`, `AWS_PROFILE`, `AWS_PAGER`, etc).
