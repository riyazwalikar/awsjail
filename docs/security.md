# Security: logging, network, caveats, and hardening

The security-facing details of awsjail: what is logged, what the network
must guarantee, which traps the design handles, and the known limitations
you should understand before relying on it. For the credential model, see
[iam.md](iam.md); for host provisioning, see [setup.md](setup.md).

## Contents

- [Logging](#logging)
- [Network (no internet from the terminal)](#network-no-internet-from-the-terminal)
- [Traps this design already handles](#traps-this-design-already-handles)
- [Known limitations and caveats](#known-limitations-and-caveats)
- [v2 hardening](#v2-hardening)

## Logging

Three layers:

- **awsjail -> syslog (authpriv).** Each command produces two JSON events:
  `command_start` *before* the CLI process is spawned and `command_finish`
  with its exit code after — so the audit record exists even if the session
  is killed mid-command. Fields: `{"user","src","cmd","exit","action"}` plus
  an optional `reason` (e.g. `credential_export` on a denied export attempt).
  Denied and unparseable lines are logged as `denied` / `parse_error` and
  never reach the CLI. Ship the auth log to CloudWatch with the agent, into
  a log group the bastion users have no write access to.
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

This guarantees *no general Internet egress from the bastion*. It does not —
and cannot, at the shell layer — guarantee that no capability minted through
an authorized AWS API (a presigned URL, an ECR token) is ever usable
elsewhere. Scope that with IAM conditions, resource policies, and endpoint
policies.

Even if a user reads their session creds out of the env, no egress means they
can't be used off the box, and the creds are only the user's own scoped role.

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
- `aws configure export-credentials` — the CLI's built-in "print my current
  credentials" command — is denied at the shell in every output format, so the
  assumed-role STS creds injected into the child stay out of the terminal.
- The AWS CLI child's `PATH` is a single root-owned directory
  (`/usr/local/lib/awsjail/bin`) that starts empty, so CLI customizations that
  spawn helpers (EMR `ssh`/`scp`, CodeArtifact's `npm`/`pip`/`dotnet`, the SSM
  Session Manager plugin) can't resolve arbitrary system binaries. `SHELL` is
  `nologin` as defense in depth.
- `PermitUserRC no` in the sshd `Match Group awsjail` block, so a
  user-writable `~/.ssh/rc` can't run commands before `awsjail` starts.
- Auditing doesn't depend on the child exiting cleanly: `command_start` is
  logged before the CLI runs, `command_finish` with the exit code after, and
  termination signals are forwarded to the child.

## Known limitations and caveats

Read these before an audit finds them for you.

- **`--endpoint-url` is open.** `aws --endpoint-url http://target ...` points
  the SDK at an arbitrary endpoint. No egress stops the internet case, but
  link-local and in-VPC targets are reachable — an SSRF/pivot primitive.
  Blocking it at the shell is on the roadmap.
- **IMDS is only softly fenced.** The instance role (which can assume every
  tier) is reachable at the network layer, and `AWS_EC2_METADATA_DISABLED` is
  not set. No known path coerces a single `aws` invocation onto the instance
  role — the env creds win precedence and the locked config can't be
  redirected — but that rests on CLI behavior, not a hard block. See
  [v2 hardening](#v2-hardening) for the broker design that closes it.
- **Session credentials expire after 1 hour** and the REPL does not
  re-assume. Long sessions start returning `ExpiredToken`. Raise
  `--duration-seconds` up to the role's max, or add re-assume-on-expiry.
- **`roles.json` is a privilege map.** If it is ever writable by a non-root
  user, that user can promote themselves. Keep it `0644` root-owned.
- **`aws s3 cp file://` reads anything the unix user can read.** Scope tier
  S3 access and pin buckets in the endpoint policy. Do not co-locate anything
  sensitive on the bastion.
- **Exfil through AWS is an IAM problem.** "No internet" does not stop
  `aws s3 cp /etc/passwd s3://theirbucket` if the role allows it. Scope every
  tier role to its resources, deny cross-account, and pin buckets/accounts in
  the VPC endpoint policies.
- **A broken syslog locks users out.** awsjail exits if it cannot open
  syslog — correct for an audit tool, but know it before you page yourself
  at 2am.
- **Service-specific tokens are not credential leaks.** ECR login passwords,
  RDS auth tokens, presigned URLs, SSM/ECS sessions are intentionally issued
  when IAM permits them. Whether a user may mint them is an IAM decision;
  awsjail does not block them (see
  [iam.md](iam.md#what-iam-decides-not-the-shell)).
- **AWS CLI version is not pinned.** `setup.sh` accepts any installed CLI v2
  or fetches the current release. The CLI's custom commands are part of the
  jail's attack surface, so pin an exact release, verify its checksum, and
  review custom-command changes before upgrading.

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
2. **Root-owned authorized keys.** Today `awsjail-admin` manages
   `/home/<user>/.ssh/authorized_keys` inside a user-owned directory. A
   stronger design moves jailed-user keys to a root-owned location such as
   `/etc/awsjail/authorized_keys/<username>` with `AuthorizedKeysFile` set for
   the `awsjail` group, so users cannot mutate their own authentication file.
3. **Session TTL.** Creds are 1h (`sessionTTL`). For longer sessions raise
   `--duration-seconds` up to the role's max session duration, or add
   re-assume-on-expiry to the REPL loop.
4. **AWS CLI pinning.** Define an exact CLI version, use the versioned
   installer artifact, verify its checksum/signature, and require an explicit
   source change to upgrade.
