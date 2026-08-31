# awsjail Security Fixes and AWS CLI Watch List

**Repository:** https://github.com/riyazwalikar/awsjail  
**Review date:** 2026-08-31

## Purpose

This document is intended to be handed directly to a coding agent.

The goal is **not** to deny legitimate AWS capabilities that a user's IAM role intentionally grants. `awsjail` already relies on IAM roles/tier policies and VPC endpoint policies to determine what AWS resources and APIs a user may access.

The goal of this patch is narrower:

> Preserve the local jail boundary: users authenticate over SSH, the local entry point is `aws`, the user's actual STS credentials should not be directly exportable, the restricted shell must not be bypassable through SSH startup hooks, AWS CLI helper behavior must not turn into arbitrary local process execution, and command auditing should survive interrupted commands.

Commands such as ECR token generation, RDS IAM auth token generation, S3 presigning, SSM sessions, ECS Exec, or `iam create-access-key` are **not automatically vulnerabilities in awsjail**. If a user's IAM role is intentionally allowed to perform those operations, that is the capability granted by the administrator.

---

# Security invariants

The implementation should preserve these properties:

1. A user cannot obtain the STS access key, secret key, and session token that `awsjail` injected into the AWS CLI process.
2. SSH cannot execute user-controlled startup files before `awsjail` starts.
3. A permitted `aws ...` command must not be able to turn into arbitrary local shell/process execution through helper binaries present on the bastion.
4. A command attempt must be logged before control is handed to the AWS CLI.
5. IAM remains the authority for whether a user may call an AWS API.
6. Do **not** create a giant denylist of ordinary AWS APIs just because their result may be sensitive or usable elsewhere.

---

# Fix now

## FIX-01 — Block `aws configure export-credentials`

### Severity

**High**

### Problem

`awsjail` places the assumed-role credentials directly into the AWS CLI child environment:

```text
AWS_ACCESS_KEY_ID
AWS_SECRET_ACCESS_KEY
AWS_SESSION_TOKEN
```

AWS CLI provides the command:

```bash
aws configure export-credentials
```

which deliberately resolves the current credentials and prints them.

For example:

```bash
aws configure export-credentials --format env
```

can print the values injected by `awsjail`.

Other formats are also supported, including `process`, `env-no-export`, `powershell`, `windows-cmd`, and `fish`.

This directly violates the intended property that the temporary STS credentials do not leave the bastion/user-facing CLI process.

AWS reference:

https://docs.aws.amazon.com/cli/latest/reference/configure/export-credentials.html

### Required fix

Explicitly deny the AWS CLI command:

```text
configure export-credentials
```

regardless of output format.

Do **not** block all `aws configure` commands unless there is a separate reason to do so.

The check should happen after parsing the user's command but before `exec.Command()`.

It should tolerate global AWS CLI options being present before, after, or around the command tokens.

A simple safe approach is to reject any parsed AWS command where:

- a token exactly equal to `configure` is present; and
- a later token exactly equal to `export-credentials` is present.

Exact token matching is important. Do not substring-match arbitrary user values.

### Denied examples

```bash
aws configure export-credentials
aws configure export-credentials --format env
aws configure export-credentials --format process
aws --region us-east-1 configure export-credentials --format env
```

### Commands that should remain allowed

Subject to normal behavior/config restrictions:

```bash
aws configure list
aws sts get-caller-identity
aws s3 ls
```

### Logging

A denied credential-export attempt should be logged with an explicit action/reason, for example:

```json
{
  "action": "denied",
  "reason": "credential_export",
  "cmd": "aws configure export-credentials --format env"
}
```

Do not log the credential values themselves.

### Tests

Add unit tests covering at least:

- default format
- `--format env`
- every documented output format
- global option before `configure`
- normal `aws configure list` remains allowed
- normal unrelated AWS commands remain allowed

---

## FIX-02 — Disable `~/.ssh/rc` for jailed users

### Severity

**Critical**

### Problem

The generated sshd configuration currently disables forwarding and user environment injection, but does not disable `PermitUserRC`.

OpenSSH defaults `PermitUserRC` to `yes`.

OpenSSH executes:

```text
~/.ssh/rc
```

before it starts the user's shell/command.

That means the restricted login shell is not the first user-controlled execution boundary.

This matters particularly because jailed Unix users own their home directories. Some legitimate AWS CLI operations can also write local files. For example, a user with appropriate S3 permissions can use the AWS CLI to copy an object to a local path.

A writable `~/.ssh/rc` therefore creates a path where local commands could execute **before `awsjail` starts**.

OpenSSH references:

https://man7.org/linux/man-pages/man5/sshd_config.5.html  
https://man.openbsd.org/sshd.8

### Required fix

Add this inside the `Match Group awsjail` block generated by `setup.sh`:

```text
PermitUserRC no
```

The effective block should contain at least:

```text
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

Do not disable `PermitUserRC` globally if the break-glass account is intentionally meant to retain normal SSH behavior. Scope it to the `awsjail` group.

### Optional cleanup

During setup or user onboarding, it is reasonable to warn if this exists:

```text
/home/<user>/.ssh/rc
```

Do not depend on deleting the file as the security control. `PermitUserRC no` is the control.

### Tests

Add a setup/config test asserting that the generated sshd drop-in contains:

```text
PermitUserRC no
```

If practical in integration tests, verify the effective sshd configuration for a jailed user using `sshd -T`.

---

## FIX-03 — Prevent AWS CLI custom commands from spawning arbitrary local helpers

### Severity

**High**

### Problem

The current AWS CLI child environment contains:

```text
PATH=/usr/local/bin:/usr/bin:/bin
```

Checking only:

```text
argv[0] == "aws"
```

does **not** guarantee that the process tree contains only the AWS CLI.

AWS CLI includes custom commands that intentionally invoke external executables.

Examples include:

- EMR commands that invoke `ssh` / `scp`
- CodeArtifact `login`, which can invoke package-manager binaries such as `npm`, `pip`, `dotnet`, `nuget`, or `swift`
- other CLI customizations/plugins may gain similar behavior over time

The most important concrete case found during review is:

```text
aws emr ssh
```

AWS documents `--ssh-options` as options passed directly to `ssh/scp`.

OpenSSH supports options such as `ProxyCommand`, which can cause local command execution.

Therefore, if `/usr/bin/ssh` is available to the AWS CLI, a command that begins with the permitted word `aws` can cross the local process-execution boundary.

AWS EMR reference:

https://docs.aws.amazon.com/cli/latest/reference/emr/ssh.html

AWS CLI CodeArtifact implementation also contains subprocess execution:

https://github.com/aws/aws-cli/blob/develop/awscli/customizations/codeartifact/login.py

### Required fix

Do not give the AWS CLI child a normal system `PATH`.

Replace:

```text
PATH=/usr/local/bin:/usr/bin:/bin
```

with a dedicated root-owned helper directory that contains no general-purpose executables, for example:

```text
PATH=/usr/local/lib/awsjail/bin
```

`setup.sh` should create the directory:

```text
/usr/local/lib/awsjail/bin
```

with root ownership and non-user-writable permissions.

Example:

```text
root:root 0755
```

Initially it should be empty.

The AWS CLI itself is already executed by absolute path:

```text
/usr/local/bin/aws
```

so it does not need to be discoverable through `PATH`.

### Defense in depth

Also set a non-shell `SHELL` value in the AWS CLI child environment, for example:

```text
SHELL=/usr/sbin/nologin
```

This is defense in depth only. Do not rely on `SHELL` as the primary control.

### Important design rule

Do **not** solve this by building an ever-growing denylist of every AWS command that currently launches a helper.

The structural control should be:

> The AWS CLI child cannot discover arbitrary system executables.

If a future use case genuinely requires a helper, add a deliberately reviewed wrapper/helper into:

```text
/usr/local/lib/awsjail/bin
```

rather than restoring `/usr/bin` or `/bin` to the AWS CLI child's `PATH`.

### Compatibility checks

After changing `PATH`, test common commands including:

```bash
aws sts get-caller-identity
aws s3 ls
aws ec2 describe-instances
aws logs describe-log-groups
aws help
```

`aws help` may have implementation-specific helper dependencies depending on the installed CLI build. If it breaks, do not restore the whole system `PATH`. Either:

- determine the minimal safe helper required; or
- change the built-in `help` behavior/documentation appropriately.

### Tests

Add tests asserting that `buildEnv()`:

- does not contain `/usr/bin`
- does not contain `/bin`
- uses only the dedicated helper path
- includes the expected non-shell `SHELL` value

Also ensure the helper directory is created root-owned/non-writable by jailed users.

---

## FIX-04 — Log command start before executing AWS CLI

### Severity

**Medium**

### Problem

Current flow is effectively:

```text
cmd.Run()
log command + exit status
```

The `awsjail` syslog record is written only after the child exits.

For long-running commands, or if the SSH session/process group receives a terminating signal, the parent process may not reach the post-execution logging call.

`auditd` is a useful backstop, but the application-level claim that every command is recorded should not depend solely on post-execution code.

### Required fix

Write an audit record **before** invoking the AWS CLI child.

Recommended event model:

```text
command_start
command_finish
```

Example start record:

```json
{
  "user": "dbbackup",
  "src": "192.0.2.10",
  "cmd": "aws s3 ls",
  "action": "command_start"
}
```

Example completion record:

```json
{
  "user": "dbbackup",
  "src": "192.0.2.10",
  "cmd": "aws s3 ls",
  "exit": 0,
  "action": "command_finish"
}
```

If compatibility with existing log consumers matters, retain the old final `run` event and add a new pre-exec `command_start` event.

### Signal handling

If practical, improve signal handling so the parent:

1. records `command_start`
2. starts the child
3. forwards relevant termination/interruption signals to the child
4. waits for the child
5. records completion when possible

However, the mandatory security improvement is that the initial command record exists **before** control is handed to the child.

### Tests

Test that:

- the start event is emitted before child execution
- normal completion logs the exit code
- failed `exec` attempts still produce an audit record
- denied commands remain separately logged as denied
- parser failures remain separately logged

---

# Security hardening recommended

## Pin the AWS CLI version actually used by the jail

The README currently says the AWS CLI version is "pinned and predictable", but `setup.sh` currently:

- accepts any installed AWS CLI v2; or
- downloads the generic current AWS CLI v2 installer URL

Because AWS CLI custom commands are part of the effective jail attack surface, upgrades should be deliberate.

Recommended implementation:

- define an exact AWS CLI version
- use a version-specific AWS installer artifact
- verify its expected checksum/signature
- require an explicit source change to upgrade the CLI
- review AWS CLI custom-command changes before bumping the version

This is primarily supply-chain/change-control hardening rather than a currently demonstrated jail escape.

---

# AWS commands and behaviors to watch

## Important

The commands in this section should **not automatically be blocked**.

They are listed because they produce credentials/tokens, open remote sessions/tunnels, write local files, or invoke external tooling.

Whether the user should be able to use them is primarily an **IAM/product-policy decision**.

If the user's assigned role intentionally permits the capability, `awsjail` should generally respect that permission unless it crosses the **local bastion boundary**.

---

## 1. STS role assumption

```bash
aws sts assume-role ...
```

Returns temporary AWS credentials.

This is not inherently an awsjail bug.

If a user's role is not supposed to assume another role, enforce that in IAM/trust policies.

If it is intentionally allowed, the resulting credentials are part of that granted AWS capability.

### Action

**IAM review only. Do not globally block by default.**

---

## 2. IAM access-key creation

```bash
aws iam create-access-key ...
```

Can return a newly created long-lived access key.

Again, this should only work if the user's tier is intentionally granted the required IAM permissions.

### Action

**IAM review only. Do not globally block by default.**

For administrative tiers, this may be legitimate.

---

## 3. ECR authentication token

```bash
aws ecr get-login-password
```

Returns an ECR registry authentication token.

AWS documents the token as valid for 12 hours.

Reference:

https://docs.aws.amazon.com/cli/latest/reference/ecr/get-login-password.html

### Action

**No awsjail fix by default.**

If a user is supposed to administer/use ECR, this is expected functionality.

---

## 4. RDS IAM database authentication token

```bash
aws rds generate-db-auth-token ...
```

Generates an IAM DB authentication token.

Reference:

https://docs.aws.amazon.com/cli/latest/reference/rds/generate-db-auth-token.html

### Action

**No awsjail fix by default.**

If the role is supposed to connect to the DB using IAM authentication, this is expected.

---

## 5. S3 presigned URLs

```bash
aws s3 presign ...
```

Produces a bearer-style presigned URL usable outside the SSH session until expiry, subject to the underlying S3/resource/network policy.

### Action

**No global awsjail block by default.**

Use IAM, bucket policy, VPC endpoint policy, source-network conditions, and object-level authorization according to the environment's requirements.

---

## 6. SSM Session Manager

```bash
aws ssm start-session ...
```

AWS documents that a shell may be launched on the managed node by default.

Reference:

https://docs.aws.amazon.com/cli/latest/reference/ssm/start-session.html

### Action

**Do not automatically classify as a jail escape.**

This is a remote AWS capability granted by IAM.

If the product requirement is merely "no local general-purpose shell on the bastion", SSM may be legitimate.

If the product requirement is "users must never obtain any remote shell", enforce that separately through IAM.

Also note that local Session Manager plugin/helper execution should be constrained by FIX-03.

---

## 7. ECS Exec

Example capability:

```text
aws ecs execute-command
```

Can provide an interactive command/shell inside a container when IAM and ECS configuration permit it.

### Action

**IAM/product-policy decision.**

It is not a local awsjail shell escape by itself.

---

## 8. EC2 Instance Connect

Relevant commands include:

```text
aws ec2-instance-connect ssh
aws ec2-instance-connect open-tunnel
```

AWS documents local forwarding/tunneling behavior for these commands.

References:

https://docs.aws.amazon.com/cli/latest/reference/ec2-instance-connect/ssh.html  
https://docs.aws.amazon.com/cli/latest/reference/ec2-instance-connect/open-tunnel.html

### Action

Two separate considerations:

1. **Local helper execution:** handled structurally by FIX-03.
2. **Whether the user should be allowed to create an EC2 connection/tunnel:** IAM/product-policy decision.

Do not globally deny the AWS API capability merely because it can be used for remote access if that access is intentional.

---

## 9. EMR SSH/SCP convenience commands

Relevant commands include:

```text
aws emr ssh
aws emr socks
aws emr put
aws emr get
```

These AWS CLI customizations can invoke local `ssh`/`scp`.

### Action

**Local process spawning must be controlled by FIX-03.**

Whether users have EMR API permissions remains an IAM decision.

Do not depend only on denying these command names; future CLI customizations may introduce additional helper processes.

---

## 10. CodeArtifact login

```bash
aws codeartifact login ...
```

The AWS CLI customization can invoke package-manager tools such as:

```text
npm
pip
dotnet
nuget
swift
```

It can also write package-manager configuration files.

Reference implementation:

https://github.com/aws/aws-cli/blob/develop/awscli/customizations/codeartifact/login.py

### Action

FIX-03 should prevent arbitrary system helper execution by default.

If CodeArtifact login is a required awsjail use case, explicitly decide which helper binaries/wrappers are permitted and expose only those reviewed helpers through the dedicated awsjail helper directory.

Do not restore a normal `/usr/bin:/bin` PATH.

---

## 11. Local file reads/writes through AWS CLI

AWS CLI supports local file parameters such as:

```text
file://...
fileb://...
```

and commands such as `aws s3 cp` can read from or write to local paths.

This is not automatically a vulnerability. The AWS CLI runs as the jailed Unix user, so normal Unix filesystem permissions still apply.

However, this is why user-controlled SSH startup hooks such as `~/.ssh/rc` must be disabled.

### Action

- FIX-02 removes the important SSH startup bypass.
- Keep the jail session HOME root-owned/unwritable.
- Minimize readable sensitive material on the bastion.
- Continue relying on IAM and VPC endpoint policy for AWS-side exfiltration control.

Do not try to enumerate and deny every AWS API that accepts `file://` input.

---

## 12. Secrets and decrypted values

Commands such as:

```text
aws secretsmanager get-secret-value
aws kms decrypt
```

may intentionally return sensitive data if IAM allows it.

### Action

**Not an awsjail bug.**

If the user is not supposed to obtain that data, fix the IAM policy.

---

# Existing known issue: IMDS pivot after a local jail escape

The repository already documents the IMDS concern correctly:

- `awsjail` itself needs the EC2 instance role in order to assume the user's mapped tier role.
- If a user somehow gains arbitrary local process/network execution, they may be able to query IMDS and obtain the bastion instance-role credentials.
- Those instance-role credentials can potentially assume other tier roles.

The planned root broker / Unix-socket design remains the stronger fix.

This document does not require implementing that broker as part of the four immediate fixes unless explicitly requested.

However, FIX-02 and FIX-03 are important because they reduce practical paths to the local code-execution state that makes the IMDS issue exploitable.

---

# Authorized keys hardening — optional backlog

`awsjail-admin` currently manages:

```text
/home/<user>/.ssh/authorized_keys
```

inside a directory owned by the user.

For a tightly controlled bastion, a stronger design is to move jailed-user authorized keys to a root-owned location such as:

```text
/etc/awsjail/authorized_keys/<username>
```

and configure `AuthorizedKeysFile` appropriately for the `awsjail` group.

Benefits:

- jailed users cannot mutate their own authentication file
- avoids root tooling writing through user-controlled path components
- simplifies key-integrity guarantees

This is defense in depth and is not required to fix the four concrete issues above.

Do not change the `bastion-admin` break-glass behavior unless intentionally redesigning it.

---

# Changes explicitly NOT requested

Do **not** add blanket denials for the following merely because they can return usable credentials/tokens or create remote access:

```text
sts assume-role
iam create-access-key
ecr get-login-password
rds generate-db-auth-token
s3 presign
ssm start-session
ecs execute-command
ec2-instance-connect open-tunnel
secretsmanager get-secret-value
kms decrypt
```

The user's IAM tier is expected to decide whether these APIs are allowed.

Only introduce command-level denial when the AWS CLI operation itself violates a jail invariant independently of IAM.

At present, the clear example is:

```text
aws configure export-credentials
```

because it exposes the credentials `awsjail` itself injected into the child process.

---

# Suggested implementation order

1. Add `PermitUserRC no` to the jailed sshd match block.
2. Block `configure export-credentials`.
3. Replace the AWS CLI child's system `PATH` with a dedicated empty/root-owned helper path and set a non-shell `SHELL`.
4. Emit command-start logs before AWS CLI execution.
5. Add regression tests for all four.
6. Update README security properties and "traps handled" section.
7. Optionally pin the exact AWS CLI release.
8. Keep IMDS broker and root-owned authorized-key storage as separate hardening work unless included in the requested scope.

---

# README wording that should be updated

Avoid absolute claims such as:

```text
only `aws` runs
```

if that statement is meant to describe the entire descendant process tree.

A more accurate property after FIX-03 is:

> `awsjail` only accepts AWS CLI commands as the user entry point, and the AWS CLI runs with a restricted helper PATH so CLI customizations cannot invoke arbitrary system tools.

Also reconsider:

> no AWS keys ever touch a human

After FIX-01, a safer formulation is:

> `awsjail` does not intentionally expose the assumed-role STS credentials to the user and blocks the AWS CLI's direct credential-export command.

This is more defensible than claiming no conceivable AWS functionality can ever emit transferable authentication material. Many AWS services intentionally issue service-specific tokens when IAM permits them.

For networking, distinguish:

> no general Internet egress from the bastion

from:

> no capability generated through an authorized AWS API can ever be used elsewhere

The latter is not generally enforceable solely at the shell layer.

---

# Acceptance criteria

The patch is complete when all of the following are true:

- [ ] `aws configure export-credentials` is denied in every output format.
- [ ] Normal unrelated AWS CLI commands continue to work.
- [ ] `PermitUserRC no` is effective for the `awsjail` SSH group.
- [ ] The AWS CLI child no longer receives `/usr/bin` or `/bin` in `PATH`.
- [ ] The dedicated awsjail helper directory is root-owned and not user-writable.
- [ ] The AWS CLI child has a non-shell `SHELL` value.
- [ ] A command-start audit event is emitted before the AWS CLI process starts.
- [ ] A completion/exit event is emitted when possible.
- [ ] Unit/integration tests cover the new controls.
- [ ] README claims are adjusted to match the actual guarantees.
- [ ] No blanket command blocks are added for AWS capabilities that should instead be governed by IAM.

---

# Source references

- awsjail repository: https://github.com/riyazwalikar/awsjail
- AWS CLI `configure export-credentials`: https://docs.aws.amazon.com/cli/latest/reference/configure/export-credentials.html
- OpenSSH `PermitUserRC`: https://man7.org/linux/man-pages/man5/sshd_config.5.html
- OpenSSH login process / `~/.ssh/rc`: https://man.openbsd.org/sshd.8
- AWS CLI EMR SSH: https://docs.aws.amazon.com/cli/latest/reference/emr/ssh.html
- AWS CLI EC2 Instance Connect SSH: https://docs.aws.amazon.com/cli/latest/reference/ec2-instance-connect/ssh.html
- AWS CLI EC2 Instance Connect tunnel: https://docs.aws.amazon.com/cli/latest/reference/ec2-instance-connect/open-tunnel.html
- AWS CLI SSM Start Session: https://docs.aws.amazon.com/cli/latest/reference/ssm/start-session.html
- AWS CLI ECR login password: https://docs.aws.amazon.com/cli/latest/reference/ecr/get-login-password.html
- AWS CLI RDS auth token: https://docs.aws.amazon.com/cli/latest/reference/rds/generate-db-auth-token.html
- AWS CLI CodeArtifact login implementation: https://github.com/aws/aws-cli/blob/develop/awscli/customizations/codeartifact/login.py
