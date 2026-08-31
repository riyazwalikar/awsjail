# Credential model and IAM

How credentials flow through awsjail, and the IAM policies the bastion and
tier roles need. For setup of the host itself, see
[setup.md](setup.md); for the threat model, see [security.md](security.md).

## Credential model

- The box has one instance role, `awsjail-bastion-instance-role`, whose only power is `sts:AssumeRole` into the tier roles.
- One IAM role per permission tier (admin, s3-operator, dbbackup, ...). Each tier role's trust policy trusts only the bastion instance role.
- On login, `awsjail` assumes the user's mapped role with `RoleSessionName=<unix user>` and exports the temporary credentials into a clean env for the CLI. Nothing is stored, nothing is printed, and the CLI's own `configure export-credentials` command is blocked at the shell so the session creds cannot be dumped to the terminal.
- Humans hold only an SSH key. Retire the existing per-user access keys after cutover.
- `RoleSessionName` = the unix user, so CloudTrail shows exactly who ran what.

The trust chain is the tier isolation boundary. A user holding tier-A
credentials cannot assume tier-B, because tier-B trusts the instance role,
not tier-A. The only principal that can assume every tier is the instance
role — which is why IMDS protection matters (see
[security.md](security.md#v2-hardening)).

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

## What IAM decides, not the shell

awsjail deliberately does **not** maintain a denylist of AWS APIs. Commands
that mint service-specific tokens or open remote sessions — `sts assume-role`,
`iam create-access-key`, `ecr get-login-password`, `rds generate-db-auth-token`,
`s3 presign`, `ssm start-session`, `ecs execute-command`,
`ec2-instance-connect`, `secretsmanager get-secret-value`, `kms decrypt` — are
allowed by the shell whenever the tier's IAM policy allows them. That is the
capability the administrator granted; scope it in IAM and VPC endpoint
policies, not here.

The single shell-level command block is `aws configure export-credentials`,
because it exists specifically to print the session's own injected STS
credentials — a jail invariant, independent of IAM.
