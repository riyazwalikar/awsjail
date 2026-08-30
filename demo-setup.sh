#!/usr/bin/env bash
#
# demo-setup.sh — stand up the full awsjail demo on EC2 from scratch.
#
# Creates:
#   IAM   awsjail-bastion-instance-role (+ instance profile), tier roles and
#         IAM users for bob (S3FullAccess), alice (AdministratorAccess),
#         mike (SecurityAudit)
#   EC2   Ubuntu 24.04 t3.micro bastion, ssh from your current IP only,
#         IMDSv2 required, instance profile attached
#   Host  awsjail installed via setup.sh, bob/alice/mike onboarded with
#         awsjail-admin, each landing in the jail with their tier role
#   Local SSH keypairs in ./keys (gitignored)
#
# Usage:
#   ./demo-setup.sh             # full setup (idempotent where cheap)
#   ./demo-setup.sh --teardown  # remove everything created in AWS
#
# Env:
#   AWS_PROFILE  (default: myiamadmin)
#   AWS_REGION   (default: us-east-1)
#
set -euo pipefail

export AWS_PROFILE="${AWS_PROFILE:-myiamadmin}"
export AWS_REGION="${AWS_REGION:-us-east-1}"
export AWS_PAGER=""

INSTANCE_TYPE="t3.micro"
KEYS_DIR="keys"
STATE_FILE="demo-state.env"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_DIR"

# demo users: unix/iam name -> managed policy (bash 3.2-safe, no assoc arrays)
DEMO_USERS=(bob alice mike)
tier_policy() {
  case "$1" in
    bob)   echo "arn:aws:iam::aws:policy/AmazonS3FullAccess" ;;
    alice) echo "arn:aws:iam::aws:policy/AdministratorAccess" ;;
    mike)  echo "arn:aws:iam::aws:policy/SecurityAudit" ;;
    *)     die "unknown demo user $1" ;;
  esac
}

step() { printf '\n==> %s\n' "$*"; }
die()  { echo "demo-setup: $*" >&2; exit 1; }

ssh_ub() { ssh -T -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 \
  -i "$KEYS_DIR/bastion-admin" "ubuntu@$PUBLIC_IP" "$@"; }

# ---------------------------------------------------------------------------
if [[ "${1:-}" == "--teardown" ]]; then
  [[ -f "$STATE_FILE" ]] || die "no $STATE_FILE — nothing to tear down"
  # shellcheck disable=SC1090
  . "$STATE_FILE"
  step "terminating instance $INSTANCE_ID"
  aws ec2 terminate-instances --instance-ids "$INSTANCE_ID" >/dev/null || true
  aws ec2 wait instance-terminated --instance-ids "$INSTANCE_ID" || true
  step "deleting security group $SG_ID"
  aws ec2 delete-security-group --group-id "$SG_ID" || true
  step "deleting EC2 key pair awsjail-bastion-admin"
  aws ec2 delete-key-pair --key-name awsjail-bastion-admin || true
  step "removing instance profile"
  aws iam remove-role-from-instance-profile \
    --instance-profile-name awsjail-bastion-instance-profile \
    --role-name awsjail-bastion-instance-role || true
  aws iam delete-instance-profile \
    --instance-profile-name awsjail-bastion-instance-profile || true
  step "deleting tier roles and IAM users"
  for u in "${DEMO_USERS[@]}"; do
    aws iam detach-role-policy --role-name "tier-$u" \
      --policy-arn "$(tier_policy "$u")" || true
    aws iam delete-role --role-name "tier-$u" || true
    aws iam detach-user-policy --user-name "$u" \
      --policy-arn "$(tier_policy "$u")" || true
    aws iam delete-user --user-name "$u" || true
  done
  step "deleting bastion instance role"
  aws iam delete-role-policy --role-name awsjail-bastion-instance-role \
    --policy-name awsjail-bastion-policy || true
  aws iam delete-role --role-name awsjail-bastion-instance-role || true
  rm -f "$STATE_FILE"
  step "teardown done (local ./keys left in place — delete manually if wanted)"
  exit 0
fi

# ---------------------------------------------------------------------------
step "preflight"
command -v aws >/dev/null        || die "aws CLI not found"
command -v ssh-keygen >/dev/null || die "ssh-keygen not found"
ACCT="$(aws sts get-caller-identity --query 'Account' --output text)" \
  || die "sts get-caller-identity failed — check AWS_PROFILE=$AWS_PROFILE"
echo "account: $ACCT  region: $AWS_REGION  profile: $AWS_PROFILE"

# ---------------------------------------------------------------------------
step "IAM: bastion instance role + profile + policy"
WORK="$(mktemp -d)"

cat > "$WORK/ec2-trust.json" <<'EOF'
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}
EOF

if aws iam get-role --role-name awsjail-bastion-instance-role >/dev/null 2>&1; then
  echo "role awsjail-bastion-instance-role: exists"
else
  aws iam create-role --role-name awsjail-bastion-instance-role \
    --assume-role-policy-document "file://$WORK/ec2-trust.json" >/dev/null
  echo "role awsjail-bastion-instance-role: created"
fi

TIER_ARNS=""
for u in "${DEMO_USERS[@]}"; do
  TIER_ARNS="$TIER_ARNS\"arn:aws:iam::${ACCT}:role/tier-${u}\","
done
cat > "$WORK/bastion-policy.json" <<EOF
{"Version":"2012-10-17","Statement":[
{"Effect":"Allow","Action":"sts:AssumeRole","Resource":[${TIER_ARNS%,}]},
{"Effect":"Allow","Action":["logs:CreateLogStream","logs:PutLogEvents"],"Resource":"arn:aws:logs:${AWS_REGION}:${ACCT}:log-group:/awsjail/*"}]}
EOF
aws iam put-role-policy --role-name awsjail-bastion-instance-role \
  --policy-name awsjail-bastion-policy \
  --policy-document "file://$WORK/bastion-policy.json"

if aws iam get-instance-profile \
    --instance-profile-name awsjail-bastion-instance-profile >/dev/null 2>&1; then
  echo "instance profile: exists"
else
  aws iam create-instance-profile \
    --instance-profile-name awsjail-bastion-instance-profile >/dev/null
  echo "instance profile: created"
fi
if aws iam get-instance-profile --instance-profile-name awsjail-bastion-instance-profile \
    --query 'InstanceProfile.Roles[?RoleName==`awsjail-bastion-instance-role`]' \
    --output text | grep -q awsjail; then
  echo "instance profile: role already attached"
else
  aws iam add-role-to-instance-profile \
    --instance-profile-name awsjail-bastion-instance-profile \
    --role-name awsjail-bastion-instance-role
  echo "instance profile: role attached"
fi

# ---------------------------------------------------------------------------
step "IAM: tier roles + IAM users"
cat > "$WORK/tier-trust.json" <<EOF
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::${ACCT}:role/awsjail-bastion-instance-role"},"Action":"sts:AssumeRole"}]}
EOF

for u in "${DEMO_USERS[@]}"; do
  # IAM is eventually consistent: a fresh bastion role can be invisible to
  # CreateRole's principal validation for a few seconds. Retry.
  for attempt in 1 2 3 4 5; do
    if aws iam get-role --role-name "tier-$u" >/dev/null 2>&1; then
      echo "role tier-$u: exists"
      break
    fi
    if aws iam create-role --role-name "tier-$u" \
        --assume-role-policy-document "file://$WORK/tier-trust.json" >/dev/null 2>&1; then
      echo "role tier-$u: created"
      break
    fi
    [[ $attempt -eq 5 ]] && die "could not create role tier-$u"
    echo "role tier-$u: create failed (IAM propagation), retry $attempt/5"
    sleep 5
  done
  aws iam attach-role-policy --role-name "tier-$u" --policy-arn "$(tier_policy "$u")"

  if aws iam get-user --user-name "$u" >/dev/null 2>&1; then
    echo "user $u: exists"
  else
    aws iam create-user --user-name "$u" >/dev/null
    echo "user $u: created"
  fi
  aws iam attach-user-policy --user-name "$u" --policy-arn "$(tier_policy "$u")"
done

# ---------------------------------------------------------------------------
step "local SSH keypairs in $KEYS_DIR/"
mkdir -p "$KEYS_DIR"
chmod 0700 "$KEYS_DIR"
for k in bastion-admin "${DEMO_USERS[@]}"; do
  if [[ -f "$KEYS_DIR/$k" ]]; then
    echo "key $k: exists"
  else
    ssh-keygen -t ed25519 -f "$KEYS_DIR/$k" -N "" -C "awsjail-$k" -q
    echo "key $k: generated"
  fi
done
grep -q '^keys/$' .gitignore 2>/dev/null || echo 'keys/' >> .gitignore

# ---------------------------------------------------------------------------
step "EC2: key pair + security group (ssh from current IP only)"
if aws ec2 describe-key-pairs --key-names awsjail-bastion-admin >/dev/null 2>&1; then
  echo "key pair: exists"
else
  aws ec2 import-key-pair --key-name awsjail-bastion-admin \
    --public-key-material "fileb://$KEYS_DIR/bastion-admin.pub" >/dev/null
  echo "key pair: imported"
fi

MY_IP="$(curl -fsS https://ifconfig.me)/32" || die "could not detect public IP"
echo "your IP: $MY_IP"

SG_ID="$(aws ec2 describe-security-groups \
  --filters "Name=group-name,Values=awsjail-bastion-sg" \
  --query 'SecurityGroups[0].GroupId' --output text)"
if [[ "$SG_ID" == "None" || -z "$SG_ID" ]]; then
  SG_ID="$(aws ec2 create-security-group --group-name awsjail-bastion-sg \
    --description "awsjail bastion: ssh from admin ip only" \
    --query 'GroupId' --output text)"
  echo "security group: created $SG_ID"
else
  echo "security group: exists $SG_ID"
fi
# ignore "rule already exists" — older AWSCLIs have no --cli-input-json skip flag for this
aws ec2 authorize-security-group-ingress --group-id "$SG_ID" \
  --protocol tcp --port 22 --cidr "$MY_IP" >/dev/null 2>&1 || true

SUBNET_ID="$(aws ec2 describe-subnets --filters "Name=default-for-az,Values=true" \
  --query 'Subnets[0].SubnetId' --output text)"
[[ -n "$SUBNET_ID" && "$SUBNET_ID" != "None" ]] || die "no default subnet found"

# ---------------------------------------------------------------------------
step "EC2: instance"
if [[ -f "$STATE_FILE" ]]; then
  # shellcheck disable=SC1090
  . "$STATE_FILE"
  STATE="$(aws ec2 describe-instances --instance-ids "$INSTANCE_ID" \
    --query 'Reservations[0].Instances[0].State.Name' --output text 2>/dev/null || echo gone)"
  if [[ "$STATE" == "running" || "$STATE" == "pending" ]]; then
    echo "instance $INSTANCE_ID: $STATE, reusing"
  else
    echo "instance $INSTANCE_ID: $STATE, launching a new one"
    rm -f "$STATE_FILE"
  fi
fi

if [[ ! -f "$STATE_FILE" ]]; then
  AMI_ID="$(aws ssm get-parameter \
    --name /aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id \
    --query 'Parameter.Value' --output text)"
  echo "ami: $AMI_ID (Ubuntu 24.04)"
  INSTANCE_ID="$(aws ec2 run-instances --image-id "$AMI_ID" \
    --instance-type "$INSTANCE_TYPE" \
    --key-name awsjail-bastion-admin \
    --subnet-id "$SUBNET_ID" \
    --security-group-ids "$SG_ID" \
    --associate-public-ip-address \
    --iam-instance-profile Name=awsjail-bastion-instance-profile \
    --metadata-options 'HttpTokens=required,HttpPutResponseHopLimit=1' \
    --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=awsjail-bastion}]' \
    --query 'Instances[0].InstanceId' --output text)"
  echo "instance: $INSTANCE_ID"
fi

aws ec2 wait instance-running --instance-ids "$INSTANCE_ID"
PUBLIC_IP="$(aws ec2 describe-instances --instance-ids "$INSTANCE_ID" \
  --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)"
cat > "$STATE_FILE" <<EOF
INSTANCE_ID=$INSTANCE_ID
SG_ID=$SG_ID
PUBLIC_IP=$PUBLIC_IP
EOF
echo "public IP: $PUBLIC_IP"

# ---------------------------------------------------------------------------
step "host: wait for ssh, ship repo, run setup.sh"
for _ in $(seq 1 30); do
  nc -z -w 2 "$PUBLIC_IP" 22 2>/dev/null && break
  sleep 5
done
nc -z -w 2 "$PUBLIC_IP" 22 || die "ssh port never opened on $PUBLIC_IP"

# NOTE: extract into ~/awsjail-src, never a dir named "awsjail" —
# `go build -o awsjail` in setup.sh would collide with it.
TARBALL="$WORK/awsjail-repo.tgz"
tar czf "$TARBALL" --exclude='.git' --exclude='keys' --exclude='.remember' \
  --exclude='.claude' --exclude='demo-state.env' \
  --exclude='awsjail' --exclude='awsjail-admin' \
  -C "$REPO_DIR" .

# sftp gets killed by setup.sh, so pipe everything over ssh (works before and after)
ssh_ub 'cat > /tmp/awsjail-repo.tgz' < "$TARBALL"
ssh_ub 'cat > /tmp/bastion-admin.pub' < "$KEYS_DIR/bastion-admin.pub"
ssh_ub 'rm -rf ~/awsjail-src && mkdir -p ~/awsjail-src &&
        tar xzf /tmp/awsjail-repo.tgz -C ~/awsjail-src 2>/dev/null;
        sudo apt-get update -qq && sudo apt-get install -y -qq unzip >/dev/null 2>&1;
        sudo ~/awsjail-src/setup.sh --bastion-admin-pubkey-file /tmp/bastion-admin.pub'

# break-glass admin needs working sudo; the account is created passwordless,
# so grant NOPASSWD (single-purpose demo box)
ssh_ub "echo 'bastion-admin ALL=(ALL) NOPASSWD:ALL' | sudo tee /etc/sudoers.d/90-bastion-admin >/dev/null && sudo chmod 0440 /etc/sudoers.d/90-bastion-admin"
echo "bastion-admin: NOPASSWD sudo granted"

# ---------------------------------------------------------------------------
step "host: onboard demo users"
for u in "${DEMO_USERS[@]}"; do
  ssh_ub "cat > /tmp/$u.pub" < "$KEYS_DIR/$u.pub"
  ssh_ub "sudo awsjail-admin add-user --username $u \
    --role-arn arn:aws:iam::${ACCT}:role/tier-$u \
    --region $AWS_REGION --pubkey-file /tmp/$u.pub"
done
ssh_ub 'sudo awsjail-admin list-users'

# ---------------------------------------------------------------------------
step "verify: jail rejects non-aws, assumes the right tier role per user"
FAIL=0
for u in "${DEMO_USERS[@]}"; do
  ARN="$(ssh -T -o StrictHostKeyChecking=accept-new -i "$KEYS_DIR/$u" \
    "$u@$PUBLIC_IP" 'aws sts get-caller-identity --query Arn --output text' 2>/dev/null || true)"
  if [[ "$ARN" == "arn:aws:sts::${ACCT}:assumed-role/tier-${u}/${u}" ]]; then
    echo "$u: OK ($ARN)"
  else
    echo "$u: FAILED (got: ${ARN:-no output})"
    FAIL=1
  fi
done
REJECT="$(ssh -T -i "$KEYS_DIR/bob" "bob@$PUBLIC_IP" 'id' 2>/dev/null || true)"
[[ "$REJECT" == *"command not found"* ]] \
  && echo "jail rejection: OK ($REJECT)" \
  || { echo "jail rejection: FAILED (got: $REJECT)"; FAIL=1; }

# ---------------------------------------------------------------------------
cat <<EOF

============================================================
awsjail demo is up.

  instance : $INSTANCE_ID ($INSTANCE_TYPE, $AWS_REGION)
  ssh from : $MY_IP
  ip       : $PUBLIC_IP

Try it:
  ssh -i keys/bob    bob@$PUBLIC_IP        # S3 tier
  ssh -i keys/alice  alice@$PUBLIC_IP      # admin tier
  ssh -i keys/mike   mike@$PUBLIC_IP       # security-audit tier
  ssh -i keys/bastion-admin bastion-admin@$PUBLIC_IP   # break-glass shell

Notes:
  - scp/sftp is disabled box-wide by design; copy files with:
      ssh -i keys/bastion-admin ubuntu@$PUBLIC_IP 'cat > /remote/path' < local
  - admin tasks: ssh ubuntu@ (or bastion-admin@) then: sudo awsjail-admin list-users
  - test setup only: open egress, no VPC endpoints (README describes the
    full no-internet network model)

Tear down:
  ./demo-setup.sh --teardown
============================================================
EOF
[[ $FAIL -eq 0 ]] || die "one or more verification checks failed"
