#!/usr/bin/env bash
set -euo pipefail

BASTION_ADMIN_PUBKEY_FILE=""
SKIP_SSHD_RELOAD=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --bastion-admin-pubkey-file)
      BASTION_ADMIN_PUBKEY_FILE="$2"
      shift 2
      ;;
    --skip-sshd-reload)
      SKIP_SSHD_RELOAD=1
      shift
      ;;
    *)
      echo "unknown flag: $1" >&2
      exit 2
      ;;
  esac
done

if [[ $EUID -ne 0 ]]; then
  echo "setup.sh: must run as root" >&2
  exit 1
fi

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_DIR"

step() { echo "==> $*"; }

# 1. OS check (warn, don't fail)
if [[ -r /etc/os-release ]]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  if [[ "${ID:-}" != "ubuntu" || ! "${VERSION_ID:-}" =~ ^(22\.04|24\.04)$ ]]; then
    echo "setup.sh: warning: this script targets Ubuntu 22.04/24.04, detected ${PRETTY_NAME:-unknown}" >&2
  fi
else
  echo "setup.sh: warning: cannot read /etc/os-release, unknown OS" >&2
fi

# 2. Go toolchain
GO_MIN_VERSION="$(awk '/^go /{print $2; exit}' go.mod)"
NEED_GO=1
GO_BIN=""
if command -v go >/dev/null 2>&1; then
  GO_BIN="go"
elif [[ -x /usr/local/go/bin/go ]]; then
  GO_BIN="/usr/local/go/bin/go"
fi
if [[ -n "$GO_BIN" ]]; then
  CUR_GO="$("$GO_BIN" version | awk '{print $3}' | sed 's/go//')"
  if printf '%s\n%s\n' "$GO_MIN_VERSION" "$CUR_GO" | sort -V -C; then
    NEED_GO=0
    step "go toolchain: $CUR_GO already installed, skipping"
    if [[ "$GO_BIN" == "/usr/local/go/bin/go" ]]; then
      export PATH="/usr/local/go/bin:$PATH"
    fi
  fi
fi
if [[ $NEED_GO -eq 1 ]]; then
  ARCH="$(uname -m)"
  case "$ARCH" in
    x86_64) GOARCH="amd64" ;;
    aarch64) GOARCH="arm64" ;;
    *) echo "setup.sh: unsupported architecture $ARCH" >&2; exit 1 ;;
  esac
  GO_VERSION="$GO_MIN_VERSION"
  TMP_GO_TARBALL="$(mktemp)"
  step "installing Go ${GO_VERSION} (${GOARCH})"
  curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${GOARCH}.tar.gz" -o "$TMP_GO_TARBALL"
  rm -rf /usr/local/go
  tar -C /usr/local -xzf "$TMP_GO_TARBALL"
  rm -f "$TMP_GO_TARBALL"
  export PATH="/usr/local/go/bin:$PATH"
fi

# 3. AWS CLI v2
NEED_AWS=1
if [[ -x /usr/local/bin/aws ]] && /usr/local/bin/aws --version 2>&1 | grep -q "aws-cli/2\."; then
  NEED_AWS=0
  step "aws cli v2: already installed, skipping"
fi
if [[ $NEED_AWS -eq 1 ]]; then
  ARCH="$(uname -m)"
  case "$ARCH" in
    x86_64) AWSARCH="x86_64" ;;
    aarch64) AWSARCH="aarch64" ;;
    *) echo "setup.sh: unsupported architecture $ARCH for aws cli" >&2; exit 1 ;;
  esac
  TMP_AWS_DIR="$(mktemp -d)"
  step "installing AWS CLI v2 (${AWSARCH})"
  curl -fsSL "https://awscli.amazonaws.com/awscli-exe-linux-${AWSARCH}.zip" -o "$TMP_AWS_DIR/awscliv2.zip"
  unzip -q "$TMP_AWS_DIR/awscliv2.zip" -d "$TMP_AWS_DIR"
  "$TMP_AWS_DIR/aws/install" --bin-dir /usr/local/bin --install-dir /usr/local/aws-cli --update
  rm -rf "$TMP_AWS_DIR"
fi

# 4. awsjail group
if getent group awsjail >/dev/null; then
  step "group awsjail: already exists"
else
  groupadd awsjail
  step "group awsjail: created"
fi

# 5. Directories and roles.json
install -d -m 0755 -o root -g root /etc/awsjail
install -d -m 0700 -o root -g root /var/lib/awsjail
if [[ -f /etc/awsjail/roles.json ]]; then
  step "roles.json: already exists, leaving it alone"
else
  echo "{}" > /etc/awsjail/roles.json
  chmod 0644 /etc/awsjail/roles.json
  chown root:root /etc/awsjail/roles.json
  step "roles.json: created empty"
fi

# 6. /etc/shells
if grep -qxF /usr/local/bin/awsjail /etc/shells 2>/dev/null; then
  step "/etc/shells: awsjail already listed"
else
  echo /usr/local/bin/awsjail >> /etc/shells
  step "/etc/shells: added awsjail"
fi

# 7. Build and install binaries
step "building awsjail"
CGO_ENABLED=0 go build -o awsjail .
install -m 0755 -o root -g root awsjail /usr/local/bin/awsjail

step "building awsjail-admin"
CGO_ENABLED=0 go build -o awsjail-admin ./admin
install -m 0700 -o root -g root awsjail-admin /usr/local/sbin/awsjail-admin

# 8. Break-glass account
if id bastion-admin >/dev/null 2>&1; then
  step "bastion-admin: already exists"
else
  useradd -m -G sudo -s /bin/bash bastion-admin
  step "bastion-admin: created"
fi

if [[ -z "$BASTION_ADMIN_PUBKEY_FILE" ]]; then
  echo "Paste the break-glass admin's SSH public key, then press Enter:"
  read -r BASTION_ADMIN_PUBKEY
else
  BASTION_ADMIN_PUBKEY="$(cat "$BASTION_ADMIN_PUBKEY_FILE")"
fi

if ! printf '%s' "$BASTION_ADMIN_PUBKEY" | grep -Eq '^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp[0-9]+) [A-Za-z0-9+/=]+'; then
  echo "setup.sh: that does not look like a valid SSH public key line" >&2
  exit 1
fi

install -d -m 0700 -o bastion-admin -g bastion-admin /home/bastion-admin/.ssh
touch /home/bastion-admin/.ssh/authorized_keys
if grep -qxF "$BASTION_ADMIN_PUBKEY" /home/bastion-admin/.ssh/authorized_keys; then
  step "bastion-admin: key already present"
else
  echo "$BASTION_ADMIN_PUBKEY" >> /home/bastion-admin/.ssh/authorized_keys
  step "bastion-admin: key installed"
fi
chmod 0600 /home/bastion-admin/.ssh/authorized_keys
chown bastion-admin:bastion-admin /home/bastion-admin/.ssh/authorized_keys

# Back up sshd_config before mutating it, so a failed `sshd -t` can be rolled back cleanly.
SSHD_CONFIG_BACKUP="$(mktemp)"
cp /etc/ssh/sshd_config "$SSHD_CONFIG_BACKUP"

# 9. sshd hardening drop-in
cat > /etc/ssh/sshd_config.d/00-awsjail.conf <<'SSHD'
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
SSHD
step "sshd drop-in written to /etc/ssh/sshd_config.d/00-awsjail.conf"

# 10. sftp subsystem
if grep -qE '^\s*Subsystem\s+sftp' /etc/ssh/sshd_config; then
  sed -i -E 's/^(\s*Subsystem\s+sftp.*)$/#\1/' /etc/ssh/sshd_config
  step "sftp subsystem: commented out"
else
  step "sftp subsystem: already disabled or absent"
fi

# 11. Validate and reload
if sshd -t; then
  step "sshd -t: ok"
  rm -f "$SSHD_CONFIG_BACKUP"
  if [[ $SKIP_SSHD_RELOAD -eq 0 ]]; then
    systemctl reload ssh
    step "sshd: reloaded"
  else
    step "sshd: reload skipped (--skip-sshd-reload)"
  fi
else
  echo "setup.sh: sshd -t failed, not reloading. Fix the config above before retrying." >&2
  cp "$SSHD_CONFIG_BACKUP" /etc/ssh/sshd_config
  rm -f /etc/ssh/sshd_config.d/00-awsjail.conf "$SSHD_CONFIG_BACKUP"
  exit 1
fi

step "done"
