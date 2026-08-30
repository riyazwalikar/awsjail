# Admin/Bastion Manager Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a root-only `awsjail-admin` binary for managing tier users, an idempotent `setup.sh` Ubuntu bootstrap script, a break-glass admin account, and the README/spec.md docs for all three.

**Architecture:** `awsjail-admin` is a second `package main` in `admin/`, built from the same `go.mod` as the existing `awsjail` binary. Its logic is split into small, independently testable files (`roles.go` for `roles.json` I/O, `validate.go` for input validation, `keys.go` for SSH key file handling, `account.go` for unix account management, `audit.go` for syslog audit lines) with `main.go` doing only flag parsing and orchestration. `setup.sh` is a single idempotent bash script that installs prerequisites, builds both binaries, and configures the host.

**Tech Stack:** Go (stdlib only, matching the existing binary), bash (`setup.sh`), Markdown (README.md, spec.md).

**Spec:** `docs/superpowers/specs/2026-08-29-admin-bastion-manager-design.md`

## Global Constraints

- Module: `github.com/riyazwalikar/awsjail` (existing `go.mod`, `go 1.26.4`). `admin/` is a second `package main` in the same module — no new `go.mod`.
- Stdlib only, no external modules — same constraint as `awsjail.go`.
- Both binaries build `CGO_ENABLED=0`.
- `roles.json` path is fixed: `/etc/awsjail/roles.json` (matches `awsjail.go`'s `roleMapPath` const).
- `awsjail-admin` installs to `/usr/local/sbin/awsjail-admin`, mode `0700`, owner `root:root`.
- `remove-user` never calls `userdel` — unix account and home directory are left in place.
- Break-glass username is fixed: `bastion-admin`, group `sudo`, shell `/bin/bash`, **not** a member of the `awsjail` group.
- `setup.sh` targets Ubuntu 22.04/24.04, installs Go and AWS CLI v2 via official upstream artifacts (not `apt`), and is idempotent — safe to re-run.
- No test coverage is expected for `setup.sh` itself (bash, requires a real Ubuntu host) or for `account.go`'s `ensureUnixAccount` (requires root + real `useradd`/`usermod`, and this plan is executed on macOS where those binaries don't exist). Everything else gets unit tests.

---

### Task 1: `roles.json` atomic I/O (`admin/roles.go`)

**Files:**
- Create: `admin/roles.go`
- Test: `admin/roles_test.go`

**Interfaces:**
- Produces: `type roleEntry struct { RoleArn string; Region string }` (JSON tags `role_arn`, `region`); `func loadRoles(path string) (map[string]roleEntry, error)`; `func saveRolesAtomic(path string, m map[string]roleEntry) error`; `func upsertRole(path, username string, entry roleEntry) error`; `func deleteRole(path, username string) (bool, error)` — second return is whether the username was present.

- [ ] **Step 1: Write the failing tests**

```go
// admin/roles_test.go
package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestUpsertAndLoadRoles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "roles.json")

	if err := upsertRole(path, "dbbackup", roleEntry{RoleArn: "arn:aws:iam::123456789012:role/tier-dbbackup", Region: "ap-south-1"}); err != nil {
		t.Fatalf("upsertRole: %v", err)
	}

	m, err := loadRoles(path)
	if err != nil {
		t.Fatalf("loadRoles: %v", err)
	}
	got, ok := m["dbbackup"]
	if !ok {
		t.Fatalf("dbbackup missing from roles map")
	}
	if got.RoleArn != "arn:aws:iam::123456789012:role/tier-dbbackup" || got.Region != "ap-south-1" {
		t.Fatalf("unexpected entry: %+v", got)
	}
}

func TestUpsertOverwritesExisting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "roles.json")
	if err := upsertRole(path, "u", roleEntry{RoleArn: "arn:aws:iam::123456789012:role/a", Region: "us-east-1"}); err != nil {
		t.Fatalf("first upsertRole: %v", err)
	}
	if err := upsertRole(path, "u", roleEntry{RoleArn: "arn:aws:iam::123456789012:role/b", Region: "eu-west-1"}); err != nil {
		t.Fatalf("second upsertRole: %v", err)
	}

	m, err := loadRoles(path)
	if err != nil {
		t.Fatalf("loadRoles: %v", err)
	}
	if m["u"].RoleArn != "arn:aws:iam::123456789012:role/b" {
		t.Fatalf("expected overwrite, got %+v", m["u"])
	}
}

func TestDeleteRolePresentAndAbsent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "roles.json")
	if err := upsertRole(path, "u", roleEntry{RoleArn: "arn:aws:iam::123456789012:role/a", Region: "us-east-1"}); err != nil {
		t.Fatalf("upsertRole: %v", err)
	}

	removed, err := deleteRole(path, "u")
	if err != nil || !removed {
		t.Fatalf("expected removal, got removed=%v err=%v", removed, err)
	}

	removed, err = deleteRole(path, "u")
	if err != nil || removed {
		t.Fatalf("expected no-op on absent user, got removed=%v err=%v", removed, err)
	}
}

func TestDeleteRoleMissingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "roles.json")
	removed, err := deleteRole(path, "u")
	if err != nil || removed {
		t.Fatalf("expected false,nil on missing file, got removed=%v err=%v", removed, err)
	}
}

func TestSaveRolesAtomicWritesReadableFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "roles.json")
	if err := upsertRole(path, "u", roleEntry{RoleArn: "arn:aws:iam::123456789012:role/a", Region: "us-east-1"}); err != nil {
		t.Fatalf("upsertRole: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read after upsert: %v", err)
	}
	if len(b) == 0 {
		t.Fatalf("expected non-empty roles.json")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd admin && go test ./... -run . -v`
Expected: FAIL — `roleEntry`, `loadRoles`, `saveRolesAtomic`, `upsertRole`, `deleteRole` undefined.

- [ ] **Step 3: Write the implementation**

```go
// admin/roles.go
package main

import (
	"encoding/json"
	"os"
	"path/filepath"
)

type roleEntry struct {
	RoleArn string `json:"role_arn"`
	Region  string `json:"region"`
}

func loadRoles(path string) (map[string]roleEntry, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	m := map[string]roleEntry{}
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// saveRolesAtomic writes m to path via a temp file in the same directory
// followed by rename, so a crash mid-write never leaves a torn roles.json.
func saveRolesAtomic(path string, m map[string]roleEntry) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".roles-*.json.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath) // no-op once renamed
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpPath, 0644); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

func upsertRole(path, username string, entry roleEntry) error {
	m, err := loadRoles(path)
	if err != nil {
		if os.IsNotExist(err) {
			m = map[string]roleEntry{}
		} else {
			return err
		}
	}
	m[username] = entry
	return saveRolesAtomic(path, m)
}

// deleteRole removes username from roles.json. The bool return reports
// whether username was present; removing an absent username is not an error.
func deleteRole(path, username string) (bool, error) {
	m, err := loadRoles(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	if _, ok := m[username]; !ok {
		return false, nil
	}
	delete(m, username)
	return true, saveRolesAtomic(path, m)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd admin && go test ./... -v`
Expected: PASS for all five tests.

- [ ] **Step 5: Commit**

```bash
git add admin/roles.go admin/roles_test.go
git commit -m "Add roles.json atomic load/upsert/delete for awsjail-admin"
```

---

### Task 2: Input validators (`admin/validate.go`)

**Files:**
- Create: `admin/validate.go`
- Test: `admin/validate_test.go`

**Interfaces:**
- Consumes: nothing from Task 1.
- Produces: `type parsedKey struct { Type, Blob, Comment string }`; `func validateUsername(u string) error`; `func validateRoleArn(arn string) error`; `func validateRegion(r string) error`; `func parsePubkeyFile(path string) (parsedKey, error)`. Task 3 and Task 6 depend on all four.

- [ ] **Step 1: Write the failing tests**

```go
// admin/validate_test.go
package main

import (
	"os"
	"testing"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("writeFile: %v", err)
	}
}

func TestValidateUsername(t *testing.T) {
	cases := map[string]bool{
		"dbbackup": true,
		"s3ops":    true,
		"admin1":   true,
		"":         false,
		"Admin":    false,
		"a b":      false,
		"1admin":   false,
		"toolongusernamethatexceedsthirtytwocharslimit": false,
	}
	for u, want := range cases {
		err := validateUsername(u)
		if (err == nil) != want {
			t.Errorf("validateUsername(%q) valid=%v want=%v (err=%v)", u, err == nil, want, err)
		}
	}
}

func TestValidateRoleArn(t *testing.T) {
	cases := map[string]bool{
		"arn:aws:iam::123456789012:role/tier-dbbackup":              true,
		"arn:aws:iam::123456789012:role/service-role/tier-dbbackup": true,
		"arn:aws:iam::12345:role/tier-dbbackup":                     false,
		"not-an-arn":                                                false,
		"arn:aws:iam::123456789012:user/notarole":                   false,
	}
	for arn, want := range cases {
		err := validateRoleArn(arn)
		if (err == nil) != want {
			t.Errorf("validateRoleArn(%q) valid=%v want=%v (err=%v)", arn, err == nil, want, err)
		}
	}
}

func TestValidateRegion(t *testing.T) {
	cases := map[string]bool{
		"ap-south-1": true,
		"us-east-1":  true,
		"eu-west-2":  true,
		"apsouth1":   false,
		"AP-SOUTH-1": false,
		"":           false,
	}
	for r, want := range cases {
		err := validateRegion(r)
		if (err == nil) != want {
			t.Errorf("validateRegion(%q) valid=%v want=%v (err=%v)", r, err == nil, want, err)
		}
	}
}

func TestParsePubkeyFileValid(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/key.pub"
	writeFile(t, path, "ssh-ed25519 dGVzdC1rZXktYmxvYg== dbbackup@laptop\n")

	pk, err := parsePubkeyFile(path)
	if err != nil {
		t.Fatalf("parsePubkeyFile: %v", err)
	}
	if pk.Type != "ssh-ed25519" || pk.Blob != "dGVzdC1rZXktYmxvYg==" || pk.Comment != "dbbackup@laptop" {
		t.Fatalf("unexpected parse result: %+v", pk)
	}
}

func TestParsePubkeyFileRejectsPrivateKey(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/key"
	writeFile(t, path, "-----BEGIN OPENSSH PRIVATE KEY-----\nbogus\n-----END OPENSSH PRIVATE KEY-----\n")

	if _, err := parsePubkeyFile(path); err == nil {
		t.Fatalf("expected rejection of private key material")
	}
}

func TestParsePubkeyFileRejectsMultipleLines(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/key.pub"
	writeFile(t, path, "ssh-ed25519 dGVzdC1rZXktYmxvYg== a\nssh-ed25519 dGVzdC1rZXktYmxvYg== b\n")

	if _, err := parsePubkeyFile(path); err == nil {
		t.Fatalf("expected rejection of multi-line key file")
	}
}

func TestParsePubkeyFileRejectsBadBase64(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/key.pub"
	writeFile(t, path, "ssh-ed25519 not-valid-base64!!! comment\n")

	if _, err := parsePubkeyFile(path); err == nil {
		t.Fatalf("expected rejection of invalid base64 blob")
	}
}

func TestParsePubkeyFileRejectsUnknownType(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/key.pub"
	writeFile(t, path, "ssh-dss dGVzdC1rZXktYmxvYg== comment\n")

	if _, err := parsePubkeyFile(path); err == nil {
		t.Fatalf("expected rejection of unsupported key type")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd admin && go test ./... -run 'Validate|ParsePubkey' -v`
Expected: FAIL — validators and `parsePubkeyFile`/`parsedKey` undefined.

- [ ] **Step 3: Write the implementation**

```go
// admin/validate.go
package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"regexp"
	"strings"
)

var (
	usernameRe = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
	roleArnRe  = regexp.MustCompile(`^arn:aws:iam::\d{12}:role/[\w+=,.@/-]+$`)
	regionRe   = regexp.MustCompile(`^[a-z]{2}-[a-z]+-\d$`)
	keyTypeRe  = regexp.MustCompile(`^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521))$`)
)

func validateUsername(u string) error {
	if !usernameRe.MatchString(u) {
		return fmt.Errorf("invalid username %q: must match %s", u, usernameRe.String())
	}
	return nil
}

func validateRoleArn(arn string) error {
	if !roleArnRe.MatchString(arn) {
		return fmt.Errorf("invalid role ARN %q: expected arn:aws:iam::<12-digit-account>:role/<name>", arn)
	}
	return nil
}

func validateRegion(r string) error {
	if !regionRe.MatchString(r) {
		return fmt.Errorf("invalid region %q: expected a form like ap-south-1", r)
	}
	return nil
}

// parsedKey is one validated SSH public key line.
type parsedKey struct {
	Type    string
	Blob    string // base64, undecoded
	Comment string
}

// parsePubkeyFile reads path and validates it contains exactly one
// well-formed "type base64blob [comment]" SSH public key line. It
// explicitly rejects private key material to catch the common mistake
// of pointing at the wrong file.
func parsePubkeyFile(path string) (parsedKey, error) {
	var pk parsedKey
	b, err := os.ReadFile(path)
	if err != nil {
		return pk, err
	}
	content := strings.TrimSpace(string(b))
	if strings.Contains(content, "-----BEGIN") {
		return pk, fmt.Errorf("%s looks like a private key, not a public key", path)
	}
	var lines []string
	for _, l := range strings.Split(content, "\n") {
		l = strings.TrimSpace(l)
		if l != "" {
			lines = append(lines, l)
		}
	}
	if len(lines) != 1 {
		return pk, fmt.Errorf("%s must contain exactly one key line, found %d", path, len(lines))
	}
	fields := strings.Fields(lines[0])
	if len(fields) < 2 {
		return pk, fmt.Errorf("%s: malformed key line, expected \"type base64blob [comment]\"", path)
	}
	if !keyTypeRe.MatchString(fields[0]) {
		return pk, fmt.Errorf("%s: unsupported key type %q", path, fields[0])
	}
	if _, err := base64.StdEncoding.DecodeString(fields[1]); err != nil {
		return pk, fmt.Errorf("%s: key blob is not valid base64: %w", path, err)
	}
	pk.Type = fields[0]
	pk.Blob = fields[1]
	if len(fields) >= 3 {
		pk.Comment = strings.Join(fields[2:], " ")
	}
	return pk, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd admin && go test ./... -v`
Expected: PASS for all Task 1 and Task 2 tests.

- [ ] **Step 5: Commit**

```bash
git add admin/validate.go admin/validate_test.go
git commit -m "Add username/ARN/region/pubkey validators for awsjail-admin"
```

---

### Task 3: SSH key file handling (`admin/keys.go`)

**Files:**
- Create: `admin/keys.go`
- Test: `admin/keys_test.go`

**Interfaces:**
- Consumes: `parsedKey` and `parsePubkeyFile` from Task 2.
- Produces: `func fingerprint(pk parsedKey) (string, error)`; `func writeAuthorizedKeys(homeDir, line string) error`; `func clearAuthorizedKeys(homeDir string) error`; `func readAuthorizedKeyFingerprint(homeDir string) (fp, comment string, err error)`. Task 6 depends on all four.

- [ ] **Step 1: Write the failing tests**

```go
// admin/keys_test.go
package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteAndClearAuthorizedKeys(t *testing.T) {
	home := t.TempDir()
	line := "ssh-ed25519 dGVzdC1rZXktYmxvYg== test@host"

	if err := writeAuthorizedKeys(home, line); err != nil {
		t.Fatalf("writeAuthorizedKeys: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(home, ".ssh", "authorized_keys"))
	if err != nil {
		t.Fatalf("read authorized_keys: %v", err)
	}
	if string(got) != line+"\n" {
		t.Fatalf("unexpected content: %q", got)
	}

	if err := clearAuthorizedKeys(home); err != nil {
		t.Fatalf("clearAuthorizedKeys: %v", err)
	}
	got, err = os.ReadFile(filepath.Join(home, ".ssh", "authorized_keys"))
	if err != nil {
		t.Fatalf("read after clear: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected empty file after clear, got %q", got)
	}
}

func TestClearAuthorizedKeysMissingFileIsNotError(t *testing.T) {
	home := t.TempDir()
	if err := clearAuthorizedKeys(home); err != nil {
		t.Fatalf("expected no error for missing .ssh dir, got %v", err)
	}
}

func TestFingerprintDeterministicAndFormatted(t *testing.T) {
	pk := parsedKey{Type: "ssh-ed25519", Blob: "dGVzdC1rZXktYmxvYg==", Comment: "x"}
	fp1, err := fingerprint(pk)
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}
	fp2, _ := fingerprint(pk)
	if fp1 != fp2 {
		t.Fatalf("fingerprint not deterministic: %q vs %q", fp1, fp2)
	}
	if len(fp1) != len("SHA256:")+43 {
		t.Fatalf("unexpected fingerprint length: %q (%d chars)", fp1, len(fp1))
	}
	other := parsedKey{Type: "ssh-ed25519", Blob: "b3RoZXItYmxvYg==", Comment: "x"}
	fp3, _ := fingerprint(other)
	if fp3 == fp1 {
		t.Fatalf("expected different blobs to produce different fingerprints")
	}
}

func TestReadAuthorizedKeyFingerprintRoundTrip(t *testing.T) {
	home := t.TempDir()
	line := "ssh-ed25519 dGVzdC1rZXktYmxvYg== dbbackup@laptop"
	if err := writeAuthorizedKeys(home, line); err != nil {
		t.Fatalf("writeAuthorizedKeys: %v", err)
	}
	fp, comment, err := readAuthorizedKeyFingerprint(home)
	if err != nil {
		t.Fatalf("readAuthorizedKeyFingerprint: %v", err)
	}
	if comment != "dbbackup@laptop" {
		t.Fatalf("unexpected comment: %q", comment)
	}
	want, err := fingerprint(parsedKey{Type: "ssh-ed25519", Blob: "dGVzdC1rZXktYmxvYg=="})
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}
	if fp != want {
		t.Fatalf("fingerprint mismatch: got %q want %q", fp, want)
	}
}

func TestReadAuthorizedKeyFingerprintMissingFile(t *testing.T) {
	home := t.TempDir()
	if _, _, err := readAuthorizedKeyFingerprint(home); err == nil {
		t.Fatalf("expected error reading fingerprint for a home with no authorized_keys")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd admin && go test ./... -run 'AuthorizedKeys|Fingerprint' -v`
Expected: FAIL — `fingerprint`, `writeAuthorizedKeys`, `clearAuthorizedKeys`, `readAuthorizedKeyFingerprint` undefined.

- [ ] **Step 3: Write the implementation**

```go
// admin/keys.go
package main

import (
	"crypto/sha256"
	"encoding/base64"
	"os"
	"path/filepath"
)

// fingerprint returns the SHA256 fingerprint of a parsed key in the same
// format `ssh-keygen -lf` prints, e.g. "SHA256:abcd...".
func fingerprint(pk parsedKey) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(pk.Blob)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:]), nil
}

// writeAuthorizedKeys overwrites homeDir/.ssh/authorized_keys with exactly
// one key line, creating .ssh if needed. Ownership (chown to the account's
// uid/gid) is the caller's responsibility once the account is known to
// exist; this function only sets permissions.
func writeAuthorizedKeys(homeDir, line string) error {
	sshDir := filepath.Join(homeDir, ".ssh")
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		return err
	}
	if err := os.Chmod(sshDir, 0700); err != nil {
		return err
	}
	akPath := filepath.Join(sshDir, "authorized_keys")
	if err := os.WriteFile(akPath, []byte(line+"\n"), 0600); err != nil {
		return err
	}
	return os.Chmod(akPath, 0600)
}

// clearAuthorizedKeys empties homeDir/.ssh/authorized_keys if it exists.
// A missing .ssh directory or file is not an error.
func clearAuthorizedKeys(homeDir string) error {
	akPath := filepath.Join(homeDir, ".ssh", "authorized_keys")
	if _, err := os.Stat(akPath); os.IsNotExist(err) {
		return nil
	}
	return os.WriteFile(akPath, []byte{}, 0600)
}

// readAuthorizedKeyFingerprint reads homeDir/.ssh/authorized_keys and
// returns the fingerprint and comment of the single key it expects to
// find there.
func readAuthorizedKeyFingerprint(homeDir string) (fp string, comment string, err error) {
	pk, err := parsePubkeyFile(filepath.Join(homeDir, ".ssh", "authorized_keys"))
	if err != nil {
		return "", "", err
	}
	fp, err = fingerprint(pk)
	if err != nil {
		return "", "", err
	}
	return fp, pk.Comment, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd admin && go test ./... -v`
Expected: PASS for all Task 1-3 tests.

- [ ] **Step 5: Commit**

```bash
git add admin/keys.go admin/keys_test.go
git commit -m "Add SSH key file handling for awsjail-admin"
```

---

### Task 4: Unix account argument builders (`admin/account.go`)

**Files:**
- Create: `admin/account.go`
- Test: `admin/account_test.go`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: `const awsjailShell = "/usr/local/bin/awsjail"`; `const awsjailGroup = "awsjail"`; `func useraddArgs(username string) []string`; `func usermodArgs(username string) []string`; `func ensureUnixAccount(username string) error`. Task 6 depends on `ensureUnixAccount`.
- Note: `ensureUnixAccount` calls real `useradd`/`usermod` via `os/exec` and is **not unit tested** — it needs root and a Linux host. Only the pure argument builders are tested here.

- [ ] **Step 1: Write the failing tests**

```go
// admin/account_test.go
package main

import (
	"reflect"
	"testing"
)

func TestUseraddArgs(t *testing.T) {
	got := useraddArgs("dbbackup")
	want := []string{"-m", "-G", "awsjail", "-s", "/usr/local/bin/awsjail", "dbbackup"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("useraddArgs = %v, want %v", got, want)
	}
}

func TestUsermodArgs(t *testing.T) {
	got := usermodArgs("dbbackup")
	want := []string{"-s", "/usr/local/bin/awsjail", "-aG", "awsjail", "dbbackup"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("usermodArgs = %v, want %v", got, want)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd admin && go test ./... -run 'Useradd|Usermod' -v`
Expected: FAIL — `useraddArgs`/`usermodArgs` undefined.

- [ ] **Step 3: Write the implementation**

```go
// admin/account.go
package main

import (
	"fmt"
	"os/exec"
	"os/user"
)

const (
	awsjailShell = "/usr/local/bin/awsjail"
	awsjailGroup = "awsjail"
)

// useraddArgs and usermodArgs are separated from execution so their exact
// argument lists are unit-testable without invoking useradd/usermod.
func useraddArgs(username string) []string {
	return []string{"-m", "-G", awsjailGroup, "-s", awsjailShell, username}
}

func usermodArgs(username string) []string {
	return []string{"-s", awsjailShell, "-aG", awsjailGroup, username}
}

// ensureUnixAccount makes sure username exists with the awsjail login
// shell and group membership: creates it via useradd if absent, or heals
// a drifted existing account via usermod.
func ensureUnixAccount(username string) error {
	_, err := user.Lookup(username)
	if err != nil {
		if _, ok := err.(user.UnknownUserError); !ok {
			return fmt.Errorf("looking up %s: %w", username, err)
		}
		cmd := exec.Command("useradd", useraddArgs(username)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("useradd %s: %v: %s", username, err, out)
		}
		return nil
	}
	cmd := exec.Command("usermod", usermodArgs(username)...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("usermod %s: %v: %s", username, err, out)
	}
	return nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd admin && go test ./... -v`
Expected: PASS for all Task 1-4 tests.

- [ ] **Step 5: Commit**

```bash
git add admin/account.go admin/account_test.go
git commit -m "Add unix account management for awsjail-admin"
```

---

### Task 5: Audit logging (`admin/audit.go`)

**Files:**
- Create: `admin/audit.go`
- Test: `admin/audit_test.go`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: `func actor() string`; `func buildAuditLine(action, target, result string) string`; `func auditLog(sl *syslog.Writer, action, target, result string)`. Task 6 depends on `buildAuditLine` (indirectly, via `auditLog`) and calls `syslog.New` itself to construct the `*syslog.Writer`.

- [ ] **Step 1: Write the failing tests**

```go
// admin/audit_test.go
package main

import (
	"encoding/json"
	"os"
	"testing"
)

func TestBuildAuditLine(t *testing.T) {
	t.Setenv("SUDO_USER", "riyaz")
	line := buildAuditLine("add_user", "dbbackup", "ok")

	var got map[string]string
	if err := json.Unmarshal([]byte(line), &got); err != nil {
		t.Fatalf("audit line is not valid JSON: %v (%q)", err, line)
	}
	want := map[string]string{"actor": "riyaz", "action": "add_user", "target": "dbbackup", "result": "ok"}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("field %s = %q, want %q", k, got[k], v)
		}
	}
}

func TestActorFallsBackWithoutSudoUser(t *testing.T) {
	os.Unsetenv("SUDO_USER")
	if a := actor(); a == "" {
		t.Fatalf("actor() returned empty string")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd admin && go test ./... -run 'Audit|Actor' -v`
Expected: FAIL — `actor`/`buildAuditLine` undefined.

- [ ] **Step 3: Write the implementation**

```go
// admin/audit.go
package main

import (
	"encoding/json"
	"log/syslog"
	"os"
	"os/user"
)

func actor() string {
	if a := os.Getenv("SUDO_USER"); a != "" {
		return a
	}
	if u, err := user.Current(); err == nil {
		return u.Username
	}
	return "unknown"
}

// buildAuditLine renders one audit event as the JSON line awsjail-admin
// writes to syslog. Kept pure and separate from *syslog.Writer so it is
// unit-testable without a real syslog socket.
func buildAuditLine(action, target, result string) string {
	b, _ := json.Marshal(map[string]string{
		"actor":  actor(),
		"action": action,
		"target": target,
		"result": result,
	})
	return string(b)
}

func auditLog(sl *syslog.Writer, action, target, result string) {
	sl.Notice(buildAuditLine(action, target, result))
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd admin && go test ./... -v`
Expected: PASS for all Task 1-5 tests.

- [ ] **Step 5: Commit**

```bash
git add admin/audit.go admin/audit_test.go
git commit -m "Add syslog audit logging for awsjail-admin"
```

---

### Task 6: CLI entrypoint and orchestration (`admin/main.go`)

**Files:**
- Create: `admin/main.go`

**Interfaces:**
- Consumes: `roleEntry`, `loadRoles`, `upsertRole`, `deleteRole` (Task 1); `validateUsername`, `validateRoleArn`, `validateRegion`, `parsePubkeyFile`, `parsedKey` (Task 2); `fingerprint`, `writeAuthorizedKeys`, `clearAuthorizedKeys`, `readAuthorizedKeyFingerprint` (Task 3); `ensureUnixAccount` (Task 4); `buildAuditLine`/`auditLog` via `syslog.New` (Task 5).
- Produces: the `awsjail-admin` executable's `main()`, plus `rolesPath` const used by all three subcommands.

No unit tests in this task — `cmdAddUser`/`cmdRemoveUser` call `ensureUnixAccount`, which needs root and real `useradd`/`usermod`, unavailable on this (macOS) dev machine. Verification is manual: build the binary and exercise the paths that don't require root or a real account.

- [ ] **Step 1: Write `admin/main.go`**

```go
// admin/main.go
package main

import (
	"flag"
	"fmt"
	"log/syslog"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
)

const rolesPath = "/etc/awsjail/roles.json"

func main() {
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "awsjail-admin: must run as root")
		os.Exit(1)
	}
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "add-user":
		cmdAddUser(os.Args[2:])
	case "remove-user":
		cmdRemoveUser(os.Args[2:])
	case "list-users":
		cmdListUsers(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: awsjail-admin <add-user|remove-user|list-users> [flags]")
}

func fail(cmd string, err error) {
	fmt.Fprintf(os.Stderr, "%s: %v\n", cmd, err)
	os.Exit(1)
}

func openAudit() *syslog.Writer {
	sl, err := syslog.New(syslog.LOG_AUTHPRIV|syslog.LOG_NOTICE, "awsjail-admin")
	if err != nil {
		fmt.Fprintln(os.Stderr, "awsjail-admin: cannot open syslog:", err)
		os.Exit(1)
	}
	return sl
}

func homeDirOf(username string) (string, error) {
	u, err := user.Lookup(username)
	if err != nil {
		return "", err
	}
	return u.HomeDir, nil
}

func chownToUser(username, path string) error {
	u, err := user.Lookup(username)
	if err != nil {
		return err
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return err
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return err
	}
	return os.Chown(path, uid, gid)
}

func cmdAddUser(args []string) {
	fs := flag.NewFlagSet("add-user", flag.ExitOnError)
	username := fs.String("username", "", "unix username")
	roleArn := fs.String("role-arn", "", "IAM role ARN to assume")
	region := fs.String("region", "", "AWS region, e.g. ap-south-1")
	pubkeyFile := fs.String("pubkey-file", "", "path to a single SSH public key file")
	fs.Parse(args)

	if *username == "" || *roleArn == "" || *region == "" || *pubkeyFile == "" {
		fmt.Fprintln(os.Stderr, "add-user: --username, --role-arn, --region, --pubkey-file are all required")
		os.Exit(1)
	}
	if err := validateUsername(*username); err != nil {
		fail("add-user", err)
	}
	if err := validateRoleArn(*roleArn); err != nil {
		fail("add-user", err)
	}
	if err := validateRegion(*region); err != nil {
		fail("add-user", err)
	}
	pk, err := parsePubkeyFile(*pubkeyFile)
	if err != nil {
		fail("add-user", err)
	}

	if err := ensureUnixAccount(*username); err != nil {
		fail("add-user", err)
	}

	if err := upsertRole(rolesPath, *username, roleEntry{RoleArn: *roleArn, Region: *region}); err != nil {
		fail("add-user", err)
	}

	home, err := homeDirOf(*username)
	if err != nil {
		fail("add-user", err)
	}
	keyLine := pk.Type + " " + pk.Blob
	if pk.Comment != "" {
		keyLine += " " + pk.Comment
	}
	if err := writeAuthorizedKeys(home, keyLine); err != nil {
		fail("add-user", err)
	}
	if err := chownToUser(*username, filepath.Join(home, ".ssh")); err != nil {
		fail("add-user", err)
	}
	if err := chownToUser(*username, filepath.Join(home, ".ssh", "authorized_keys")); err != nil {
		fail("add-user", err)
	}

	fp, err := fingerprint(pk)
	if err != nil {
		fail("add-user", err)
	}
	sl := openAudit()
	auditLog(sl, "add_user", *username, "ok")
	sl.Close()
	fmt.Printf("added %s: role %s, region %s, key %s\n", *username, *roleArn, *region, fp)
}

func cmdRemoveUser(args []string) {
	fs := flag.NewFlagSet("remove-user", flag.ExitOnError)
	username := fs.String("username", "", "unix username")
	fs.Parse(args)
	if *username == "" {
		fmt.Fprintln(os.Stderr, "remove-user: --username is required")
		os.Exit(1)
	}

	removed, err := deleteRole(rolesPath, *username)
	if err != nil {
		fail("remove-user", err)
	}

	sl := openAudit()
	defer sl.Close()
	if !removed {
		auditLog(sl, "remove_user", *username, "not_mapped")
		fmt.Printf("%s was not mapped, nothing to remove\n", *username)
		return
	}

	if home, err := homeDirOf(*username); err == nil {
		if err := clearAuthorizedKeys(home); err != nil {
			fail("remove-user", err)
		}
	}
	auditLog(sl, "remove_user", *username, "ok")
	fmt.Printf("removed %s: role mapping deleted, key cleared\n", *username)
}

func cmdListUsers(args []string) {
	m, err := loadRoles(rolesPath)
	if err != nil {
		fail("list-users", err)
	}
	fmt.Printf("%-16s %-60s %-15s %-52s %s\n", "USERNAME", "ROLE_ARN", "REGION", "KEY_FINGERPRINT", "STATUS")
	for username, entry := range m {
		status, fp := "no-key", "-"
		if home, err := homeDirOf(username); err == nil {
			akPath := filepath.Join(home, ".ssh", "authorized_keys")
			if _, statErr := os.Stat(akPath); statErr == nil {
				if f, _, ferr := readAuthorizedKeyFingerprint(home); ferr != nil {
					status = "key-parse-error"
				} else {
					status, fp = "ok", f
				}
			}
		}
		fmt.Printf("%-16s %-60s %-15s %-52s %s\n", username, entry.RoleArn, entry.Region, fp, status)
	}
}
```

- [ ] **Step 2: Build the binary**

Run: `cd admin && go build -o /tmp/awsjail-admin-test . && echo BUILD_OK`
Expected: `BUILD_OK`, no compile errors.

- [ ] **Step 3: Manually verify the root check and usage paths (no root/useradd required)**

```bash
/tmp/awsjail-admin-test
# expect: "awsjail-admin: must run as root" on stderr, exit 1 (assuming this shell is not root)

sudo /tmp/awsjail-admin-test 2>&1 | head -1
# expect (as root, no args): "usage: awsjail-admin <add-user|remove-user|list-users> [flags]", exit 2

sudo /tmp/awsjail-admin-test bogus-command 2>&1 | head -1
# expect: same usage message, exit 2
```

Expected: both root-check and usage/dispatch paths behave as described. Full `add-user`/`remove-user`/`list-users` end-to-end verification (which needs real `useradd`) is deferred to Task 7's deployment testing on an actual Ubuntu host — note this explicitly when reporting Task 6 done.

- [ ] **Step 4: Run the full admin test suite once more**

Run: `cd admin && go test ./... -v`
Expected: PASS for every test from Tasks 1-5 (main.go itself has no tests, but must not break compilation of the package).

- [ ] **Step 5: Commit**

```bash
git add admin/main.go
git commit -m "Add awsjail-admin CLI: add-user, remove-user, list-users"
```

---

### Task 7: `setup.sh` host bootstrap script

**Files:**
- Create: `setup.sh`

**Interfaces:**
- Consumes: nothing from Go code directly (invokes `go build` on `.` and `./admin` as external commands).
- Produces: the deployable script referenced by README's Admin/Bastion Manager Setup section (Task 8).

No automated tests (bash script targeting a real Ubuntu host, root privileges, and system package managers this dev machine doesn't have). Verified via syntax check only.

- [ ] **Step 1: Write `setup.sh`**

```bash
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
GO_MIN_VERSION="1.22"
NEED_GO=1
if command -v go >/dev/null 2>&1; then
  CUR_GO="$(go version | awk '{print $3}' | sed 's/go//')"
  if printf '%s\n%s\n' "$GO_MIN_VERSION" "$CUR_GO" | sort -V -C; then
    NEED_GO=0
    step "go toolchain: $CUR_GO already installed, skipping"
  fi
fi
if [[ $NEED_GO -eq 1 ]]; then
  ARCH="$(uname -m)"
  case "$ARCH" in
    x86_64) GOARCH="amd64" ;;
    aarch64) GOARCH="arm64" ;;
    *) echo "setup.sh: unsupported architecture $ARCH" >&2; exit 1 ;;
  esac
  GO_VERSION="1.22.0"
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

# 9. sshd hardening drop-in
cat > /etc/ssh/sshd_config.d/awsjail.conf <<'SSHD'
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
step "sshd drop-in written to /etc/ssh/sshd_config.d/awsjail.conf"

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
  if [[ $SKIP_SSHD_RELOAD -eq 0 ]]; then
    systemctl reload ssh
    step "sshd: reloaded"
  else
    step "sshd: reload skipped (--skip-sshd-reload)"
  fi
else
  echo "setup.sh: sshd -t failed, not reloading. Fix the config above before retrying." >&2
  exit 1
fi

step "done"
```

- [ ] **Step 2: Make it executable**

Run: `chmod +x setup.sh`

- [ ] **Step 3: Syntax-check it**

Run: `bash -n setup.sh && echo SYNTAX_OK`
Expected: `SYNTAX_OK`, no errors.

- [ ] **Step 4: Run shellcheck if available (best-effort, not blocking)**

Run: `command -v shellcheck >/dev/null && shellcheck setup.sh || echo "shellcheck not installed, skipped"`
Expected: either shellcheck's output (review and fix anything that isn't an intentional/acknowledged pattern) or the skip message. Do not treat a missing `shellcheck` binary as a failure.

- [ ] **Step 5: Commit**

```bash
git add setup.sh
git commit -m "Add idempotent Ubuntu host bootstrap script"
```

---

### Task 8: README and spec.md documentation

**Files:**
- Modify: `README.md`
- Modify: `spec.md`

**Interfaces:**
- Consumes: nothing (documentation only).
- Produces: nothing consumed by later tasks.

- [ ] **Step 1: Add a Table of Contents entry in README.md**

Find this line (in the `## Contents` list):
```
- [Host setup](#host-setup)
```
Change it to:
```
- [Host setup](#host-setup)
- [Admin/Bastion Manager Setup](#adminbastion-manager-setup)
```

- [ ] **Step 2: Insert the new README section**

Find the end of the `## Host setup` section — the line:
```
Put each user's SSH public key in their `~/.ssh/authorized_keys` as usual.
```
Insert this new section immediately after it, before the `## sshd` heading:

```markdown

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
`/etc/ssh/sshd_config.d/awsjail.conf` before it takes effect.

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
  `/etc/ssh/sshd_config.d/awsjail.conf`, comments out the sftp subsystem,
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
| `/etc/ssh/sshd_config.d/awsjail.conf` | root:root | sshd hardening drop-in, regenerated by `setup.sh`. |
| `/home/bastion-admin` | bastion-admin:bastion-admin | Break-glass account home. |

### Audit trail

Every `add-user` and `remove-user` writes one JSON line to syslog facility
`authpriv`, tag `awsjail-admin`: `{"actor", "action", "target", "result"}`,
where `actor` is whoever ran `sudo`. This sits alongside the three logging
layers in [Logging](#logging) — it's the record of who provisioned or
deprovisioned access, not of what a session did with that access.
```

- [ ] **Step 3: Update spec.md's Filesystem layout bullet list**

Find:
```
- `/etc/shells` — must list `/usr/local/bin/awsjail` for it to be a valid login shell.
```
Change to:
```
- `/etc/shells` — must list `/usr/local/bin/awsjail` for it to be a valid login shell.
- `/usr/local/sbin/awsjail-admin` — the admin binary, `root:root`, `0700`.
- `/etc/ssh/sshd_config.d/awsjail.conf` — sshd hardening drop-in generated by `setup.sh`.
```

- [ ] **Step 4: Add a cross-reference after spec.md's roles.json schema paragraph**

Find:
```
Keys are unix usernames. Each value is a `role_arn` plus a `region`, one profile-equivalent per user, the same way a stanza in `~/.aws/config` carries its own region. A user not present in the map, or present with an empty `role_arn` or `region`, cannot log in — `loadRole` treats both as unmapped and fails closed.
```
Insert immediately after it:
```

See the README's [Admin/Bastion Manager Setup](README.md#adminbastion-manager-setup) section for `setup.sh` and `awsjail-admin` — the sanctioned way to populate this file.
```

- [ ] **Step 5: Add an Admin audit schema subsection after spec.md's Log schema table**

Find the end of the Log schema table and its following line:
```
Severity maps to the action: `no_role` and `assume_failed` are errors, `parse_error` and `denied` are warnings, `run` is info.
```
Insert immediately after it:
```

**Admin audit schema.** `awsjail-admin` logs to the same `authpriv` facility, tag `awsjail-admin`, at `LOG_NOTICE`:

| Field | Type | Meaning |
| --- | --- | --- |
| `actor` | string | `SUDO_USER`, or the running unix user if not invoked via sudo |
| `action` | string | `add_user` or `remove_user` |
| `target` | string | the tier username being added or removed |
| `result` | string | `ok` or `not_mapped` (remove-user on an absent user) |

This is what makes `roles.json` mutation itself auditable — see the `roles.json` gotcha below.
```

- [ ] **Step 6: Update the roles.json gotcha in spec.md**

Find:
```
- **`roles.json` is a privilege map.** If it is ever writable by a non-root user, that user can promote themselves. Keep it `0644` root-owned and watch it.
```
Change to:
```
- **`roles.json` is a privilege map.** If it is ever writable by a non-root user, that user can promote themselves. Keep it `0644` root-owned and watch it. Mutate it only through `awsjail-admin` (see the README's Admin/Bastion Manager Setup section) — that path is atomic and audited to syslog; a manual `tee`/editor edit bypasses both.
```

- [ ] **Step 7: Commit**

```bash
git add README.md spec.md
git commit -m "Document Admin/Bastion Manager Setup in README and spec.md"
```

---

### Task 9: Final integration check

**Files:** none created; verification only.

**Interfaces:** none.

- [ ] **Step 1: Build both binaries from repo root**

Run: `CGO_ENABLED=0 go build -o awsjail . && CGO_ENABLED=0 go build -o awsjail-admin ./admin && echo BUILD_OK`
Expected: `BUILD_OK`.

- [ ] **Step 2: Vet the whole module**

Run: `go vet ./...`
Expected: no output (no issues).

- [ ] **Step 3: Run the full test suite**

Run: `go test ./... -v`
Expected: PASS for every test across `admin/`.

- [ ] **Step 4: Syntax-check setup.sh once more**

Run: `bash -n setup.sh && echo SYNTAX_OK`
Expected: `SYNTAX_OK`.

- [ ] **Step 5: Clean up build artifacts and review the full diff**

```bash
rm -f awsjail awsjail-admin
git status --short
git diff --stat HEAD
```
Expected: only the files from Tasks 1-8 (admin/*.go, setup.sh, README.md, spec.md, plus the design/plan docs already committed) show as tracked changes; no stray binaries.

- [ ] **Step 6: Commit anything left uncommitted**

If Step 5 shows uncommitted changes (e.g. a final doc tweak), commit them with a message describing what was finished. If everything is already committed from Tasks 1-8, skip this step.
