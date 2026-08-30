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
