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
