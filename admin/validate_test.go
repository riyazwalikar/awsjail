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
