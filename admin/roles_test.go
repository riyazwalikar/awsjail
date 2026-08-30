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
