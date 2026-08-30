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
