package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestHelpToArgv(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{"bare help", []string{"help"}, []string{"aws", "help"}},
		{"help topic", []string{"help", "s3"}, []string{"aws", "help", "s3"}},
		{"aws passthrough", []string{"aws", "s3", "ls"}, []string{"aws", "s3", "ls"}},
		{"other command untouched", []string{"id"}, []string{"id"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := helpToArgv(tc.in); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("helpToArgv(%v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestAccountFromArn(t *testing.T) {
	cases := []struct {
		name, arn, want string
	}{
		{"assumed role", "arn:aws:sts::123456789012:assumed-role/tier-dbbackup/dbbackup", "123456789012"},
		{"role path", "arn:aws:sts::999888777666:assumed-role/path/tier-x/session", "999888777666"},
		{"not an arn", "something-else", ""},
		{"short arn", "arn:aws:sts", ""},
		{"empty", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := accountFromArn(tc.arn); got != tc.want {
				t.Fatalf("accountFromArn(%q) = %q, want %q", tc.arn, got, tc.want)
			}
		})
	}
}

func TestIsCredentialExport(t *testing.T) {
	denied := []struct {
		name string
		argv []string
	}{
		{"default format", []string{"aws", "configure", "export-credentials"}},
		{"format env", []string{"aws", "configure", "export-credentials", "--format", "env"}},
		{"format env-no-export", []string{"aws", "configure", "export-credentials", "--format", "env-no-export"}},
		{"format powershell", []string{"aws", "configure", "export-credentials", "--format", "powershell"}},
		{"format windows-cmd", []string{"aws", "configure", "export-credentials", "--format", "windows-cmd"}},
		{"format fish", []string{"aws", "configure", "export-credentials", "--format", "fish"}},
		{"format process", []string{"aws", "configure", "export-credentials", "--format", "process"}},
		{"global option before", []string{"aws", "--region", "us-east-1", "configure", "export-credentials", "--format", "env"}},
		{"global option around", []string{"aws", "--debug", "configure", "--region", "us-east-1", "export-credentials"}},
		{"option equals form", []string{"aws", "--output=json", "configure", "export-credentials"}},
		{"option after service", []string{"aws", "configure", "--profile", "ops", "export-credentials"}},
	}
	for _, tc := range denied {
		t.Run("deny/"+tc.name, func(t *testing.T) {
			if !isCredentialExport(tc.argv) {
				t.Fatalf("isCredentialExport(%v) = false, want true", tc.argv)
			}
		})
	}
	allowed := []struct {
		name string
		argv []string
	}{
		{"configure list", []string{"aws", "configure", "list"}},
		{"configure set", []string{"aws", "configure", "set", "region", "us-east-1"}},
		{"sts caller identity", []string{"aws", "sts", "get-caller-identity"}},
		{"s3 ls", []string{"aws", "s3", "ls"}},
		{"reversed order", []string{"aws", "export-credentials", "configure"}},
		{"no substring match", []string{"aws", "configures", "export-credentialss"}},
		{"tokens inside values", []string{"aws", "s3", "cp", "s3://b/configure", "s3://b/export-credentials"}},
		{"bare file names", []string{"aws", "s3", "cp", "configure", "export-credentials"}},
		{"configure as value", []string{"aws", "iam", "create-access-key", "--user-name", "configure"}},
		{"configure as option value", []string{"aws", "--profile", "configure", "s3", "ls"}},
		{"region value shadows nothing", []string{"aws", "--region", "configure", "export-credentials"}},
	}
	for _, tc := range allowed {
		t.Run("allow/"+tc.name, func(t *testing.T) {
			if isCredentialExport(tc.argv) {
				t.Fatalf("isCredentialExport(%v) = true, want false", tc.argv)
			}
		})
	}
}

func envMap(env []string) map[string]string {
	m := map[string]string{}
	for _, kv := range env {
		k, v, _ := strings.Cut(kv, "=")
		m[k] = v
	}
	return m
}

func TestBuildEnvRestrictions(t *testing.T) {
	env := buildEnv(creds{AccessKeyID: "AKID", SecretAccessKey: "secret", SessionToken: "tok"}, "ap-south-1")
	m := envMap(env)

	path := m["PATH"]
	if path == "" {
		t.Fatal("buildEnv: PATH missing")
	}
	entries := strings.Split(path, ":")
	if !reflect.DeepEqual(entries, []string{helperBin}) {
		t.Fatalf("buildEnv PATH = %q, want exactly [%q]", path, helperBin)
	}
	for _, e := range entries {
		if e == "/usr/bin" || e == "/bin" || e == "/usr/local/bin" {
			t.Fatalf("buildEnv PATH contains system entry %q", e)
		}
	}
	if got := m["SHELL"]; got != noShell {
		t.Fatalf("buildEnv SHELL = %q, want %q", got, noShell)
	}
	if got := m["AWS_ACCESS_KEY_ID"]; got != "AKID" {
		t.Fatalf("buildEnv AWS_ACCESS_KEY_ID = %q, want AKID", got)
	}
}

func TestIsSensitiveLocalPath(t *testing.T) {
	const cwd = "/home/alice"
	denied := []struct {
		name string
		argv []string
	}{
		{"proc environ to stdout", []string{"aws", "s3", "cp", "/proc/self/environ", "-"}},
		{"proc via fileb", []string{"aws", "s3api", "put-object", "--body", "fileb:///proc/self/environ", "--bucket", "b", "--key", "k"}},
		{"proc via file", []string{"aws", "s3", "cp", "file:///proc/self/environ", "s3://b/k"}},
		{"proc relative traversal", []string{"aws", "s3", "cp", "../../proc/self/environ", "s3://b/k"}},
		{"proc root", []string{"aws", "s3", "cp", "/proc", "s3://b/k"}},
		{"sys path", []string{"aws", "s3", "cp", "/sys/class/dmi/id/product_uuid", "-"}},
		{"proc write target", []string{"aws", "s3", "cp", "s3://b/k", "/proc/self/fd/1"}},
	}
	for _, tc := range denied {
		t.Run("deny/"+tc.name, func(t *testing.T) {
			if !isSensitiveLocalPath(tc.argv, cwd) {
				t.Fatalf("isSensitiveLocalPath(%v) = false, want true", tc.argv)
			}
		})
	}
	allowed := []struct {
		name string
		argv []string
	}{
		{"tmp upload", []string{"aws", "s3", "cp", "/tmp/backup.tar.gz", "s3://b/k"}},
		{"home file", []string{"aws", "s3", "cp", "./notes.txt", "s3://b/k"}},
		{"bare name", []string{"aws", "s3", "cp", "notes.txt", "s3://b/k"}},
		{"file uri tmp", []string{"aws", "s3", "cp", "file:///tmp/x", "s3://b/k"}},
		{"s3 uri with proc key", []string{"aws", "s3", "cp", "s3://b/proc/self/environ", "/tmp/x"}},
		{"path merely containing proc", []string{"aws", "s3", "cp", "/data/proc/self/environ", "s3://b/k"}},
		{"jmespath query", []string{"aws", "ec2", "describe-instances", "--query", "Reservations[].Instances[]"}},
	}
	for _, tc := range allowed {
		t.Run("allow/"+tc.name, func(t *testing.T) {
			if isSensitiveLocalPath(tc.argv, cwd) {
				t.Fatalf("isSensitiveLocalPath(%v) = true, want false", tc.argv)
			}
		})
	}
}

func TestRunOneDeniedSensitivePath(t *testing.T) {
	fl := &fakeLogger{}
	code := runOne("aws s3 cp /proc/self/environ -", nil, fl, "alice", "")
	if code != 127 {
		t.Fatalf("runOne(proc environ) = %d, want 127", code)
	}
	events := parseEvents(t, fl)
	if len(events) != 1 || events[0].Action != "denied" || events[0].Reason != "sensitive_path" {
		t.Fatalf("events = %+v, want denied with reason sensitive_path", events)
	}
}

// fakeLogger captures audit events in emission order.
type fakeLogger struct {
	events []string
}

func (f *fakeLogger) Info(s string) error    { f.events = append(f.events, s); return nil }
func (f *fakeLogger) Warning(s string) error { f.events = append(f.events, s); return nil }
func (f *fakeLogger) Err(s string) error     { f.events = append(f.events, s); return nil }

type auditEvent struct {
	User   string `json:"user"`
	Src    string `json:"src"`
	Cmd    string `json:"cmd"`
	Exit   int    `json:"exit"`
	Action string `json:"action"`
	Reason string `json:"reason"`
}

func parseEvents(t *testing.T, f *fakeLogger) []auditEvent {
	t.Helper()
	out := make([]auditEvent, 0, len(f.events))
	for _, raw := range f.events {
		var e auditEvent
		if err := json.Unmarshal([]byte(raw), &e); err != nil {
			t.Fatalf("bad audit line %q: %v", raw, err)
		}
		out = append(out, e)
	}
	return out
}

// withFakeAWS points awsBin at a script with the given body and returns the
// script path. The real awsBin is restored on test cleanup.
func withFakeAWS(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "aws")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
	old := awsBin
	awsBin = p
	t.Cleanup(func() { awsBin = old })
	return p
}

func TestRunOneLogsStartBeforeExec(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "child-ran")
	// Uses a shell builtin (redirect), not an external binary: the child env's
	// PATH is the empty helper dir, which this test also relies on.
	withFakeAWS(t, "echo ran > '"+marker+"'\nexit 7")

	fl := &fakeLogger{}
	code := runOne("aws s3 ls", buildEnv(creds{}, "us-east-1"), fl, "alice", "192.0.2.10")

	if code != 7 {
		t.Fatalf("runOne exit = %d, want 7", code)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("child did not run: %v", err)
	}
	events := parseEvents(t, fl)
	if len(events) != 2 {
		t.Fatalf("got %d events, want 2: %v", len(events), events)
	}
	if events[0].Action != "command_start" {
		t.Fatalf("first event action = %q, want command_start", events[0].Action)
	}
	if events[1].Action != "command_finish" || events[1].Exit != 7 {
		t.Fatalf("second event = %+v, want command_finish exit 7", events[1])
	}
	if events[0].Cmd != "aws s3 ls" || events[0].User != "alice" || events[0].Src != "192.0.2.10" {
		t.Fatalf("start event fields wrong: %+v", events[0])
	}
}

func TestRunOneDeniedNonAWS(t *testing.T) {
	fl := &fakeLogger{}
	code := runOne("id", nil, fl, "alice", "")
	if code != 127 {
		t.Fatalf("runOne(id) = %d, want 127", code)
	}
	events := parseEvents(t, fl)
	if len(events) != 1 || events[0].Action != "denied" {
		t.Fatalf("events = %+v, want single denied event", events)
	}
}

func TestRunOneDeniedCredentialExport(t *testing.T) {
	fl := &fakeLogger{}
	code := runOne("aws configure export-credentials --format env", nil, fl, "alice", "")
	if code != 127 {
		t.Fatalf("runOne(export-credentials) = %d, want 127", code)
	}
	events := parseEvents(t, fl)
	if len(events) != 1 || events[0].Action != "denied" || events[0].Reason != "credential_export" {
		t.Fatalf("events = %+v, want denied with reason credential_export", events)
	}
}

func TestRunOneParseError(t *testing.T) {
	fl := &fakeLogger{}
	code := runOne("aws s3 ls 'unbalanced", nil, fl, "alice", "")
	if code != 2 {
		t.Fatalf("runOne(parse error) = %d, want 2", code)
	}
	events := parseEvents(t, fl)
	if len(events) != 1 || events[0].Action != "parse_error" {
		t.Fatalf("events = %+v, want single parse_error event", events)
	}
}

func TestRunOneExecFailureStillAudited(t *testing.T) {
	old := awsBin
	awsBin = "/nonexistent/aws"
	t.Cleanup(func() { awsBin = old })

	fl := &fakeLogger{}
	code := runOne("aws s3 ls", nil, fl, "alice", "")
	if code != 127 {
		t.Fatalf("runOne(missing aws) = %d, want 127", code)
	}
	events := parseEvents(t, fl)
	if len(events) != 2 || events[0].Action != "command_start" ||
		events[1].Action != "command_finish" || events[1].Exit != 127 {
		t.Fatalf("events = %+v, want command_start then command_finish exit 127", events)
	}
}

func TestLogLineReasonOmittedWhenEmpty(t *testing.T) {
	line := logLine("alice", "", "aws s3 ls", 0, "command_finish", "")
	if strings.Contains(line, "reason") {
		t.Fatalf("empty reason should be omitted, got %s", line)
	}
	line = logLine("alice", "", "aws configure export-credentials", -1, "denied", "credential_export")
	if !strings.Contains(line, `"reason":"credential_export"`) {
		t.Fatalf("reason missing, got %s", line)
	}
}

// TestSetupShHardening guards the host-side half of the fixes: the generated
// sshd drop-in must disable user rc files for the awsjail group, and setup.sh
// must create the root-owned helper-PATH directory.
func TestSetupShHardening(t *testing.T) {
	b, err := os.ReadFile("setup.sh")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if !strings.Contains(s, "Match Group awsjail") {
		t.Fatal("setup.sh: sshd drop-in lost the Match Group awsjail block")
	}
	if !strings.Contains(s, "PermitUserRC no") {
		t.Fatal("setup.sh: sshd drop-in must contain 'PermitUserRC no'")
	}
	if !strings.Contains(s, "install -d -m 0755 -o root -g root /usr/local/lib/awsjail/bin") {
		t.Fatal("setup.sh: must create /usr/local/lib/awsjail/bin root-owned 0755")
	}
	// The AWS CLI must stay pinned and checksum-verified: its custom commands
	// are part of the jail's attack surface.
	if !strings.Contains(s, `AWS_CLI_VERSION="`) {
		t.Fatal("setup.sh: AWS CLI version must be pinned via AWS_CLI_VERSION")
	}
	if !strings.Contains(s, "sha256sum -c -") {
		t.Fatal("setup.sh: AWS CLI download must be checksum-verified")
	}
	if !strings.Contains(s, "awscli-exe-linux-${AWSARCH}-${AWS_CLI_VERSION}.zip") {
		t.Fatal("setup.sh: AWS CLI must use the version-pinned download URL")
	}
}
