// awsjail is a login shell that only runs the AWS CLI.
//
// Deploy it as the login shell for bastion users. On start it reads the unix
// user, looks up that user's IAM role in /etc/awsjail/roles.json, assumes the
// role using the instance profile (via IMDS), and exports the temporary
// credentials into a clean environment for the aws CLI. Every command is
// logged to syslog.
//
// Security properties:
//   - Input is split into argv and the aws binary is exec'd directly. No shell
//     is ever involved, so ; | & $() and backticks are never interpreted. This
//     is also why JMESPath --query strings with | and backticks work: they are
//     passed to aws as literal argv.
//   - Only argv[0] == "aws" is allowed, with one exception inside that: `aws
//     configure export-credentials` is denied, because it exists specifically
//     to print the credentials awsjail injected into the child environment.
//   - The child environment is built from scratch. PATH is a dedicated
//     root-owned helper directory with no general-purpose executables, so AWS
//     CLI customizations (EMR ssh, CodeArtifact login, ...) cannot discover
//     system tools like ssh/scp/npm through it. SHELL points at nologin as
//     defense in depth. AWS_PAGER is empty so the CLI cannot page output
//     through less (and less cannot spawn a shell). AWS_CONFIG_FILE and
//     AWS_SHARED_CREDENTIALS_FILE point at /dev/null so a user-controlled
//     ~/.aws/config cannot inject credential_process or a stored profile.
//   - Every command is logged to syslog before it executes (command_start) and
//     again when it finishes (command_finish), so the audit record exists even
//     if the session is killed mid-command.
//   - Build with CGO_ENABLED=0 so LD_PRELOAD cannot affect this process.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log/syslog"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"regexp"
	"strings"
	"syscall"
)

const (
	roleMapPath = "/etc/awsjail/roles.json"
	sessionTTL  = "3600" // seconds; raise up to the role max if needed
	sessionHome = "/var/lib/awsjail"
	// helperBin is the only PATH entry the AWS CLI child gets. It is a
	// root-owned directory, created empty by setup.sh, so CLI customizations
	// cannot resolve system helpers (ssh, scp, npm, ...) through PATH. Add a
	// reviewed wrapper here if a legitimate use case ever needs one.
	helperBin = "/usr/local/lib/awsjail/bin"
	// noShell is defense in depth for anything in the CLI that consults SHELL.
	noShell = "/usr/sbin/nologin"
)

// awsBin is a var, not a const, so tests can point it at a fake CLI.
var awsBin = "/usr/local/bin/aws"

type roleEntry struct {
	RoleArn string `json:"role_arn"`
	Region  string `json:"region"`
}

type creds struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
}

// logger is satisfied by *syslog.Writer and by test fakes.
type logger interface {
	Info(string) error
	Warning(string) error
	Err(string) error
}

var sessRe = regexp.MustCompile(`[^\w+=,.@-]`)

func main() {
	sl, err := syslog.New(syslog.LOG_AUTHPRIV|syslog.LOG_NOTICE, "awsjail")
	if err != nil {
		fmt.Fprintln(os.Stderr, "awsjail: cannot open syslog")
		os.Exit(1)
	}
	defer sl.Close()

	u, err := user.Current()
	if err != nil {
		fmt.Fprintln(os.Stderr, "awsjail: cannot determine user")
		os.Exit(1)
	}

	src := ""
	if sc := os.Getenv("SSH_CONNECTION"); sc != "" {
		if f := strings.Fields(sc); len(f) > 0 {
			src = f[0]
		}
	}

	role, err := loadRole(u.Username)
	if err != nil {
		fmt.Fprintf(os.Stderr, "awsjail: no role mapping for %q\n", u.Username)
		sl.Err(logLine(u.Username, src, "", -1, "no_role", ""))
		os.Exit(1)
	}

	c, account, err := assume(role, sessionName(u.Username))
	if err != nil {
		fmt.Fprintf(os.Stderr, "awsjail: could not obtain credentials: %v\n", err)
		sl.Err(logLine(u.Username, src, "", -1, "assume_failed", ""))
		os.Exit(1)
	}
	env := buildEnv(c, role.Region)
	prompt := "awsjail:" + account + ":" + u.Username + " > "
	if account == "" {
		prompt = "awsjail:" + u.Username + " > "
	}

	// Non-interactive path. `ssh host "cmd"` calls the login shell as `-c "cmd"`.
	// With sshd ForceCommand the client command arrives in SSH_ORIGINAL_COMMAND.
	// Both are validated exactly like an interactive line.
	oneShot := ""
	if len(os.Args) >= 3 && os.Args[1] == "-c" {
		oneShot = os.Args[2]
	} else if v := os.Getenv("SSH_ORIGINAL_COMMAND"); v != "" {
		oneShot = v
	}
	if oneShot != "" {
		os.Exit(runOne(oneShot, env, sl, u.Username, src))
	}

	fmt.Fprintln(os.Stderr, "aws-only shell. only 'aws ...' is permitted. 'help' = aws help. type 'exit' to quit.")
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for {
		fmt.Fprint(os.Stderr, prompt)
		if !in.Scan() {
			break
		}
		line := strings.TrimSpace(in.Text())
		if line == "" {
			continue
		}
		if line == "exit" || line == "quit" {
			break
		}
		runOne(line, env, sl, u.Username, src)
	}
}

func loadRole(username string) (roleEntry, error) {
	var e roleEntry
	b, err := os.ReadFile(roleMapPath)
	if err != nil {
		return e, err
	}
	m := map[string]roleEntry{}
	if err := json.Unmarshal(b, &m); err != nil {
		return e, err
	}
	e, ok := m[username]
	if !ok || e.RoleArn == "" || e.Region == "" {
		return roleEntry{}, fmt.Errorf("not mapped")
	}
	return e, nil
}

// assume runs `aws sts assume-role` with an env that has no AWS credentials, so
// the CLI falls back to the instance profile via IMDS. It also returns the AWS
// account ID from the assumed-role ARN, for the prompt.
func assume(role roleEntry, session string) (creds, string, error) {
	var c creds
	cmd := exec.Command(awsBin, "sts", "assume-role",
		"--role-arn", role.RoleArn,
		"--role-session-name", session,
		"--duration-seconds", sessionTTL,
		"--output", "json")
	cmd.Env = []string{
		"PATH=" + helperBin,
		"SHELL=" + noShell,
		"HOME=" + sessionHome,
		"AWS_REGION=" + role.Region,
		"AWS_DEFAULT_REGION=" + role.Region,
		"AWS_PAGER=",
		"AWS_CONFIG_FILE=/dev/null",
		"AWS_SHARED_CREDENTIALS_FILE=/dev/null",
	}
	out, err := cmd.Output()
	if err != nil {
		return c, "", err
	}
	var resp struct {
		Credentials struct {
			AccessKeyID     string `json:"AccessKeyId"`
			SecretAccessKey string `json:"SecretAccessKey"`
			SessionToken    string `json:"SessionToken"`
		} `json:"Credentials"`
		AssumedRoleUser struct {
			Arn string `json:"Arn"`
		} `json:"AssumedRoleUser"`
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		return c, "", err
	}
	c = creds{resp.Credentials.AccessKeyID, resp.Credentials.SecretAccessKey, resp.Credentials.SessionToken}
	if c.AccessKeyID == "" {
		return c, "", fmt.Errorf("empty credentials returned")
	}
	return c, accountFromArn(resp.AssumedRoleUser.Arn), nil
}

// accountFromArn extracts the account ID (field 4) from an ARN like
// arn:aws:sts::123456789012:assumed-role/tier-dbbackup/dbbackup.
// Returns "" if the ARN doesn't look like one.
func accountFromArn(arn string) string {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) < 6 || parts[0] != "arn" {
		return ""
	}
	return parts[4]
}

func buildEnv(c creds, region string) []string {
	return []string{
		"PATH=" + helperBin,
		"SHELL=" + noShell,
		"HOME=" + sessionHome,
		"AWS_REGION=" + region,
		"AWS_DEFAULT_REGION=" + region,
		"AWS_PAGER=",
		"AWS_CONFIG_FILE=/dev/null",
		"AWS_SHARED_CREDENTIALS_FILE=/dev/null",
		"AWS_ACCESS_KEY_ID=" + c.AccessKeyID,
		"AWS_SECRET_ACCESS_KEY=" + c.SecretAccessKey,
		"AWS_SESSION_TOKEN=" + c.SessionToken,
	}
}

// isCredentialExport reports whether a parsed aws command is
// `configure export-credentials`, the CLI's built-in way to print the
// credentials of the current session. Matching is on exact tokens, in order,
// tolerating global options anywhere: a token exactly "configure" followed by
// a later token exactly "export-credentials". It deliberately ignores argv[0]
// (already known to be "aws") and never substring-matches user values.
func isCredentialExport(argv []string) bool {
	seenConfigure := false
	for _, tok := range argv[1:] {
		switch tok {
		case "configure":
			seenConfigure = true
		case "export-credentials":
			if seenConfigure {
				return true
			}
		}
	}
	return false
}

// runOne validates and executes a single input line, returning the child exit code.
func runOne(line string, env []string, sl logger, username, src string) int {
	argv, err := splitArgs(line)
	if err != nil {
		fmt.Fprintf(os.Stderr, "awsjail: %v\n", err)
		sl.Warning(logLine(username, src, line, -1, "parse_error", ""))
		return 2
	}
	if len(argv) == 0 {
		return 0
	}
	argv = helpToArgv(argv)
	if argv[0] != "aws" {
		fmt.Fprintf(os.Stderr, "%s: command not found (only 'aws' is permitted)\n", argv[0])
		sl.Warning(logLine(username, src, line, -1, "denied", ""))
		return 127
	}
	if isCredentialExport(argv) {
		fmt.Fprintln(os.Stderr, "awsjail: 'aws configure export-credentials' is not permitted")
		sl.Warning(logLine(username, src, line, -1, "denied", "credential_export"))
		return 127
	}
	cmd := exec.Command(awsBin, argv[1:]...)
	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// The audit record is written before control is handed to the child, so
	// even a command that is killed mid-run has a start event in the log.
	sl.Info(logLine(username, src, line, -1, "command_start", ""))

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigCh)

	code := 0
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "awsjail: cannot run aws: %v\n", err)
		code = 127
	} else {
		// Forward termination signals to the child until it exits, so a
		// signal aimed at awsjail (e.g. sshd tearing down the session)
		// reaches the actual command.
		done := make(chan struct{})
		go func() {
			for {
				select {
				case s := <-sigCh:
					_ = cmd.Process.Signal(s) // harmless once the child is gone
				case <-done:
					return
				}
			}
		}()
		err = cmd.Wait()
		close(done)
		if err != nil {
			if ee, ok := err.(*exec.ExitError); ok {
				code = ee.ExitCode()
			} else {
				code = 127
			}
		}
	}
	sl.Info(logLine(username, src, line, code, "command_finish", ""))
	return code
}

func sessionName(u string) string {
	s := sessRe.ReplaceAllString(u, "-")
	if len(s) > 64 {
		s = s[:64]
	}
	return s
}

// logLine builds one JSON audit record. reason is included only when set
// (e.g. "credential_export" for a denied export attempt); credential values
// are never logged.
func logLine(username, src, cmd string, exit int, action, reason string) string {
	m := map[string]any{
		"user": username, "src": src, "cmd": cmd, "exit": exit, "action": action,
	}
	if reason != "" {
		m["reason"] = reason
	}
	b, _ := json.Marshal(m)
	return string(b)
}

// helpToArgv maps `help` to `aws help` and `help s3` to `aws s3 help`.
// Pure convenience: the result still goes through the same argv[0] == "aws"
// check and direct exec, and `aws help` was already reachable in the jail —
// this adds no new capability. The pager is disabled (AWS_PAGER=) so the
// help text can't spawn less or a shell.
func helpToArgv(argv []string) []string {
	if argv[0] != "help" {
		return argv
	}
	out := make([]string, 0, len(argv)+1)
	out = append(out, "aws", "help")
	return append(out, argv[1:]...)
}

// splitArgs is a minimal POSIX-ish word splitter. It honors single quotes,
// double quotes and backslash escaping, and splits on unquoted whitespace. It
// deliberately does NOT interpret ; | & $ or backticks; those pass through as
// literal characters. That is safe because argv is exec'd directly without a
// shell, and it is what lets JMESPath --query expressions work.
func splitArgs(s string) ([]string, error) {
	var args []string
	var cur strings.Builder
	var inSingle, inDouble, escaped, hasTok bool
	for _, r := range s {
		if escaped {
			cur.WriteRune(r)
			escaped = false
			hasTok = true
			continue
		}
		switch {
		case r == '\\' && !inSingle:
			escaped = true
			hasTok = true
		case r == '\'' && !inDouble:
			inSingle = !inSingle
			hasTok = true
		case r == '"' && !inSingle:
			inDouble = !inDouble
			hasTok = true
		case (r == ' ' || r == '\t') && !inSingle && !inDouble:
			if hasTok {
				args = append(args, cur.String())
				cur.Reset()
				hasTok = false
			}
		default:
			cur.WriteRune(r)
			hasTok = true
		}
	}
	if inSingle || inDouble {
		return nil, fmt.Errorf("unbalanced quotes")
	}
	if escaped {
		return nil, fmt.Errorf("trailing backslash")
	}
	if hasTok {
		args = append(args, cur.String())
	}
	return args, nil
}
