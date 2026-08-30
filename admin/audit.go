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
