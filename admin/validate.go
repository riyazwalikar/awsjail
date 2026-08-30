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
