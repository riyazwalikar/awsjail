// admin/main.go
package main

import (
	"flag"
	"fmt"
	"log/syslog"
	"os"
	"os/user"
	"path/filepath"
	"sort"
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

var protectedUsernames = map[string]bool{
	"root":          true,
	"bastion-admin": true,
}

func isAwsjailMember(u *user.User) (bool, error) {
	groupIDs, err := u.GroupIds()
	if err != nil {
		return false, err
	}
	awsjailGrp, err := user.LookupGroup(awsjailGroup)
	if err != nil {
		return false, err
	}
	for _, gid := range groupIDs {
		if gid == awsjailGrp.Gid {
			return true, nil
		}
	}
	return false, nil
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

	if protectedUsernames[*username] {
		fail("add-user", fmt.Errorf("refusing to manage protected account %q", *username))
	}
	if existing, lookupErr := user.Lookup(*username); lookupErr == nil {
		member, memberErr := isAwsjailMember(existing)
		if memberErr != nil {
			fail("add-user", fmt.Errorf("checking group membership for %q: %w", *username, memberErr))
		}
		if !member {
			fail("add-user", fmt.Errorf("refusing to adopt existing account %q: not already a member of the %s group", *username, awsjailGroup))
		}
	}

	sl := openAudit()
	defer sl.Close()

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
	auditLog(sl, "add_user", *username, "ok")
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

	sl := openAudit()
	defer sl.Close()

	removed, err := deleteRole(rolesPath, *username)
	if err != nil {
		fail("remove-user", err)
	}

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
	usernames := make([]string, 0, len(m))
	for username := range m {
		usernames = append(usernames, username)
	}
	sort.Strings(usernames)
	fmt.Printf("%-16s %-60s %-15s %-52s %s\n", "USERNAME", "ROLE_ARN", "REGION", "KEY_FINGERPRINT", "STATUS")
	for _, username := range usernames {
		entry := m[username]
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
