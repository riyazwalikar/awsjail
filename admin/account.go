package main

import (
	"fmt"
	"os/exec"
	"os/user"
)

const (
	awsjailShell = "/usr/local/bin/awsjail"
	awsjailGroup = "awsjail"
)

// useraddArgs and usermodArgs are separated from execution so their exact
// argument lists are unit-testable without invoking useradd/usermod.
func useraddArgs(username string) []string {
	return []string{"-m", "-G", awsjailGroup, "-s", awsjailShell, username}
}

func usermodArgs(username string) []string {
	return []string{"-s", awsjailShell, "-aG", awsjailGroup, username}
}

// ensureUnixAccount makes sure username exists with the awsjail login
// shell and group membership: creates it via useradd if absent, or heals
// a drifted existing account via usermod.
func ensureUnixAccount(username string) error {
	_, err := user.Lookup(username)
	if err != nil {
		if _, ok := err.(user.UnknownUserError); !ok {
			return fmt.Errorf("looking up %s: %w", username, err)
		}
		cmd := exec.Command("useradd", useraddArgs(username)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("useradd %s: %v: %s", username, err, out)
		}
		return nil
	}
	cmd := exec.Command("usermod", usermodArgs(username)...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("usermod %s: %v: %s", username, err, out)
	}
	return nil
}
