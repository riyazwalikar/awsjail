// admin/roles.go
package main

import (
	"encoding/json"
	"os"
	"path/filepath"
)

type roleEntry struct {
	RoleArn string `json:"role_arn"`
	Region  string `json:"region"`
}

func loadRoles(path string) (map[string]roleEntry, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	m := map[string]roleEntry{}
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// saveRolesAtomic writes m to path via a temp file in the same directory
// followed by rename, so a crash mid-write never leaves a torn roles.json.
func saveRolesAtomic(path string, m map[string]roleEntry) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".roles-*.json.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath) // no-op once renamed
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpPath, 0644); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

func upsertRole(path, username string, entry roleEntry) error {
	m, err := loadRoles(path)
	if err != nil {
		if os.IsNotExist(err) {
			m = map[string]roleEntry{}
		} else {
			return err
		}
	}
	m[username] = entry
	return saveRolesAtomic(path, m)
}

// deleteRole removes username from roles.json. The bool return reports
// whether username was present; removing an absent username is not an error.
func deleteRole(path, username string) (bool, error) {
	m, err := loadRoles(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	if _, ok := m[username]; !ok {
		return false, nil
	}
	delete(m, username)
	return true, saveRolesAtomic(path, m)
}
