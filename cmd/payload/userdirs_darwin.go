//go:build darwin

package main

import (
	"os"
	"path/filepath"
	"strings"
)

// defaultTargetDirs discovers every profile under /Users.
func defaultTargetDirs() []string {
	entries, err := os.ReadDir("/Users")
	if err != nil {
		return nil
	}
	skip := map[string]bool{"shared": true, ".localized": true, "guest": true, "deleted users": true}
	var dirs []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if skip[strings.ToLower(e.Name())] {
			continue
		}
		dirs = append(dirs, filepath.Join("/Users", e.Name()))
	}
	return dirs
}
