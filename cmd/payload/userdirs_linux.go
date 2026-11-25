//go:build linux

package main

import (
	"os"
	"path/filepath"
)

// defaultTargetDirs discovers every profile under /home.
func defaultTargetDirs() []string {
	entries, err := os.ReadDir("/home")
	if err != nil {
		return nil
	}
	var dirs []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if e.Name() == "lost+found" {
			continue
		}
		dirs = append(dirs, filepath.Join("/home", e.Name()))
	}
	return dirs
}
