//go:build windows

package main

import (
	"os"
	"path/filepath"
	"strings"
)

// defaultTargetDirs discovers user data roots on Windows.
// Order: current profile (USERPROFILE / home) → every profile under
// %SystemDrive%\Users (minus system accounts). Never returns empty when
// the current user has a usable profile, even if listing C:\Users fails
// (restricted tokens, non-standard layouts, OneDrive-only homes, etc.).
func defaultTargetDirs() []string {
	seen := map[string]bool{}
	var dirs []string
	add := func(p string) {
		p = strings.TrimSpace(p)
		if p == "" {
			return
		}
		// normalize for dedupe (Windows is case-insensitive)
		key := strings.ToLower(filepath.Clean(p))
		if seen[key] {
			return
		}
		st, err := os.Stat(p)
		if err != nil || !st.IsDir() {
			return
		}
		seen[key] = true
		dirs = append(dirs, p)
	}

	// 1) current user — most reliable on lab VMs / non-admin shells
	if up := os.Getenv("USERPROFILE"); up != "" {
		add(up)
	}
	if hd, hp := os.Getenv("HOMEDRIVE"), os.Getenv("HOMEPATH"); hd != "" && hp != "" {
		add(filepath.Join(hd, hp))
	}
	if home, err := os.UserHomeDir(); err == nil {
		add(home)
	}

	// 2) common data folders under the current profile (if home itself was skipped)
	if up := os.Getenv("USERPROFILE"); up != "" {
		for _, sub := range []string{
			"Desktop", "Documents", "Downloads", "Pictures", "Videos", "Music",
			"OneDrive", "OneDrive - Personal",
		} {
			add(filepath.Join(up, sub))
		}
	}

	// 3) every real profile under %SystemDrive%\Users
	drive := os.Getenv("SystemDrive")
	if drive == "" {
		drive = "C:"
	}
	root := filepath.Join(drive, "Users")
	if entries, err := os.ReadDir(root); err == nil {
		skip := map[string]bool{
			"all users": true, "default": true, "default user": true,
			"public": true, "defaultuser0": true, "updatuser": true,
			"wdagutilityaccount": true, // Windows Sandbox
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			n := strings.ToLower(e.Name())
			if skip[n] || strings.HasPrefix(n, "ntuser") {
				continue
			}
			add(filepath.Join(root, e.Name()))
		}
	}

	// 4) last resort: Public + temp (still better than aborting the lab run)
	if len(dirs) == 0 {
		add(filepath.Join(drive, "Users", "Public"))
		add(os.TempDir())
	}
	return dirs
}
