# DeadByte — EDR/XDR/MDR evasion (simulation)

This document describes what DeadByte implements to reduce its detection surface in labs,
and — honestly — what it does **not** do. The goal is to train detection, so the code
favors plausibility over aggressiveness.

## Implemented techniques

### 1. Signature and static artifacts
- Static Go binaries without CGO: few dynamic dependencies, no external scripting runtime.
- `-trimpath` and `-ldflags "-s -w"` at build time: removes compilation paths and debug
  symbols (`scripts/build-all.sh`).
- Sensitive strings (C2 URLs, brand names) can be obfuscated with XOR+base64
  (`internal/obfs`, generator `deadbyte-xorgen`) — light obfuscation, not encryption.
- The payload configuration travels as an obfuscated blob (`-config`), avoiding cleartext
  arguments with URLs/keys in the process history.

### 2. Behavior
- **Delay + jitter**: an initial `-delay` (avoids sandbox timeouts) and sleep with
  percentage jitter (`-jitter`) to break heartbeat periodicity.
- **Single instance**: `O_EXCL` lock in temp — prevents multiple runs and reduces triage
  noise.
- **Self-rename** (`-self-rename`): copies the binary to a random name in temp and
  re-executes it with an environment marker, abandoning the original name.
- **Heartbeat interval configurable** by the C2 (`-beacon-interval` on the server): the C2
  controls cadence without rebuilding the payload.
- **Per-OS persistence** (`-persist`): Windows Startup, Linux `~/.config/autostart`, macOS
  LaunchAgent — the canonical paths most EDRs monitor.

### 3. Anti-analysis (heuristics, abortable with `-force`)
- CPUs ≤ 2 (typical sandbox VMs).
- VM/container environment variables (`VIRTUALBOX`, `VMWARE`, `KUBERNETES`, `CONTAINER`,
  `CI`) and a suspicious `HOSTNAME` (sandbox, malware, virustotal...).
- Presence of `/dev/kvm` on Linux.
- Refuses to run as root/admin without `-force` (protection and lower profile).

### 4. Copy destruction (Windows)
- `-wipe-vss`: `vssadmin delete shadows /all /quiet` — removes restore points that would
  allow recovery without the key (simulation of the real tactic).

## What is NOT implemented (deliberately)

| Technique | Status | Reason |
| --- | --- | --- |
| Code obfuscation (garble/obfuscator) | No | Keeps the code auditable; garble can be added at build time |
| Digital signing / signature-based AV evasion | No | Defeats the training purpose and the lab scope |
| Polymorphism / payload mutation | No | Complexity without benefit in the lab |
| Data exfiltration | No | Out of scope; the payload only sends telemetry metadata |
| EDR zero-day exploitation | No | Illegal/unethical and unnecessary for a simulation |
| MBR encryption / bootkit | No | Irreversible damage; incompatible with "simulation" |
| Worm / lateral movement | No | Scope restricted to the declared target host |

## Notes for the defensive exercise

1. **Telemetry**: the C2 receives hostname, user, OS/arch, interface IPs and directory lists
   in the initial beacon — an excellent correlation point in SIEM/XDR.
2. **Behavioral IOCs**: lock in temp, bulk file reads, large writes with a 1 MiB+16B pattern,
   `Chtimes` preserving mtime, creation of `README_DEADBYTE.txt`.
3. **Network**: JSON HTTP beacon with a fixed `User-Agent`
   `Mozilla/5.0 (compatible; DeadByte/<version>)` — detectable by UA rule + `/api/v1/*`
   path pattern.
4. **Recovery**: the decryptor is the proof of concept for the response process — key
   exports are recorded in the panel events.

## Recommended hardening before a real exercise

- TLS with a proper certificate on the C2 (`-tls-cert`/`-tls-key`); the payload uses
  `-insecure-tls` for lab use only.
- Change the `User-Agent` and API path per build (`internal/types`).
- Inject `BuiltinC2`/`BuiltinPubKey` via ldflags and remove runtime flags.
- Embed the `-config` blob (via ldflags/`-config-gen`) instead of passing it on the command
  line.
