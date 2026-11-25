// Package rans builds the ransom note templates.
package rans

import "fmt"

// NoteFilename is the default ransom note file name.
const NoteFilename = "README_DEADBYTE.txt"

// Note builds the ransom note text. panelURL is where the victim is told to go
// (the C2 panel); victimID identifies the infection.
func Note(panelURL, victimID, extra string, paid bool) string {
	status := "PENDING"
	if paid {
		status = "PAID (simulation)"
	}
	note := fmt.Sprintf(`============================================================
  DeadByte - RANSOMWARE SIMULATION (CONTROLLED ENVIRONMENT)
  This file and all of your data have been encrypted.
  There is NO real payment. This is an authorized exercise.
============================================================

[NOTICE: authorized lab - no real payment]
Your files were protected with strong encryption
(X25519 + AES-256-GCM). Without the correct master key,
recovery is not feasible.

Victim identifier      : %s
Status                 : %s
Support panel          : %s

Instructions:
  1. Open the panel shown above.
  2. Enter the victim identifier.
  3. After the (simulated) release, use the
     "deadbyte-decrypt" tool provided by the operator.

Legal notice: this simulated environment is the property of
the authorized operator. No real data was compromised.
`, victimID, status, panelURL)
	if extra != "" {
		note += "\n[Operator message]\n" + extra + "\n"
	}
	return note
}
