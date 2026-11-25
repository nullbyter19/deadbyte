// Package store persists C2 state (infections, events, commands, keys) in an
// embedded bbolt database. The master private key is stored only in sealed
// (Argon2id + AES-256-GCM) form.
package store

import (
	"encoding/json"
	"errors"
	"time"

	"go.etcd.io/bbolt"

	"deadbyte/internal/types"
)

var (
	bktMeta       = []byte("meta")
	bktInfect     = []byte("infections")
	bktEvents     = []byte("events")
	bktCommands   = []byte("commands")
	keyMasterPub  = "master_pub_b64"
	keyMasterPriv = "master_priv_sealed"
	keyAdminTok   = "admin_token"
)

// Store wraps a bbolt database.
type Store struct {
	db *bbolt.DB
}

// Open opens (creating if needed) the database at path.
func Open(path string) (*Store, error) {
	db, err := bbolt.Open(path, 0o600, &bbolt.Options{Timeout: 2 * time.Second})
	if err != nil {
		return nil, err
	}
	err = db.Update(func(tx *bbolt.Tx) error {
		for _, b := range [][]byte{bktMeta, bktInfect, bktEvents, bktCommands} {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

// Close releases the database.
func (s *Store) Close() error { return s.db.Close() }

// ---------- meta ----------

func (s *Store) GetMeta(key string) (string, error) {
	var out string
	err := s.db.View(func(tx *bbolt.Tx) error {
		out = string(tx.Bucket(bktMeta).Get([]byte(key)))
		return nil
	})
	return out, err
}

func (s *Store) SetMeta(key, val string) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		return tx.Bucket(bktMeta).Put([]byte(key), []byte(val))
	})
}

// ---------- infections ----------

func (s *Store) UpsertInfection(inf *types.Infection) error {
	b, err := json.Marshal(inf)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bbolt.Tx) error {
		return tx.Bucket(bktInfect).Put([]byte(inf.ID), b)
	})
}

func (s *Store) GetInfection(id string) (*types.Infection, error) {
	var inf *types.Infection
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bktInfect).Get([]byte(id))
		if b == nil {
			return errors.New("store: infection not found")
		}
		return json.Unmarshal(b, &inf)
	})
	return inf, err
}

func (s *Store) ListInfections() ([]*types.Infection, error) {
	var out []*types.Infection
	err := s.db.View(func(tx *bbolt.Tx) error {
		return tx.Bucket(bktInfect).ForEach(func(k, v []byte) error {
			var inf types.Infection
			if err := json.Unmarshal(v, &inf); err != nil {
				return err
			}
			out = append(out, &inf)
			return nil
		})
	})
	return out, err
}

// ---------- events ----------

const maxEventsPerInfection = 200

// appendEvent appends ev to the bucket key list (trimmed to the cap).
func appendEvent(bkt *bbolt.Bucket, key []byte, b []byte) error {
	var list [][]byte
	if raw := bkt.Get(key); raw != nil {
		_ = json.Unmarshal(raw, &list)
	}
	list = append(list, b)
	if len(list) > maxEventsPerInfection {
		list = list[len(list)-maxEventsPerInfection:]
	}
	enc, _ := json.Marshal(list)
	return bkt.Put(key, enc)
}

func (s *Store) AddEvent(ev types.Event) error {
	b, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bbolt.Tx) error {
		bkt := tx.Bucket(bktEvents)
		// Always mirror into the global feed (used by GET /api/v1/events).
		if err := appendEvent(bkt, []byte("global"), b); err != nil {
			return err
		}
		if ev.InfID != "" {
			return appendEvent(bkt, []byte("inf:"+ev.InfID), b)
		}
		return nil
	})
}

func (s *Store) ListEvents(infID string, limit int) ([]types.Event, error) {
	key := []byte("inf:" + infID)
	if infID == "" {
		key = []byte("global")
	}
	var out []types.Event
	err := s.db.View(func(tx *bbolt.Tx) error {
		raw := tx.Bucket(bktEvents).Get(key)
		if raw == nil {
			return nil
		}
		var list [][]byte
		if err := json.Unmarshal(raw, &list); err != nil {
			return err
		}
		start := 0
		if limit > 0 && len(list) > limit {
			start = len(list) - limit
		}
		for _, b := range list[start:] {
			var ev types.Event
			if err := json.Unmarshal(b, &ev); err != nil {
				return err
			}
			out = append(out, ev)
		}
		return nil
	})
	return out, err
}

// ---------- commands ----------

func (s *Store) AddCommand(infID string, cmd types.Command) error {
	b, err := json.Marshal(cmd)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bbolt.Tx) error {
		bkt := tx.Bucket(bktCommands)
		var list [][]byte
		if raw := bkt.Get([]byte(infID)); raw != nil {
			_ = json.Unmarshal(raw, &list)
		}
		list = append(list, b)
		enc, _ := json.Marshal(list)
		return bkt.Put([]byte(infID), enc)
	})
}

// DrainCommands returns and clears pending commands for an infection.
func (s *Store) DrainCommands(infID string) ([]types.Command, error) {
	var out []types.Command
	err := s.db.Update(func(tx *bbolt.Tx) error {
		bkt := tx.Bucket(bktCommands)
		raw := bkt.Get([]byte(infID))
		if raw == nil {
			return nil
		}
		var list [][]byte
		if err := json.Unmarshal(raw, &list); err != nil {
			return err
		}
		for _, b := range list {
			var c types.Command
			if err := json.Unmarshal(b, &c); err != nil {
				return err
			}
			out = append(out, c)
		}
		return bkt.Delete([]byte(infID))
	})
	return out, err
}
