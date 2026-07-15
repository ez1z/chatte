// Chatte VPN backend: subscription validation and config distribution.
package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

type ServerEntry struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Country  string `json:"country"`
	City     string `json:"city"`
	Protocol string `json:"protocol"`
	Config   string `json:"config"`
}

type SubscriptionResponse struct {
	Expires string        `json:"expires"`
	Servers []ServerEntry `json:"servers"`
}

type app struct {
	db *sql.DB
}

var (
	errNotFound = errors.New("subscription not found")
	errExpired  = errors.New("subscription expired or revoked")
)

func (a *app) lookupSubscription(token string) (*SubscriptionResponse, error) {
	sum := sha256.Sum256([]byte(token))
	hash := hex.EncodeToString(sum[:])

	var subID int64
	var expires time.Time
	var revoked bool
	err := a.db.QueryRow(
		`SELECT id, expires_at, revoked FROM subscriptions WHERE token_hash = $1`, hash,
	).Scan(&subID, &expires, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errNotFound
	}
	if err != nil {
		return nil, err
	}
	if revoked || time.Now().After(expires) {
		return nil, errExpired
	}

	rows, err := a.db.Query(`
		SELECT s.id, s.name, s.country, s.city, s.protocol, pc.config
		FROM peer_configs pc
		JOIN servers s ON s.id = pc.server_id
		WHERE pc.subscription_id = $1 AND s.enabled
		ORDER BY s.id`, subID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	resp := &SubscriptionResponse{
		Expires: expires.UTC().Format(time.RFC3339),
		Servers: []ServerEntry{},
	}
	for rows.Next() {
		var e ServerEntry
		if err := rows.Scan(&e.ID, &e.Name, &e.Country, &e.City, &e.Protocol, &e.Config); err != nil {
			return nil, err
		}
		resp.Servers = append(resp.Servers, e)
	}
	return resp, rows.Err()
}

func (a *app) handleSubscription(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	if len(token) < 8 || len(token) > 128 {
		http.Error(w, "invalid token", http.StatusBadRequest)
		return
	}
	resp, err := a.lookupSubscription(token)
	switch {
	case errors.Is(err, errNotFound):
		http.Error(w, "not found", http.StatusNotFound)
		return
	case errors.Is(err, errExpired):
		http.Error(w, "subscription expired", http.StatusForbidden)
		return
	case err != nil:
		log.Printf("subscription lookup: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(resp)
}

// rateLimit: fixed-window per-IP limiter.
// ponytail: in-memory, per-instance; move to the gateway when horizontally scaled.
func rateLimit(next http.Handler) http.Handler {
	type window struct {
		count int
		start time.Time
	}
	var mu sync.Mutex
	hits := map[string]*window{}
	const perMinute = 30

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			ip = r.RemoteAddr
		}
		mu.Lock()
		wnd := hits[ip]
		if wnd == nil || time.Since(wnd.start) > time.Minute {
			wnd = &window{start: time.Now()}
			hits[ip] = wnd
			if len(hits) > 100000 { // shed memory under abuse
				hits = map[string]*window{ip: wnd}
			}
		}
		wnd.count++
		over := wnd.count > perMinute
		mu.Unlock()
		if over {
			http.Error(w, "rate limited", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func main() {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		dsn = "postgres://chatte:chatte@localhost:5432/chatte?sslmode=disable"
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		log.Fatal(err)
	}
	for i := 0; ; i++ { // wait for postgres in compose
		if err = db.Ping(); err == nil {
			break
		}
		if i >= 30 {
			log.Fatalf("database unreachable: %v", err)
		}
		time.Sleep(time.Second)
	}

	a := &app{db: db}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})
	mux.HandleFunc("GET /v1/subscription/{token}", a.handleSubscription)

	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	log.Printf("chatte api listening on %s", addr)
	srv := &http.Server{
		Addr:              addr,
		Handler:           rateLimit(mux),
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Fatal(srv.ListenAndServe())
}
