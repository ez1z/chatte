package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestTokenValidation(t *testing.T) {
	a := &app{} // db never reached for invalid tokens
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/subscription/{token}", a.handleSubscription)

	for _, tok := range []string{"short", strings.Repeat("a", 200)} {
		req := httptest.NewRequest("GET", "/v1/subscription/"+tok, nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("token %q: got %d, want 400", tok, rec.Code)
		}
	}
}

func TestRateLimit(t *testing.T) {
	h := rateLimit(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	var last int
	for i := 0; i < 40; i++ {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "10.0.0.1:1234"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		last = rec.Code
	}
	if last != http.StatusTooManyRequests {
		t.Errorf("41st request: got %d, want 429", last)
	}
	// different IP unaffected
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.2:1234"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("fresh IP: got %d, want 200", rec.Code)
	}
}
