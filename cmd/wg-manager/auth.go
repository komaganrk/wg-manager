package main

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"sync"
	"time"
)

type Auth struct {
	mu       sync.Mutex
	sessions map[string]time.Time
	password string
}

func NewAuth(password string) *Auth {
	return &Auth{
		sessions: make(map[string]time.Time),
		password: password,
	}
}

// Login validates the password and returns a new session token on success.
func (a *Auth) Login(password string) (string, bool) {
	if password != a.password {
		return "", false
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", false
	}
	token := hex.EncodeToString(raw)
	a.mu.Lock()
	a.sessions[token] = time.Now().Add(24 * time.Hour)
	a.mu.Unlock()
	return token, true
}

// Check returns true if the request carries a valid, unexpired session cookie.
func (a *Auth) Check(r *http.Request) bool {
	cookie, err := r.Cookie("session")
	if err != nil {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	expiry, ok := a.sessions[cookie.Value]
	if !ok {
		return false
	}
	if time.Now().After(expiry) {
		delete(a.sessions, cookie.Value)
		return false
	}
	return true
}

// Logout invalidates the session carried in the request cookie.
func (a *Auth) Logout(r *http.Request) {
	cookie, err := r.Cookie("session")
	if err != nil {
		return
	}
	a.mu.Lock()
	delete(a.sessions, cookie.Value)
	a.mu.Unlock()
}
