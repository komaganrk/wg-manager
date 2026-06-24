package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	qrcode "github.com/skip2/go-qrcode"
)

type loginData struct {
	Error string
}

type indexData struct {
	Peers   []Peer
	Error   string
	Success string
}

type qrData struct {
	Name    string
	Config  string
	QRImage string // base64-encoded PNG
}

func (a *App) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !a.auth.Check(r) {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		next(w, r)
	}
}

func (a *App) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	if a.auth.Check(r) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	a.render(w, "login.html", loginData{})
}

func (a *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	token, ok := a.auth.Login(r.FormValue("password"))
	if !ok {
		a.render(w, "login.html", loginData{Error: "Invalid password"})
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(24 * time.Hour),
	})
	http.Redirect(w, r, "/", http.StatusFound)
}

func (a *App) handleLogout(w http.ResponseWriter, r *http.Request) {
	a.auth.Logout(r)
	http.SetCookie(w, &http.Cookie{
		Name:   "session",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})
	http.Redirect(w, r, "/login", http.StatusFound)
}

func (a *App) handleIndex(w http.ResponseWriter, r *http.Request) {
	cfg, err := a.k8s.GetConfig(r.Context())
	if err != nil {
		a.render(w, "index.html", indexData{Error: "Load config: " + err.Error()})
		return
	}
	a.render(w, "index.html", indexData{Peers: cfg.Peers})
}

func (a *App) handleAddPeer(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		http.Error(w, "name required", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	cfg, err := a.k8s.GetConfig(ctx)
	if err != nil {
		a.render(w, "index.html", indexData{Error: "Load config: " + err.Error()})
		return
	}
	if cfg.FindPeer(name) != nil {
		a.render(w, "index.html", indexData{Peers: cfg.Peers, Error: "Peer " + name + " already exists"})
		return
	}

	privKey, pubKey, err := GenerateKeyPair()
	if err != nil {
		a.render(w, "index.html", indexData{Peers: cfg.Peers, Error: "Keygen: " + err.Error()})
		return
	}
	psk, err := GeneratePSK()
	if err != nil {
		a.render(w, "index.html", indexData{Peers: cfg.Peers, Error: "PSK gen: " + err.Error()})
		return
	}

	ip := cfg.NextIP(a.subnet)
	peer := Peer{
		Name:       name,
		PublicKey:  pubKey,
		PrivateKey: privKey,
		PSK:        psk,
		IP:         ip,
		AllowedIPs: ip + "/32",
	}
	cfg.Peers = append(cfg.Peers, peer)

	if err := a.k8s.SaveConfig(ctx, cfg); err != nil {
		cfg.Peers = cfg.Peers[:len(cfg.Peers)-1] // undo append for display
		a.render(w, "index.html", indexData{Peers: cfg.Peers, Error: "Save config: " + err.Error()})
		return
	}

	// Hot-add into the running WireGuard instance; secret update is the source of truth.
	if err := a.k8s.WGAddPeer(ctx, pubKey, psk, peer.AllowedIPs); err != nil {
		log.Printf("warn: hot-add peer %q: %v", name, err)
	}

	http.Redirect(w, r, "/", http.StatusFound)
}

func (a *App) handleDeletePeer(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")

	ctx := r.Context()
	cfg, err := a.k8s.GetConfig(ctx)
	if err != nil {
		http.Error(w, "load config: "+err.Error(), http.StatusInternalServerError)
		return
	}

	peer := cfg.FindPeer(name)
	if peer == nil {
		http.Error(w, "peer not found", http.StatusNotFound)
		return
	}
	pubKey := peer.PublicKey

	cfg.RemovePeer(name)

	if err := a.k8s.SaveConfig(ctx, cfg); err != nil {
		http.Error(w, "save config: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if err := a.k8s.WGRemovePeer(ctx, pubKey); err != nil {
		log.Printf("warn: hot-remove peer %q: %v", name, err)
	}

	http.Redirect(w, r, "/", http.StatusFound)
}

func (a *App) handleQR(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")

	ctx := r.Context()
	cfg, err := a.k8s.GetConfig(ctx)
	if err != nil {
		http.Error(w, "load config: "+err.Error(), http.StatusInternalServerError)
		return
	}

	peer := cfg.FindPeer(name)
	if peer == nil {
		http.Error(w, "peer not found", http.StatusNotFound)
		return
	}
	if peer.PrivateKey == "" {
		http.Error(w, "private key not available for this peer", http.StatusInternalServerError)
		return
	}

	serverPubKey, err := cfg.ServerPublicKey()
	if err != nil {
		http.Error(w, "server public key: "+err.Error(), http.StatusInternalServerError)
		return
	}

	confText := buildPeerConfig(*peer, serverPubKey, a.endpoint, a.endpointPort)

	png, err := qrcode.Encode(confText, qrcode.Medium, 256)
	if err != nil {
		http.Error(w, "qr encode: "+err.Error(), http.StatusInternalServerError)
		return
	}

	a.render(w, "qr.html", qrData{
		Name:    name,
		Config:  confText,
		QRImage: base64.StdEncoding.EncodeToString(png),
	})
}

func (a *App) handleConfig(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")

	ctx := r.Context()
	cfg, err := a.k8s.GetConfig(ctx)
	if err != nil {
		http.Error(w, "load config: "+err.Error(), http.StatusInternalServerError)
		return
	}

	peer := cfg.FindPeer(name)
	if peer == nil {
		http.Error(w, "peer not found", http.StatusNotFound)
		return
	}
	if peer.PrivateKey == "" {
		http.Error(w, "private key not available", http.StatusInternalServerError)
		return
	}

	serverPubKey, err := cfg.ServerPublicKey()
	if err != nil {
		http.Error(w, "server public key: "+err.Error(), http.StatusInternalServerError)
		return
	}

	confText := buildPeerConfig(*peer, serverPubKey, a.endpoint, a.endpointPort)

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.conf"`, name))
	fmt.Fprint(w, confText)
}

func (a *App) render(w http.ResponseWriter, name string, data any) {
	if err := a.tmpls.ExecuteTemplate(w, name, data); err != nil {
		log.Printf("template %s: %v", name, err)
	}
}

func listenPort(cfg *WGConfig) string {
	if cfg.ListenPort != "" {
		return cfg.ListenPort
	}
	return "51820"
}

type editData struct {
	Peer   Peer
	Subnet string
	Error  string
}

func (a *App) handleEditPage(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	cfg, err := a.k8s.GetConfig(r.Context())
	if err != nil {
		http.Error(w, "load config: "+err.Error(), http.StatusInternalServerError)
		return
	}
	peer := cfg.FindPeer(name)
	if peer == nil {
		http.Error(w, "peer not found", http.StatusNotFound)
		return
	}
	a.render(w, "edit.html", editData{Peer: *peer, Subnet: a.subnet})
}

func (a *App) handleUpdatePeer(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	newName := strings.TrimSpace(r.FormValue("newname"))
	newIP := strings.TrimSpace(r.FormValue("ip"))

	ctx := r.Context()
	cfg, err := a.k8s.GetConfig(ctx)
	if err != nil {
		http.Error(w, "load config: "+err.Error(), http.StatusInternalServerError)
		return
	}

	peer := cfg.FindPeer(name)
	if peer == nil {
		http.Error(w, "peer not found", http.StatusNotFound)
		return
	}

	if newName == "" {
		a.render(w, "edit.html", editData{Peer: *peer, Subnet: a.subnet, Error: "Name cannot be empty"})
		return
	}
	if newName != name {
		for _, p := range cfg.Peers {
			if p.Name == newName {
				a.render(w, "edit.html", editData{Peer: *peer, Subnet: a.subnet, Error: "Name " + newName + " is already in use"})
				return
			}
		}
	}

	_, ipNet, _ := net.ParseCIDR(a.subnet)
	if net.ParseIP(newIP) == nil || ipNet == nil || !ipNet.Contains(net.ParseIP(newIP)) {
		a.render(w, "edit.html", editData{Peer: *peer, Subnet: a.subnet, Error: "IP must be within " + a.subnet})
		return
	}
	for _, p := range cfg.Peers {
		if p.Name != name && p.IP == newIP {
			a.render(w, "edit.html", editData{Peer: *peer, Subnet: a.subnet, Error: newIP + " is already assigned to " + p.Name})
			return
		}
	}

	pubKey := peer.PublicKey
	peer.Name = newName
	peer.IP = newIP
	peer.AllowedIPs = newIP + "/32"

	if err := a.k8s.SaveConfig(ctx, cfg); err != nil {
		a.render(w, "edit.html", editData{Peer: *peer, Subnet: a.subnet, Error: "Save failed: " + err.Error()})
		return
	}

	if err := a.k8s.WGSetAllowedIPs(ctx, pubKey, peer.AllowedIPs); err != nil {
		log.Printf("warn: hot-update allowed-ips for %q: %v", name, err)
	}

	http.Redirect(w, r, "/", http.StatusFound)
}

// ── live stats ────────────────────────────────────────────────────────────────

type peerStat struct {
	Name          string `json:"name"`
	PublicKey     string `json:"pubkey"`
	Endpoint      string `json:"endpoint"`
	LastHandshake int64  `json:"last_handshake"`
	RxBytes       int64  `json:"rx_bytes"`
	TxBytes       int64  `json:"tx_bytes"`
}

type statsPayload struct {
	Ts    int64      `json:"ts"`
	Peers []peerStat `json:"peers"`
}

func (a *App) handleStats(w http.ResponseWriter, r *http.Request) {
	a.render(w, "stats.html", nil)
}

func (a *App) handleStatsStream(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	ctx := r.Context()

	send := func() {
		cfg, err := a.k8s.GetConfig(ctx)
		if err != nil {
			fmt.Fprintf(w, "data: {\"error\":%q}\n\n", err.Error())
			flusher.Flush()
			return
		}
		names := make(map[string]string, len(cfg.Peers))
		for _, p := range cfg.Peers {
			names[p.PublicKey] = p.Name
		}
		dump, err := a.k8s.WGShowDump(ctx)
		if err != nil {
			fmt.Fprintf(w, "data: {\"error\":%q}\n\n", err.Error())
			flusher.Flush()
			return
		}
		payload := parseDump(dump, names)
		data, _ := json.Marshal(payload)
		fmt.Fprintf(w, "data: %s\n\n", data)
		flusher.Flush()
	}

	send() // immediate first push

	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			send()
		}
	}
}

// parseDump parses `wg show wg0 dump` tab-separated output.
// Peer lines have 8 fields; the interface line has 4 — skip everything else.
func parseDump(dump string, names map[string]string) statsPayload {
	var peers []peerStat
	for _, line := range strings.Split(strings.TrimSpace(dump), "\n") {
		f := strings.Split(line, "\t")
		if len(f) != 8 {
			continue
		}
		p := peerStat{
			PublicKey: f[0],
			Endpoint:  f[2],
			Name:      names[f[0]],
		}
		p.LastHandshake, _ = strconv.ParseInt(f[4], 10, 64)
		p.RxBytes, _ = strconv.ParseInt(f[5], 10, 64)
		p.TxBytes, _ = strconv.ParseInt(f[6], 10, 64)
		peers = append(peers, p)
	}
	return statsPayload{Ts: time.Now().Unix(), Peers: peers}
}

func buildPeerConfig(p Peer, serverPubKey, endpoint, port string) string {
	ep := endpoint
	if ep == "" {
		ep = "YOUR_SERVER_IP"
	}
	return fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s/24

[Peer]
PublicKey = %s
PresharedKey = %s
Endpoint = %s:%s
AllowedIPs = 10.66.66.0/24
PersistentKeepalive = 25
`, p.PrivateKey, p.IP, serverPubKey, p.PSK, ep, port)
}
