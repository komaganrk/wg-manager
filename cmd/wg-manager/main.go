package main

import (
	"embed"
	"html/template"
	"log"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/joho/godotenv"
)

//go:embed templates
var templateFS embed.FS

// SubnetPool is a named WireGuard peer address pool.
type SubnetPool struct {
	Name        string
	CIDR        string
	ExtraRoutes []string // additional CIDRs routed into the tunnel for peers in this pool (e.g. VCN access)
	net         *net.IPNet
}

type App struct {
	auth         *Auth
	k8s          *K8sClient
	endpoint     string
	endpointPort string
	subnets      []SubnetPool
	tmpls        *template.Template
}

func main() {
	// Load .env if present; no-op in Kubernetes where env vars come from the pod spec.
	_ = godotenv.Load()

	password := os.Getenv("WG_PASSWORD")
	if password == "" {
		log.Fatal("WG_PASSWORD env var is required")
	}

	k8s, err := NewK8sClient(
		getenv("WG_NAMESPACE", "vpn"),
		getenv("WG_SECRET", "wireguard-keys"),
	)
	if err != nil {
		log.Fatalf("k8s client: %v", err)
	}

	// WG_SUBNETS: comma-separated "Name:cidr" pairs, e.g.
	//   "Friends:10.66.66.0/24,Personal:10.99.99.0/24"
	// Falls back to WG_SUBNET for single-subnet backward compat.
	subnetsRaw := os.Getenv("WG_SUBNETS")
	if subnetsRaw == "" {
		subnetsRaw = "Default:" + getenv("WG_SUBNET", "10.0.0.0/24")
	}
	subnets := parseSubnets(subnetsRaw)
	if len(subnets) == 0 {
		log.Fatal("no valid subnets configured")
	}

	// WG_SUBNET_ROUTES: comma-separated "Name:cidr" pairs granting a pool
	// extra routes beyond its own subnet, e.g. "Personal:10.0.0.0/16" to let
	// the Personal pool reach the OCI VCN while Friends stays confined.
	applyExtraRoutes(subnets, os.Getenv("WG_SUBNET_ROUTES"))

	tmpls := template.Must(template.ParseFS(templateFS, "templates/*.html"))

	app := &App{
		auth:         NewAuth(password),
		k8s:          k8s,
		endpoint:     os.Getenv("WG_ENDPOINT"),
		endpointPort: getenv("WG_ENDPOINT_PORT", "443"),
		subnets:      subnets,
		tmpls:        tmpls,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /login", app.handleLoginPage)
	mux.HandleFunc("POST /login", app.handleLogin)
	mux.HandleFunc("POST /logout", app.handleLogout)
	mux.HandleFunc("GET /{$}", app.requireAuth(app.handleIndex))
	mux.HandleFunc("POST /peer/add", app.requireAuth(app.handleAddPeer))
	mux.HandleFunc("POST /peer/delete", app.requireAuth(app.handleDeletePeer))
	mux.HandleFunc("GET /peer/qr", app.requireAuth(app.handleQR))
	mux.HandleFunc("GET /peer/config", app.requireAuth(app.handleConfig))
	mux.HandleFunc("GET /peer/edit", app.requireAuth(app.handleEditPage))
	mux.HandleFunc("POST /peer/update", app.requireAuth(app.handleUpdatePeer))
	mux.HandleFunc("GET /stats", app.requireAuth(app.handleStats))
	mux.HandleFunc("GET /stats/stream", app.requireAuth(app.handleStatsStream))

	log.Println("listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}

func parseSubnets(raw string) []SubnetPool {
	var pools []SubnetPool
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		idx := strings.Index(part, ":")
		if idx < 0 {
			continue
		}
		name := strings.TrimSpace(part[:idx])
		cidr := strings.TrimSpace(part[idx+1:])
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			log.Printf("warn: invalid subnet %q: %v", cidr, err)
			continue
		}
		pools = append(pools, SubnetPool{Name: name, CIDR: cidr, net: ipNet})
	}
	return pools
}

// applyExtraRoutes parses WG_SUBNET_ROUTES and attaches ExtraRoutes to the
// matching pools by name. Unknown pool names are logged and skipped.
func applyExtraRoutes(subnets []SubnetPool, raw string) {
	if raw == "" {
		return
	}
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		idx := strings.Index(part, ":")
		if idx < 0 {
			continue
		}
		name := strings.TrimSpace(part[:idx])
		cidr := strings.TrimSpace(part[idx+1:])
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			log.Printf("warn: invalid extra route %q for pool %q: %v", cidr, name, err)
			continue
		}
		found := false
		for i := range subnets {
			if subnets[i].Name == name {
				subnets[i].ExtraRoutes = append(subnets[i].ExtraRoutes, cidr)
				found = true
				break
			}
		}
		if !found {
			log.Printf("warn: WG_SUBNET_ROUTES names unknown pool %q", name)
		}
	}
}

// peerSubnetCIDR returns the CIDR of the subnet that contains the given IP,
// falling back to the first subnet if none match.
func (a *App) peerSubnetCIDR(ip string) string {
	parsed := net.ParseIP(ip)
	for _, pool := range a.subnets {
		if pool.net.Contains(parsed) {
			return pool.CIDR
		}
	}
	return a.subnets[0].CIDR
}

// peerAllowedIPs returns the full AllowedIPs string for a peer's client
// config: its own pool CIDR plus any ExtraRoutes granted to that pool.
func (a *App) peerAllowedIPs(ip string) string {
	parsed := net.ParseIP(ip)
	for _, pool := range a.subnets {
		if pool.net.Contains(parsed) {
			return strings.Join(append([]string{pool.CIDR}, pool.ExtraRoutes...), ",")
		}
	}
	return a.subnets[0].CIDR
}

// peerSubnetName returns the human-readable name of the subnet containing ip.
func (a *App) peerSubnetName(ip string) string {
	parsed := net.ParseIP(ip)
	for _, pool := range a.subnets {
		if pool.net.Contains(parsed) {
			return pool.Name
		}
	}
	return ""
}

// subnetByName finds a pool by name; returns nil if not found.
func (a *App) subnetByName(name string) *SubnetPool {
	for i := range a.subnets {
		if a.subnets[i].Name == name {
			return &a.subnets[i]
		}
	}
	return nil
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
