package main

import (
	"embed"
	"html/template"
	"log"
	"net/http"
	"os"

	"github.com/joho/godotenv"
)

//go:embed templates
var templateFS embed.FS

type App struct {
	auth         *Auth
	k8s          *K8sClient
	endpoint     string
	endpointPort string
	subnet       string
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

	tmpls := template.Must(template.ParseFS(templateFS, "templates/*.html"))

	app := &App{
		auth:         NewAuth(password),
		k8s:          k8s,
		endpoint:     os.Getenv("WG_ENDPOINT"),
		endpointPort: getenv("WG_ENDPOINT_PORT", "443"),
		subnet:       getenv("WG_SUBNET", "10.0.0.0/24"),
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

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
