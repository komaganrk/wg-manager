# wg-manager

Minimal WireGuard peer manager for Kubernetes — add, edit, delete peers and generate mobile QR codes, without wg-easy's Node.js + privileged container risk.

> **Deployment focus:** This project is built and tested for Kubernetes. Docker Compose, bare-metal, or other deployment modes are not included but contributions are welcome — see [Contributing](#contributing).

## Features

- List peers with IP address
- Add peer — auto-assigns next IP, generates Curve25519 keypair + PSK
- Edit peer — reassign IP with conflict detection and hot-reload
- Delete peer
- QR code + downloadable `.conf` for mobile onboarding
- Hot-reload via `wg set` exec into the WireGuard pod (no restarts, no dropped connections)
- Password authentication with 24h session cookie
- Server-rendered HTML — no JavaScript frameworks, no CDN dependencies

## How it works

- Reads and writes peer config directly from a Kubernetes Secret (`wireguard-keys` in the `vpn` namespace)
- After updating the secret, execs `wg set wg0 peer ...` into the running WireGuard pod for immediate effect
- Uses an in-cluster ServiceAccount with a minimal Role (secret get/update, pod list/get, pod exec) — no cluster-admin, no privileged containers

## Requirements

- Kubernetes cluster with WireGuard running as a pod (label `app=wireguard`)
- WireGuard config stored in a Secret with the following structure:
  - `wg0.conf` — full server config
  - `PEER{N}_NAME`, `PEER{N}_PUBLIC_KEY`, `PEER{N}_PRIVATE_KEY`, `PEER{N}_PSK` — per-peer keys

## Deployment

### 1. Apply RBAC

```bash
kubectl apply -f k8s/rbac.yaml
```

### 2. Create the password secret

```bash
kubectl -n vpn create secret generic wg-manager-secret \
  --from-literal=password=<YOUR_PASSWORD>
```

### 3. Build and push the image

Edit `Makefile` — set `REGISTRY` to your container registry and `PLATFORM` to match your cluster nodes (`linux/amd64` or `linux/arm64`), then:

```bash
make build
```

### 4. Deploy

Edit `k8s/deployment.yaml` — set your image and `WG_ENDPOINT` (the server's public IP or hostname), then:

```bash
make deploy
```

### 5. Access

```bash
make port-forward
```

Open `http://localhost:8080`.

## Makefile targets

| Target | Description |
|---|---|
| `make build` | Build + push image (`REGISTRY`, `TAG`, `PLATFORM` overridable) |
| `make deploy` | `kubectl apply` RBAC + deployment |
| `make restart` | Rollout restart and wait |
| `make logs` | Follow pod logs |
| `make port-forward` | Forward `localhost:8080` → service |

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `WG_PASSWORD` | required | Login password |
| `WG_ENDPOINT` | — | Server public IP/hostname used in generated peer configs and QR codes |
| `WG_NAMESPACE` | `vpn` | Namespace containing the WireGuard pod and secret |
| `WG_SECRET` | `wireguard-keys` | Name of the Kubernetes Secret |

## Security notes

- RBAC Role is scoped to the exact secret name (`resourceNames: ["wireguard-keys"]`)
- Container runs as non-root (`runAsUser: 65534`), read-only root filesystem, all Linux capabilities dropped
- No privileged container required — peer management uses the K8s exec API, not a host socket
- PSK is passed to `wg set` via stdin (not command-line args) to keep it out of `/proc`

## Contributing

The core of this project (`cmd/wg-manager/`) is a plain Go binary with no Kubernetes-specific imports — it talks to the K8s API but the peer logic, keygen, and UI are fully portable.

If you'd like to add support for a different deployment mode (Docker Compose with a mounted `wg0.conf`, systemd, bare-metal, etc.), contributions are welcome. Open an issue to discuss the approach before sending a PR.

## License

MIT — see [LICENSE](LICENSE).
