# Run `go mod tidy` locally before building to ensure go.sum is present.
FROM golang:1.22-alpine AS builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o wg-manager ./cmd/wg-manager

FROM alpine:3.20
# ca-certificates is required for TLS connections to the Kubernetes API.
RUN apk add --no-cache ca-certificates
COPY --from=builder /build/wg-manager /wg-manager
EXPOSE 8080
ENTRYPOINT ["/wg-manager"]
