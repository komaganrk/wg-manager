package main

import (
	"fmt"
	"net"
	"strings"
)

type Peer struct {
	Name       string
	PublicKey  string
	PrivateKey string // from PEER{N}_PRIVATE_KEY in secret, not in wg0.conf
	PSK        string
	IP         string // e.g. 10.66.66.2
	AllowedIPs string // e.g. 10.66.66.2/32
}

type WGConfig struct {
	Raw           string // original [Interface] block preserved as-is
	Peers         []Peer
	ServerPrivKey string
	ListenPort    string
}

// ParseWGConfig parses wg0.conf into a WGConfig.
func ParseWGConfig(conf string) WGConfig {
	var cfg WGConfig
	var currentPeer *Peer
	var interfaceLines []string
	inInterface := false

	for _, line := range strings.Split(conf, "\n") {
		trimmed := strings.TrimSpace(line)

		switch {
		case trimmed == "[Interface]":
			inInterface = true
			interfaceLines = append(interfaceLines, line)
		case trimmed == "[Peer]":
			if currentPeer != nil {
				cfg.Peers = append(cfg.Peers, *currentPeer)
			}
			currentPeer = &Peer{}
			inInterface = false
		case inInterface:
			interfaceLines = append(interfaceLines, line)
			if strings.HasPrefix(trimmed, "PrivateKey") {
				cfg.ServerPrivKey = valueAfterEq(trimmed)
			} else if strings.HasPrefix(trimmed, "ListenPort") {
				cfg.ListenPort = valueAfterEq(trimmed)
			}
		case currentPeer != nil:
			if strings.HasPrefix(trimmed, "# ") {
				currentPeer.Name = strings.TrimPrefix(trimmed, "# ")
			} else if strings.HasPrefix(trimmed, "PublicKey") {
				currentPeer.PublicKey = valueAfterEq(trimmed)
			} else if strings.HasPrefix(trimmed, "PresharedKey") {
				currentPeer.PSK = valueAfterEq(trimmed)
			} else if strings.HasPrefix(trimmed, "AllowedIPs") {
				currentPeer.AllowedIPs = valueAfterEq(trimmed)
				ip, _, _ := net.ParseCIDR(currentPeer.AllowedIPs)
				if ip != nil {
					currentPeer.IP = ip.String()
				}
			}
		}
	}
	if currentPeer != nil {
		cfg.Peers = append(cfg.Peers, *currentPeer)
	}

	cfg.Raw = strings.Join(interfaceLines, "\n")
	return cfg
}

// Marshal regenerates wg0.conf from the config.
func (c *WGConfig) Marshal() string {
	var sb strings.Builder
	sb.WriteString(c.Raw)
	sb.WriteString("\n")
	for _, p := range c.Peers {
		sb.WriteString("\n[Peer]\n")
		fmt.Fprintf(&sb, "# %s\n", p.Name)
		fmt.Fprintf(&sb, "PublicKey = %s\n", p.PublicKey)
		if p.PSK != "" {
			fmt.Fprintf(&sb, "PresharedKey = %s\n", p.PSK)
		}
		fmt.Fprintf(&sb, "AllowedIPs = %s\n", p.AllowedIPs)
	}
	return sb.String()
}

// NextIP returns the next available peer IP in the 10.66.66.0/24 subnet.
func (c *WGConfig) NextIP() string {
	max := 1
	for _, p := range c.Peers {
		var last int
		fmt.Sscanf(strings.Split(p.IP, ".")[3], "%d", &last)
		if last > max {
			max = last
		}
	}
	return fmt.Sprintf("10.66.66.%d", max+1)
}

// RemovePeer removes a peer by name, returns false if not found.
func (c *WGConfig) RemovePeer(name string) bool {
	for i, p := range c.Peers {
		if p.Name == name {
			c.Peers = append(c.Peers[:i], c.Peers[i+1:]...)
			return true
		}
	}
	return false
}

// FindPeer returns a peer by name.
func (c *WGConfig) FindPeer(name string) *Peer {
	for i := range c.Peers {
		if c.Peers[i].Name == name {
			return &c.Peers[i]
		}
	}
	return nil
}

// ServerPublicKey derives the server's public key from the parsed private key.
func (c *WGConfig) ServerPublicKey() (string, error) {
	if c.ServerPrivKey == "" {
		return "", fmt.Errorf("no PrivateKey in [Interface] block")
	}
	return PublicKeyFromPrivate(c.ServerPrivKey)
}

func valueAfterEq(s string) string {
	parts := strings.SplitN(s, "=", 2)
	if len(parts) != 2 {
		return ""
	}
	return strings.TrimSpace(parts[1])
}
