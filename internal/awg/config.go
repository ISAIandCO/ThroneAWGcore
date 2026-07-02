package awg

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

const defaultMTU = 1408

type Config struct {
	PrivateKey string
	Address    []netip.Prefix
	DNS        []netip.Addr
	MTU        int
	Jc         int
	Jmin       int
	Jmax       int
	S1         int
	S2         int
	S3         int
	S4         int
	H1         string
	H2         string
	H3         string
	H4         string
	I1         string
	I2         string
	I3         string
	I4         string
	I5         string
	Peers      []Peer
}

type Peer struct {
	PublicKey                   string
	PresharedKey                string
	Endpoint                    string
	AllowedIPs                  []netip.Prefix
	PersistentKeepaliveInterval int
}

func LoadConfig(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ParseConfig(f)
}

func ParseConfig(r interface{ Read([]byte) (int, error) }) (*Config, error) {
	cfg := &Config{MTU: defaultMTU}
	var section string
	var currentPeer *Peer

	scanner := bufio.NewScanner(r)
	for lineNo := 1; scanner.Scan(); lineNo++ {
		line := stripComment(strings.TrimSpace(scanner.Text()))
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			switch section {
			case "interface":
				currentPeer = nil
			case "peer":
				cfg.Peers = append(cfg.Peers, Peer{})
				currentPeer = &cfg.Peers[len(cfg.Peers)-1]
			default:
				return nil, fmt.Errorf("line %d: unsupported section %q", lineNo, section)
			}
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("line %d: expected key=value", lineNo)
		}
		key = normalizeKey(key)
		value = strings.TrimSpace(value)

		switch section {
		case "interface":
			if err := parseInterfaceKey(cfg, key, value); err != nil {
				return nil, fmt.Errorf("line %d: %w", lineNo, err)
			}
		case "peer":
			if currentPeer == nil {
				return nil, fmt.Errorf("line %d: peer key outside peer section", lineNo)
			}
			if err := parsePeerKey(currentPeer, key, value); err != nil {
				return nil, fmt.Errorf("line %d: %w", lineNo, err)
			}
		default:
			return nil, fmt.Errorf("line %d: key outside section", lineNo)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (cfg *Config) Validate() error {
	if err := validateKey("PrivateKey", cfg.PrivateKey, false); err != nil {
		return err
	}
	if len(cfg.Address) == 0 {
		return fmt.Errorf("Address is required")
	}
	if len(cfg.Peers) == 0 {
		return fmt.Errorf("at least one Peer is required")
	}
	if cfg.MTU <= 0 {
		return fmt.Errorf("MTU must be positive")
	}
	if cfg.Jmin > cfg.Jmax && cfg.Jmax != 0 {
		return fmt.Errorf("Jmin must be <= Jmax")
	}
	for idx, peer := range cfg.Peers {
		if err := validateKey(fmt.Sprintf("Peer[%d].PublicKey", idx), peer.PublicKey, false); err != nil {
			return err
		}
		if err := validateKey(fmt.Sprintf("Peer[%d].PresharedKey", idx), peer.PresharedKey, true); err != nil {
			return err
		}
		if peer.Endpoint == "" {
			return fmt.Errorf("Peer[%d].Endpoint is required", idx)
		}
		if _, _, err := net.SplitHostPort(peer.Endpoint); err != nil {
			return fmt.Errorf("Peer[%d].Endpoint must be host:port: %w", idx, err)
		}
		if len(peer.AllowedIPs) == 0 {
			return fmt.Errorf("Peer[%d].AllowedIPs is required", idx)
		}
	}
	return nil
}

func parseInterfaceKey(cfg *Config, key, value string) error {
	switch key {
	case "privatekey":
		cfg.PrivateKey = value
	case "address":
		prefixes, err := parsePrefixes(value)
		if err != nil {
			return err
		}
		cfg.Address = append(cfg.Address, prefixes...)
	case "dns":
		addrs, err := parseAddrs(value)
		if err != nil {
			return err
		}
		cfg.DNS = append(cfg.DNS, addrs...)
	case "mtu":
		v, err := parseInt(key, value)
		if err != nil {
			return err
		}
		cfg.MTU = v
	case "jc":
		return parseIntInto(value, &cfg.Jc, key)
	case "jmin":
		return parseIntInto(value, &cfg.Jmin, key)
	case "jmax":
		return parseIntInto(value, &cfg.Jmax, key)
	case "s1":
		return parseIntInto(value, &cfg.S1, key)
	case "s2":
		return parseIntInto(value, &cfg.S2, key)
	case "s3":
		return parseIntInto(value, &cfg.S3, key)
	case "s4":
		return parseIntInto(value, &cfg.S4, key)
	case "h1":
		cfg.H1 = value
	case "h2":
		cfg.H2 = value
	case "h3":
		cfg.H3 = value
	case "h4":
		cfg.H4 = value
	case "i1":
		cfg.I1 = value
	case "i2":
		cfg.I2 = value
	case "i3":
		cfg.I3 = value
	case "i4":
		cfg.I4 = value
	case "i5":
		cfg.I5 = value
	default:
		return fmt.Errorf("unsupported interface key %q", key)
	}
	return nil
}

func parsePeerKey(peer *Peer, key, value string) error {
	switch key {
	case "publickey":
		peer.PublicKey = value
	case "presharedkey":
		peer.PresharedKey = value
	case "endpoint":
		peer.Endpoint = value
	case "allowedips":
		prefixes, err := parsePrefixes(value)
		if err != nil {
			return err
		}
		peer.AllowedIPs = append(peer.AllowedIPs, prefixes...)
	case "persistentkeepalive", "persistentkeepaliveinterval":
		v, err := parseInt(key, value)
		if err != nil {
			return err
		}
		peer.PersistentKeepaliveInterval = v
	default:
		return fmt.Errorf("unsupported peer key %q", key)
	}
	return nil
}

func stripComment(line string) string {
	inQuote := false
	for i, r := range line {
		if r == '"' {
			inQuote = !inQuote
		}
		if !inQuote && (r == '#' || r == ';') {
			return strings.TrimSpace(line[:i])
		}
	}
	return line
}

func normalizeKey(key string) string {
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(key), "_", ""))
}

func parsePrefixes(value string) ([]netip.Prefix, error) {
	items := splitList(value)
	if len(items) == 0 {
		return nil, fmt.Errorf("empty prefix list")
	}
	prefixes := make([]netip.Prefix, 0, len(items))
	for _, item := range items {
		prefix, err := parsePrefixOrHost(item)
		if err != nil {
			return nil, fmt.Errorf("invalid prefix %q: %w", item, err)
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes, nil
}

func parsePrefixOrHost(value string) (netip.Prefix, error) {
	if prefix, err := netip.ParsePrefix(value); err == nil {
		return prefix, nil
	}
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Prefix{}, err
	}
	bits := 128
	if addr.Is4() {
		bits = 32
	}
	return netip.PrefixFrom(addr, bits), nil
}

func parseAddrs(value string) ([]netip.Addr, error) {
	items := splitList(value)
	addrs := make([]netip.Addr, 0, len(items))
	for _, item := range items {
		addr, err := netip.ParseAddr(item)
		if err != nil {
			return nil, fmt.Errorf("invalid DNS address %q: %w", item, err)
		}
		addrs = append(addrs, addr)
	}
	return addrs, nil
}

func splitList(value string) []string {
	raw := strings.Split(value, ",")
	items := make([]string, 0, len(raw))
	for _, item := range raw {
		item = strings.TrimSpace(item)
		if item != "" {
			items = append(items, item)
		}
	}
	return items
}

func parseIntInto(value string, target *int, name string) error {
	v, err := parseInt(name, value)
	if err != nil {
		return err
	}
	*target = v
	return nil
}

func parseInt(name, value string) (int, error) {
	v, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("%s must be an integer", name)
	}
	if v < 0 {
		return 0, fmt.Errorf("%s must be non-negative", name)
	}
	return v, nil
}

func validateKey(name, value string, optional bool) error {
	if value == "" {
		if optional {
			return nil
		}
		return fmt.Errorf("%s is required", name)
	}
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return fmt.Errorf("%s must be base64: %w", name, err)
	}
	if len(raw) != 32 {
		return fmt.Errorf("%s must decode to 32 bytes", name)
	}
	return nil
}

func keyToHex(value string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return "", err
	}
	if len(raw) != 32 {
		return "", fmt.Errorf("key must decode to 32 bytes")
	}
	return hex.EncodeToString(raw), nil
}
