package awg

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

func (cfg *Config) IPC() (string, error) {
	privateKey, err := keyToHex(cfg.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("PrivateKey: %w", err)
	}

	var b strings.Builder
	writeKV(&b, "private_key", privateKey)
	writeInt(&b, "jc", cfg.Jc)
	writeInt(&b, "jmin", cfg.Jmin)
	writeInt(&b, "jmax", cfg.Jmax)
	writeInt(&b, "s1", cfg.S1)
	writeInt(&b, "s2", cfg.S2)
	writeInt(&b, "s3", cfg.S3)
	writeInt(&b, "s4", cfg.S4)
	writeString(&b, "h1", cfg.H1)
	writeString(&b, "h2", cfg.H2)
	writeString(&b, "h3", cfg.H3)
	writeString(&b, "h4", cfg.H4)
	writeString(&b, "i1", cfg.I1)
	writeString(&b, "i2", cfg.I2)
	writeString(&b, "i3", cfg.I3)
	writeString(&b, "i4", cfg.I4)
	writeString(&b, "i5", cfg.I5)

	for idx, peer := range cfg.Peers {
		publicKey, err := keyToHex(peer.PublicKey)
		if err != nil {
			return "", fmt.Errorf("Peer[%d].PublicKey: %w", idx, err)
		}
		writeKV(&b, "public_key", publicKey)
		writeKV(&b, "endpoint", peer.Endpoint)
		for _, prefix := range peer.AllowedIPs {
			writeKV(&b, "allowed_ip", prefix.String())
		}
		if peer.PresharedKey != "" {
			presharedKey, err := keyToHex(peer.PresharedKey)
			if err != nil {
				return "", fmt.Errorf("Peer[%d].PresharedKey: %w", idx, err)
			}
			writeKV(&b, "preshared_key", presharedKey)
		}
		writeInt(&b, "persistent_keepalive_interval", peer.PersistentKeepaliveInterval)
	}

	return b.String(), nil
}

func (cfg *Config) LocalAddresses() []netip.Addr {
	addrs := make([]netip.Addr, 0, len(cfg.Address))
	for _, prefix := range cfg.Address {
		addrs = append(addrs, prefix.Addr())
	}
	return addrs
}

func writeString(b *strings.Builder, key, value string) {
	if value != "" {
		writeKV(b, key, value)
	}
}

func writeInt(b *strings.Builder, key string, value int) {
	if value != 0 {
		writeKV(b, key, strconv.Itoa(value))
	}
}

func writeKV(b *strings.Builder, key, value string) {
	if b.Len() > 0 {
		b.WriteByte('\n')
	}
	b.WriteString(key)
	b.WriteByte('=')
	b.WriteString(value)
}
