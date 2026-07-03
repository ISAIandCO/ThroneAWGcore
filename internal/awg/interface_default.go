//go:build !windows

package awg

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"
)

func detectSystemInterfaceIndex(ctx context.Context, cfg *Config) (uint32, string, error) {
	var lastErr error
	for idx, peer := range cfg.Peers {
		interfaceIndex, interfaceName, err := detectPeerRouteInterfaceIndex(ctx, peer.Endpoint)
		if err == nil {
			return interfaceIndex, interfaceName, nil
		}
		lastErr = fmt.Errorf("Peer[%d].Endpoint %s: %w", idx, peer.Endpoint, err)
	}
	if lastErr == nil {
		lastErr = errors.New("no peers")
	}
	return 0, "", fmt.Errorf("auto interface detection failed: %w", lastErr)
}

func detectPeerRouteInterfaceIndex(ctx context.Context, endpoint string) (uint32, string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, "udp", endpoint)
	if err != nil {
		return 0, "", err
	}
	defer conn.Close()

	udpAddr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || udpAddr.IP == nil || udpAddr.IP.IsUnspecified() {
		return 0, "", fmt.Errorf("cannot determine local UDP address")
	}
	iface, err := interfaceByIP(udpAddr.IP)
	if err != nil {
		return 0, "", err
	}
	return uint32(iface.Index), iface.Name, nil
}

func interfaceByIP(ip net.IP) (*net.Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for i := range ifaces {
		addrs, err := ifaces[i].Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if interfaceAddrMatchesIP(addr, ip) {
				return &ifaces[i], nil
			}
		}
	}
	return nil, fmt.Errorf("no interface has local address %s", ip)
}

func interfaceAddrMatchesIP(addr net.Addr, ip net.IP) bool {
	switch v := addr.(type) {
	case *net.IPNet:
		return v.IP.Equal(ip) || v.Contains(ip)
	case *net.IPAddr:
		return v.IP.Equal(ip)
	default:
		return false
	}
}
