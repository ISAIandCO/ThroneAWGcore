//go:build windows

package awg

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	windowsIfTypeWWANPP  = 243
	windowsIfTypeWWANPP2 = 244
)

type interfaceCandidate struct {
	index  uint32
	label  string
	metric uint32
	speed  uint64
}

type windowsAdapterTable struct {
	first *windows.IpAdapterAddresses
	buf   []byte
}

func detectSystemInterfaceIndex(_ context.Context, cfg *Config) (uint32, string, error) {
	family := endpointFamily(cfg)
	candidate, err := bestWindowsGatewayInterface(family)
	if err != nil {
		return 0, "", fmt.Errorf("auto interface detection failed: %w", err)
	}
	return candidate.index, candidate.label, nil
}

func endpointFamily(cfg *Config) uint16 {
	for _, peer := range cfg.Peers {
		host, _, err := net.SplitHostPort(peer.Endpoint)
		if err != nil {
			continue
		}
		addr, err := netip.ParseAddr(host)
		if err != nil {
			continue
		}
		if addr.Is4() {
			return windows.AF_INET
		}
		return windows.AF_INET6
	}
	return windows.AF_UNSPEC
}

func bestWindowsGatewayInterface(family uint16) (interfaceCandidate, error) {
	adapters, err := windowsAdapters()
	if err != nil {
		return interfaceCandidate{}, err
	}

	bestAny := interfaceCandidate{metric: math.MaxUint32}
	bestPreferred := interfaceCandidate{metric: math.MaxUint32}
	for adapter := adapters.first; adapter != nil; adapter = adapter.Next {
		if !windowsAdapterEligible(adapter, family) {
			continue
		}
		candidate := interfaceCandidate{
			index:  windowsAdapterIndex(adapter, family),
			label:  fmt.Sprintf("interface index %d, iftype %d, metric %d", windowsAdapterIndex(adapter, family), adapter.IfType, windowsAdapterMetric(adapter, family)),
			metric: windowsAdapterMetric(adapter, family),
			speed:  adapter.TransmitLinkSpeed + adapter.ReceiveLinkSpeed,
		}
		if candidate.index == 0 {
			continue
		}
		if betterWindowsCandidate(candidate, bestAny) {
			bestAny = candidate
		}
		if !windowsAdapterNameLooksVirtual(adapter) && betterWindowsCandidate(candidate, bestPreferred) {
			bestPreferred = candidate
		}
	}
	if bestPreferred.index != 0 {
		return bestPreferred, nil
	}
	if bestAny.index != 0 {
		return bestAny, nil
	}
	return interfaceCandidate{}, errors.New("no up physical gateway interface found")
}

func betterWindowsCandidate(candidate, current interfaceCandidate) bool {
	if current.index == 0 {
		return true
	}
	return candidate.metric < current.metric || candidate.metric == current.metric && candidate.speed > current.speed
}

func windowsAdapterNameLooksVirtual(adapter *windows.IpAdapterAddresses) bool {
	text := strings.ToLower(strings.Join([]string{
		windows.UTF16PtrToString(adapter.FriendlyName),
		windows.UTF16PtrToString(adapter.Description),
	}, " "))
	if text == "" {
		return false
	}
	for _, marker := range []string{"tun", "wintun", "wireguard", "tap", "vpn", "throne"} {
		if strings.Contains(text, marker) {
			return true
		}
	}
	return false
}

func windowsAdapters() (windowsAdapterTable, error) {
	var size uint32 = 15 * 1024
	for {
		buf := make([]byte, size)
		adapters := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
		flags := uint32(windows.GAA_FLAG_INCLUDE_GATEWAYS)
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, flags, 0, adapters, &size)
		if err == nil {
			return windowsAdapterTable{first: adapters, buf: buf}, nil
		}
		if err != windows.ERROR_BUFFER_OVERFLOW {
			return windowsAdapterTable{}, err
		}
	}
}

func windowsAdapterEligible(adapter *windows.IpAdapterAddresses, family uint16) bool {
	if adapter.OperStatus != windows.IfOperStatusUp {
		return false
	}
	if !windowsExternalIfType(adapter.IfType) {
		return false
	}
	if adapter.PhysicalAddressLength == 0 {
		return false
	}
	if adapter.TransmitLinkSpeed == 0 && adapter.ReceiveLinkSpeed == 0 {
		return false
	}
	return windowsAdapterHasGateway(adapter, family)
}

func windowsExternalIfType(ifType uint32) bool {
	switch ifType {
	case windows.IF_TYPE_ETHERNET_CSMACD,
		windows.IF_TYPE_IEEE80211,
		windows.IF_TYPE_PPP,
		windowsIfTypeWWANPP,
		windowsIfTypeWWANPP2:
		return true
	default:
		return false
	}
}

func windowsAdapterHasGateway(adapter *windows.IpAdapterAddresses, family uint16) bool {
	for gateway := adapter.FirstGatewayAddress; gateway != nil; gateway = gateway.Next {
		gatewayFamily := windowsSocketAddressFamily(gateway.Address)
		if gatewayFamily == 0 {
			continue
		}
		if family == windows.AF_UNSPEC || family == gatewayFamily {
			return true
		}
	}
	return false
}

func windowsSocketAddressFamily(addr windows.SocketAddress) uint16 {
	if addr.Sockaddr == nil {
		return 0
	}
	return addr.Sockaddr.Addr.Family
}

func windowsAdapterIndex(adapter *windows.IpAdapterAddresses, family uint16) uint32 {
	if family == windows.AF_INET6 && adapter.Ipv6IfIndex != 0 {
		return adapter.Ipv6IfIndex
	}
	return adapter.IfIndex
}

func windowsAdapterMetric(adapter *windows.IpAdapterAddresses, family uint16) uint32 {
	if family == windows.AF_INET6 {
		return adapter.Ipv6Metric
	}
	if family == windows.AF_INET {
		return adapter.Ipv4Metric
	}
	if adapter.Ipv4Metric != 0 && (adapter.Ipv6Metric == 0 || adapter.Ipv4Metric <= adapter.Ipv6Metric) {
		return adapter.Ipv4Metric
	}
	if adapter.Ipv6Metric != 0 {
		return adapter.Ipv6Metric
	}
	return adapter.Ipv4Metric
}
