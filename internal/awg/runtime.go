package awg

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/conn"
	"github.com/amnezia-vpn/amneziawg-go/device"
	"github.com/amnezia-vpn/amneziawg-go/tun"
	"github.com/amnezia-vpn/amneziawg-go/tun/netstack"
)

type Runtime struct {
	tun  tun.Device
	dev  *device.Device
	net  *netstack.Net
	once sync.Once
}

type Options struct {
	Verbose        bool
	StdBind        bool
	InterfaceIndex uint32
	AutoInterface  bool
}

func Start(ctx context.Context, cfg *Config, opts Options) (*Runtime, error) {
	ipc, err := cfg.IPC()
	if err != nil {
		return nil, err
	}

	interfaceIndex := opts.InterfaceIndex
	var interfaceName string
	if opts.AutoInterface && interfaceIndex == 0 {
		interfaceIndex, interfaceName, err = detectInterfaceIndex(ctx, cfg)
		if err != nil && opts.Verbose {
			fmt.Fprintf(os.Stderr, "awg: auto interface detection skipped: %v\n", err)
		}
	}

	tdev, tnet, err := netstack.CreateNetTUN(cfg.LocalAddresses(), cfg.DNS, cfg.MTU)
	if err != nil {
		return nil, fmt.Errorf("create netstack tun: %w", err)
	}

	logger := device.Logger{
		Verbosef: func(string, ...any) {},
		Errorf: func(format string, args ...any) {
			fmt.Fprintf(os.Stderr, "awg error: "+format+"\n", args...)
		},
	}
	if opts.Verbose {
		logger.Verbosef = func(format string, args ...any) {
			fmt.Fprintf(os.Stderr, "awg: "+format+"\n", args...)
		}
	}
	bind := conn.NewDefaultBind()
	if opts.StdBind {
		bind = conn.NewStdNetBind()
	}
	if opts.Verbose {
		if opts.StdBind {
			fmt.Fprintln(os.Stderr, "awg: using StdNetBind")
		} else {
			fmt.Fprintln(os.Stderr, "awg: using DefaultBind")
		}
	}
	dev := device.NewDevice(tdev, bind, &logger)
	if err := dev.IpcSet(ipc); err != nil {
		dev.Close()
		return nil, fmt.Errorf("configure awg device: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("start awg device: %w", err)
	}
	if interfaceIndex != 0 {
		if err := bindToInterface(dev.Bind(), interfaceIndex); err != nil {
			if opts.AutoInterface && opts.InterfaceIndex == 0 {
				if opts.Verbose {
					fmt.Fprintf(os.Stderr, "awg: auto interface binding skipped: %v\n", err)
				}
			} else {
				dev.Close()
				return nil, err
			}
		} else {
			if opts.Verbose {
				if interfaceName != "" {
					fmt.Fprintf(os.Stderr, "awg: bound UDP sockets to interface %s (%d)\n", interfaceName, interfaceIndex)
				} else {
					fmt.Fprintf(os.Stderr, "awg: bound UDP sockets to interface index %d\n", interfaceIndex)
				}
			}
			dev.SendKeepalivesToPeersWithCurrentKeypair()
		}
	}

	r := &Runtime{tun: tdev, dev: dev, net: tnet}
	go func() {
		<-ctx.Done()
		r.Close()
	}()
	return r, nil
}

func detectInterfaceIndex(ctx context.Context, cfg *Config) (uint32, string, error) {
	var lastErr error
	for idx, peer := range cfg.Peers {
		interfaceIndex, interfaceName, err := detectPeerInterfaceIndex(ctx, peer.Endpoint)
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

func detectPeerInterfaceIndex(ctx context.Context, endpoint string) (uint32, string, error) {
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

func bindToInterface(bind conn.Bind, interfaceIndex uint32) error {
	interfaceBind, ok := bind.(conn.BindSocketToInterface)
	if !ok {
		return errors.New("selected UDP bind does not support --interface-index")
	}
	err4 := interfaceBind.BindSocketToInterface4(interfaceIndex, false)
	err6 := interfaceBind.BindSocketToInterface6(interfaceIndex, false)
	if err4 != nil && err6 != nil {
		return fmt.Errorf("bind UDP sockets to interface %d: %w", interfaceIndex, errors.Join(err4, err6))
	}
	return nil
}

func (r *Runtime) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network == "tcp" || network == "tcp4" || network == "tcp6" {
		if addr, ok := parseAddrPort(address); ok {
			return r.net.DialContextTCPAddrPort(ctx, addr)
		}
	}
	return r.net.DialContext(ctx, network, address)
}

func parseAddrPort(address string) (netip.AddrPort, bool) {
	host, portRaw, err := net.SplitHostPort(address)
	if err != nil {
		return netip.AddrPort{}, false
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return netip.AddrPort{}, false
	}
	port, err := strconv.ParseUint(portRaw, 10, 16)
	if err != nil {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(ip, uint16(port)), true
}

func (r *Runtime) ProbeTCP(ctx context.Context, target string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := r.DialContext(ctx, "tcp", target)
	if err != nil {
		return err
	}
	_ = conn.Close()
	return nil
}

func (r *Runtime) Close() {
	if r == nil {
		return
	}
	r.once.Do(func() {
		r.dev.Close()
	})
}
