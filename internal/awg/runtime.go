package awg

import (
	"context"
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
	Verbose bool
}

func Start(ctx context.Context, cfg *Config, opts Options) (*Runtime, error) {
	ipc, err := cfg.IPC()
	if err != nil {
		return nil, err
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
	// Prefer the plain UDP bind for an external desktop helper. On Windows,
	// NewDefaultBind selects WinRing/RIO when available; StdNetBind is slower
	// but avoids RIO-specific compatibility issues in an Extra Core process.
	dev := device.NewDevice(tdev, conn.NewStdNetBind(), &logger)
	if err := dev.IpcSet(ipc); err != nil {
		dev.Close()
		return nil, fmt.Errorf("configure awg device: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("start awg device: %w", err)
	}

	r := &Runtime{tun: tdev, dev: dev, net: tnet}
	go func() {
		<-ctx.Done()
		r.Close()
	}()
	return r, nil
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
