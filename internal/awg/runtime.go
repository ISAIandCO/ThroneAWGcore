package awg

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync"

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

func Start(ctx context.Context, cfg *Config) (*Runtime, error) {
	ipc, err := cfg.IPC()
	if err != nil {
		return nil, err
	}

	tdev, tnet, err := netstack.CreateNetTUN(cfg.LocalAddresses(), cfg.DNS, cfg.MTU)
	if err != nil {
		return nil, fmt.Errorf("create netstack tun: %w", err)
	}

	logger := device.Logger{
		Verbosef: func(format string, args ...any) {
			fmt.Fprintf(os.Stderr, "awg: "+format+"\n", args...)
		},
		Errorf: func(format string, args ...any) {
			fmt.Fprintf(os.Stderr, "awg error: "+format+"\n", args...)
		},
	}
	dev := device.NewDevice(tdev, conn.NewDefaultBind(), &logger)
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
	return r.net.DialContext(ctx, network, address)
}

func (r *Runtime) Close() {
	if r == nil {
		return
	}
	r.once.Do(func() {
		r.dev.Close()
	})
}
