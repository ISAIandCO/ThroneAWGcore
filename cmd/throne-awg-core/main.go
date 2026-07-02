package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/throneawgcore/throne-awg-core/internal/awg"
	"github.com/throneawgcore/throne-awg-core/internal/socks"
)

var version = "dev"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return usage()
	}

	switch args[0] {
	case "run":
		return runCore(args[1:])
	case "check":
		return checkConfig(args[1:])
	case "probe":
		return probeConfig(args[1:])
	case "version":
		fmt.Println(version)
		return nil
	case "-h", "--help", "help":
		return usage()
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func runCore(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	listen := fs.String("listen", "127.0.0.1:1080", "SOCKS5 listen address")
	configPath := fs.String("config", "", "path to AmneziaWG config")
	verbose := fs.Bool("verbose", false, "enable verbose AmneziaWG and SOCKS logs")
	stdBind := fs.Bool("std-bind", false, "force the portable UDP bind instead of the platform default")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *configPath == "" {
		return errors.New("missing --config")
	}

	cfg, err := awg.LoadConfig(*configPath)
	if err != nil {
		return err
	}
	if err := cfg.Validate(); err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	runtime, err := awg.Start(ctx, cfg, awg.Options{Verbose: *verbose, StdBind: *stdBind})
	if err != nil {
		return err
	}
	defer runtime.Close()

	server := socks.NewServer(*listen, runtime, socks.Options{Verbose: *verbose})
	fmt.Printf("throne-awg-core %s listening on %s\n", version, *listen)
	return server.ListenAndServe(ctx)
}

func checkConfig(args []string) error {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := fs.String("config", "", "path to AmneziaWG config")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *configPath == "" {
		return errors.New("missing --config")
	}
	cfg, err := awg.LoadConfig(*configPath)
	if err != nil {
		return err
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	if _, err := cfg.IPC(); err != nil {
		return err
	}
	fmt.Println("config ok")
	return nil
}

func probeConfig(args []string) error {
	fs := flag.NewFlagSet("probe", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := fs.String("config", "", "path to AmneziaWG config")
	target := fs.String("target", "1.1.1.1:443", "TCP target to dial through AmneziaWG")
	timeout := fs.Duration("timeout", 15*time.Second, "probe timeout")
	verbose := fs.Bool("verbose", false, "enable verbose AmneziaWG logs")
	stdBind := fs.Bool("std-bind", false, "force the portable UDP bind instead of the platform default")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *configPath == "" {
		return errors.New("missing --config")
	}
	cfg, err := awg.LoadConfig(*configPath)
	if err != nil {
		return err
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	runtime, err := awg.Start(ctx, cfg, awg.Options{Verbose: *verbose, StdBind: *stdBind})
	if err != nil {
		return err
	}
	defer runtime.Close()
	if err := runtime.ProbeTCP(ctx, *target, *timeout); err != nil {
		return fmt.Errorf("probe tcp %s: %w", *target, err)
	}
	fmt.Printf("probe tcp %s ok\n", *target)
	return nil
}

func usage() error {
	fmt.Fprintln(os.Stderr, `Usage:
  throne-awg-core run --listen 127.0.0.1:1080 --config <path>
  throne-awg-core check --config <path>
  throne-awg-core probe --config <path> --target 1.1.1.1:443
  throne-awg-core version`)
	return nil
}
