package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/drudge/sable/internal/app"
	"github.com/drudge/sable/internal/dnsclient"
	serviceinstall "github.com/drudge/sable/internal/install"
	"github.com/drudge/sable/internal/version"
)

const usage = `Sable is a modern DNS server and client.

Usage:
  sable serve [--config sable.toml]
  sable query [options] <name> [type]
  sable config check [--config sable.toml]
  sable install [--no-start] [--certificate-name name-or-ip]
  sable version
`

func main() {
	if err := run(os.Args[1:]); err != nil {
		if errors.Is(err, app.ErrRestartRequested) {
			os.Exit(75)
		}
		fmt.Fprintln(os.Stderr, "sable:", err)
		os.Exit(1)
	}
}

func run(arguments []string) error {
	if len(arguments) == 0 {
		fmt.Print(usage)
		return nil
	}
	switch arguments[0] {
	case "serve":
		return serve(arguments[1:])
	case "query":
		return query(arguments[1:])
	case "config":
		return configCommand(arguments[1:])
	case "install":
		return installCommand(arguments[1:])
	case "version":
		info := version.Current()
		fmt.Printf("Sable %s (%s, %s, %s)\n", info.Release, info.Commit, info.BuiltAt, info.Go)
		return nil
	case "help", "-h", "--help":
		fmt.Print(usage)
		return nil
	default:
		return fmt.Errorf("unknown command %q", arguments[0])
	}
}

func installCommand(arguments []string) error {
	flags := flag.NewFlagSet("install", flag.ContinueOnError)
	noStart := flags.Bool("no-start", false, "install and enable the service without starting it")
	var certificateNames stringListFlag
	flags.Var(&certificateNames, "certificate-name", "additional DNS name or IP for the initial HTTPS certificate (repeatable)")
	if err := flags.Parse(arguments); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("usage: sable install [--no-start] [--certificate-name name-or-ip]")
	}
	result, err := serviceinstall.SystemService(context.Background(), serviceinstall.Options{
		CertificateNames: certificateNames,
		Start:            !*noStart,
	})
	if err != nil {
		return err
	}
	fmt.Printf("Sable installed: %s\nConfiguration: %s\nData: %s\n", result.BinaryPath, result.ConfigurationPath, result.DataDirectory)
	if result.Started {
		fmt.Printf("Console: https://%s/\n", result.ConsoleHost)
		fmt.Println("The initial HTTPS certificate is self-signed; replace or trust it after first-run setup.")
	} else {
		fmt.Println("Start Sable with: systemctl start sable")
	}
	return nil
}

type stringListFlag []string

func (values *stringListFlag) String() string { return strings.Join(*values, ",") }

func (values *stringListFlag) Set(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return errors.New("certificate name cannot be empty")
	}
	*values = append(*values, value)
	return nil
}

func serve(arguments []string) error {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	configurationPath := flags.String("config", "sable.toml", "path to the TOML configuration")
	if err := flags.Parse(arguments); err != nil {
		return err
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return app.Run(ctx, *configurationPath, logger)
}

func query(arguments []string) error {
	flags := flag.NewFlagSet("query", flag.ContinueOnError)
	server := flags.String("server", "127.0.0.1:8053", "DNS server address")
	transport := flags.String("transport", "udp", "udp, tcp, tcp-tls, or doh")
	timeout := flags.Duration("timeout", 3*time.Second, "query timeout")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	positionals := flags.Args()
	if len(positionals) == 0 {
		return errors.New("query name is required")
	}
	queryType := "A"
	if len(positionals) > 1 {
		queryType = strings.ToUpper(positionals[1])
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	result, err := dnsclient.Query(ctx, dnsclient.Request{
		Server:    *server,
		Name:      positionals[0],
		Type:      queryType,
		Transport: *transport,
		Timeout:   *timeout,
	})
	if err != nil {
		return err
	}
	fmt.Printf(";; server: %s\n;; elapsed: %s\n%s", result.Server, result.Elapsed.Round(time.Microsecond), result.Response.String())
	return nil
}

func configCommand(arguments []string) error {
	if len(arguments) == 0 || arguments[0] != "check" {
		return errors.New("usage: sable config check [--config sable.toml]")
	}
	flags := flag.NewFlagSet("config check", flag.ContinueOnError)
	configurationPath := flags.String("config", "sable.toml", "path to the TOML configuration")
	if err := flags.Parse(arguments[1:]); err != nil {
		return err
	}
	loaded, err := app.CheckConfiguration(*configurationPath)
	if err != nil {
		return err
	}
	fmt.Printf("configuration valid: %s (%s)\n", *configurationPath, loaded.Database.Driver)
	return nil
}
