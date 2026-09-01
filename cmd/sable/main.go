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
	"github.com/drudge/sable/internal/durationfmt"
	serviceinstall "github.com/drudge/sable/internal/install"
	"github.com/drudge/sable/internal/update"
	"github.com/drudge/sable/internal/version"
)

const usage = `Sable is a modern DNS server and client.

Usage:
  sable serve [--config sable.toml]
  sable query [options] <name> [type]
  sable config check [--config sable.toml]
  sable backup create [--config sable.toml] [--out file]
  sable backup restore [--config sable.toml] <file>
  sable backup inspect <file>
  sable install [--no-start] [--enable-web-updates] [--certificate-name name-or-ip]
  sable update [--pre-release] [--check] [--version tag] [--no-restart]
  sable version [--short]
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
	case "backup":
		return backupCommand(arguments[1:])
	case "container":
		return containerCommand(arguments[1:])
	case "install":
		return installCommand(arguments[1:])
	case "update":
		return updateCommand(arguments[1:])
	case "version":
		return versionCommand(arguments[1:])
	case "help", "-h", "--help":
		fmt.Print(usage)
		return nil
	default:
		return fmt.Errorf("unknown command %q", arguments[0])
	}
}

func versionCommand(arguments []string) error {
	flags := flag.NewFlagSet("version", flag.ContinueOnError)
	short := flags.Bool("short", false, "print only the release version")
	if err := flags.Parse(arguments); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("usage: sable version [--short]")
	}
	info := version.Current()
	if *short {
		fmt.Println(info.Release)
		return nil
	}
	fmt.Printf("Sable %s (%s, %s, %s)\n", info.Release, info.Commit, info.BuiltAt, info.Go)
	return nil
}

func installCommand(arguments []string) error {
	flags := flag.NewFlagSet("install", flag.ContinueOnError)
	noStart := flags.Bool("no-start", false, "install and enable the service without starting it")
	webUpdates := flags.Bool("enable-web-updates", false, "allow administrators to install verified releases from the web console")
	var certificateNames stringListFlag
	flags.Var(&certificateNames, "certificate-name", "additional DNS name or IP for the initial HTTPS certificate (repeatable)")
	if err := flags.Parse(arguments); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("usage: sable install [--no-start] [--enable-web-updates] [--certificate-name name-or-ip]")
	}
	result, err := serviceinstall.SystemService(context.Background(), serviceinstall.Options{
		CertificateNames: certificateNames,
		Start:            !*noStart,
		WebUpdates:       *webUpdates,
	})
	if err != nil {
		return err
	}
	fmt.Printf("Sable installed: %s\nConfiguration: %s\nData: %s\n", result.BinaryPath, result.ConfigurationPath, result.DataDirectory)
	if result.WebUpdates {
		fmt.Printf("Web updates: enabled (%s)\n", result.ServiceBinaryPath)
	}
	if result.Started {
		fmt.Printf("Console: https://%s/\n", result.ConsoleHost)
		fmt.Println("The initial HTTPS certificate is self-signed; replace or trust it after first-run setup.")
	} else {
		fmt.Println("Start Sable with: systemctl start sable")
	}
	return nil
}

func updateCommand(arguments []string) error {
	flags := flag.NewFlagSet("update", flag.ContinueOnError)
	preRelease := flags.Bool("pre-release", false, "consider pre-release builds when selecting the newest release")
	check := flags.Bool("check", false, "report the available release without installing it")
	requested := flags.String("version", "", "install a specific release tag instead of the newest one")
	noRestart := flags.Bool("no-restart", false, "replace the executable without restarting the Sable service")
	if err := flags.Parse(arguments); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("usage: sable update [--pre-release] [--check] [--version tag] [--no-restart]")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	result, err := update.Apply(ctx, update.Options{
		Version:          *requested,
		PreRelease:       *preRelease,
		CheckOnly:        *check,
		Restart:          !*noRestart,
		MirrorBinaryPath: serviceinstall.InstalledWebUpdateBinaryPath(),
		Output:           os.Stdout,
	})
	if err != nil {
		return err
	}
	switch {
	case result.UpToDate:
		fmt.Printf("Sable %s is the newest release.\n", result.CurrentVersion)
	case !result.Applied:
		install := "sable update"
		if *preRelease {
			install += " --pre-release"
		}
		if *requested != "" {
			install += " --version " + *requested
		}
		fmt.Printf("Sable %s is available (running %s).\n%s\nInstall it with: %s\n",
			result.LatestVersion, result.CurrentVersion, result.ReleaseURL, install)
	default:
		fmt.Printf("Sable updated: %s -> %s (%s)\n", result.CurrentVersion, result.LatestVersion, result.BinaryPath)
		switch {
		case result.Restarted:
			fmt.Printf("Restarted %s.\n", serviceinstall.ServiceName)
		case result.ServiceManaged:
			fmt.Printf("The Sable service is not running; start it with: systemctl start %s\n", serviceinstall.ServiceName)
		default:
			fmt.Println("Restart Sable to run the new version.")
		}
	}
	return nil
}

type stringListFlag []string

func (values *stringListFlag) String() string { return strings.Join(*values, ",") }

func (values *stringListFlag) Set(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return errors.New("value cannot be empty")
	}
	*values = append(*values, value)
	return nil
}

type durationFlag time.Duration

func (value *durationFlag) String() string {
	return durationfmt.Format(time.Duration(*value))
}

func (value *durationFlag) Set(input string) error {
	parsed, err := durationfmt.Parse(input)
	if err != nil {
		return err
	}
	*value = durationFlag(parsed)
	return nil
}

func serve(arguments []string) error {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	configurationPath := flags.String("config", "sable.toml", "path to the TOML configuration")
	if err := flags.Parse(arguments); err != nil {
		return err
	}

	// The application applies the configured runtime level. The terminal
	// handler must accept debug records so lowering that level can take effect.
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return app.Run(ctx, *configurationPath, logger)
}

func query(arguments []string) error {
	flags := flag.NewFlagSet("query", flag.ContinueOnError)
	server := flags.String("server", "127.0.0.1:8053", "DNS server address")
	transport := flags.String("transport", "udp", "udp, tcp, tcp-tls, quic, or doh")
	timeout := durationFlag(3 * time.Second)
	flags.Var(&timeout, "timeout", "query timeout")
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
	timeoutDuration := time.Duration(timeout)
	ctx, cancel := context.WithTimeout(context.Background(), timeoutDuration)
	defer cancel()
	result, err := dnsclient.Query(ctx, dnsclient.Request{
		Server:    *server,
		Name:      positionals[0],
		Type:      queryType,
		Transport: *transport,
		Timeout:   timeoutDuration,
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
