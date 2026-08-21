package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"
)

// shot is one page photographed at one window size. Heights are chosen to end
// just below each page's content so the images carry no dead space.
type shot struct {
	File   string
	Path   string
	Width  int
	Height int
}

var shots = []shot{
	{"dashboard.png", "/", 1600, 1000},
	{"dashboard-full.png", "/", 1600, 1400},
	{"blocking.png", "/blocked", 1600, 880},
	{"blocking-domains.png", "/blocked?tab=domains", 1600, 1150},
	{"blocking-allowed.png", "/blocked?tab=allowed", 1600, 880},
	{"unifi.png", "/integrations", 1600, 1000},
	{"unifi-card.png", "/integrations", 1600, 750},
	{"cluster.png", "/cluster", 1600, 1500},
	{"cluster-status.png", "/cluster", 1600, 1000},
}

// captureShots photographs the console. A signed-in session lives in a cookie,
// and a headless browser cannot be handed one on the command line, so the pages
// are served through a local proxy that attaches the session to every request.
func captureShots(ctx context.Context, target *console, outputDirectory string) error {
	browser, err := findBrowser()
	if err != nil {
		return err
	}
	session, err := target.SessionCookies()
	if err != nil {
		return err
	}
	proxy, err := startSessionProxy(target.baseURL, session)
	if err != nil {
		return err
	}
	defer proxy.Close()

	if err := os.MkdirAll(outputDirectory, 0o755); err != nil {
		return fmt.Errorf("create screenshot directory: %w", err)
	}
	for _, image := range shots {
		destination := filepath.Join(outputDirectory, image.File)
		if err := capture(ctx, browser, proxy.URL()+image.Path, destination, image.Width, image.Height); err != nil {
			return err
		}
		fmt.Printf("  wrote %s (%dx%d at 2x)\n", destination, image.Width, image.Height)
	}
	return nil
}

// capture drives the browser once. Screenshots are taken at twice the device
// scale so the images stay sharp on a retina display.
func capture(ctx context.Context, browser, address, destination string, width, height int) error {
	command := exec.CommandContext(ctx, browser,
		"--headless=new",
		"--disable-gpu",
		"--hide-scrollbars",
		"--force-device-scale-factor=2",
		"--virtual-time-budget=6000",
		fmt.Sprintf("--window-size=%d,%d", width, height),
		"--screenshot="+destination,
		address,
	)
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("capture %s: %w\n%s", destination, err, output)
	}
	if _, err := os.Stat(destination); err != nil {
		return fmt.Errorf("capture %s produced no image:\n%s", destination, output)
	}
	return nil
}

// browserCandidates are the Chrome-family binaries a headless capture can use.
func browserCandidates() []string {
	if runtime.GOOS == "darwin" {
		return []string{
			"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
			"/Applications/Chromium.app/Contents/MacOS/Chromium",
			"/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
		}
	}
	return []string{"google-chrome", "google-chrome-stable", "chromium", "chromium-browser"}
}

func findBrowser() (string, error) {
	if custom := os.Getenv("SABLE_DEMO_BROWSER"); custom != "" {
		return custom, nil
	}
	for _, candidate := range browserCandidates() {
		if path, err := exec.LookPath(candidate); err == nil {
			return path, nil
		}
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate, nil
		}
	}
	return "", errors.New("no Chrome-family browser found; set SABLE_DEMO_BROWSER to one")
}

// sessionProxy forwards to the console with a signed-in session attached.
type sessionProxy struct {
	server  *http.Server
	address string
}

func startSessionProxy(consoleURL, session string) (*sessionProxy, error) {
	target, err := url.Parse(consoleURL)
	if err != nil {
		return nil, fmt.Errorf("parse console URL: %w", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listen for screenshot proxy: %w", err)
	}
	reverse := httputil.NewSingleHostReverseProxy(target)
	director := reverse.Director
	reverse.Director = func(request *http.Request) {
		director(request)
		request.Header.Set("Cookie", session)
	}
	proxy := &sessionProxy{
		server:  &http.Server{Handler: reverse, ReadHeaderTimeout: 5 * time.Second},
		address: listener.Addr().String(),
	}
	go func() {
		if err := proxy.server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Println("screenshot proxy stopped:", err)
		}
	}()
	return proxy, nil
}

func (proxy *sessionProxy) URL() string { return "http://" + proxy.address }

func (proxy *sessionProxy) Close() {
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = proxy.server.Shutdown(shutdown)
}
