package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

var (
	// The sign-in and first-run forms carry a single-use token in a hidden
	// field; every other form reads it from the page's console dataset.
	preAuthTokenPattern = regexp.MustCompile(`name="csrf_token" value="([^"]+)"`)
	sessionTokenPattern = regexp.MustCompile(`CSRF-Token&#34;:&#34;([^&]*)&#34;`)
	enrollmentPattern   = regexp.MustCompile(`id="cluster-enrollment-token">([^<]+)<`)
)

// console drives one node's web interface the way an operator would, keeping
// its session so the demo can be assembled without anybody clicking.
type console struct {
	baseURL string
	client  *http.Client
}

func newConsole(baseURL string) *console {
	jar, _ := cookiejar.New(nil)
	return &console{
		baseURL: strings.TrimRight(baseURL, "/"),
		client: &http.Client{
			Jar:     jar,
			Timeout: 30 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// trustCluster teaches the client to trust a node's cluster certificate, which
// is what the HTTPS console and the enrollment endpoints present.
func (c *console) trustCluster(trustAnchorPath string) error {
	authority, err := os.ReadFile(trustAnchorPath)
	if err != nil {
		return fmt.Errorf("read cluster trust anchor: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(authority) {
		return fmt.Errorf("cluster trust anchor %s holds no certificates", trustAnchorPath)
	}
	c.client.Transport = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
	return nil
}

// SessionCookies renders the current session as a Cookie header, which is how
// the screenshot proxy borrows this sign-in.
func (c *console) SessionCookies() (string, error) {
	target, err := url.Parse(c.baseURL)
	if err != nil {
		return "", fmt.Errorf("parse console URL: %w", err)
	}
	cookies := c.client.Jar.Cookies(target)
	if len(cookies) == 0 {
		return "", errors.New("the console session has no cookies")
	}
	pairs := make([]string, 0, len(cookies))
	for _, cookie := range cookies {
		pairs = append(pairs, cookie.Name+"="+cookie.Value)
	}
	return strings.Join(pairs, "; "), nil
}

func (c *console) get(path string) (string, error) {
	response, err := c.client.Get(c.baseURL + path)
	if err != nil {
		return "", fmt.Errorf("GET %s: %w", path, err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 8<<20))
	if err != nil {
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	return string(body), nil
}

// post submits a form the way the console's own JavaScript does, carrying the
// session's CSRF token in the header rather than the body.
func (c *console) post(path string, form url.Values) (string, error) {
	token, err := c.sessionToken()
	if err != nil {
		return "", err
	}
	request, err := http.NewRequest(http.MethodPost, c.baseURL+path, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("build POST %s: %w", path, err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("HX-Request", "true")
	// A node with security switched off issues no token and enforces none.
	if token != "" {
		request.Header.Set("X-CSRF-Token", token)
	}
	response, err := c.client.Do(request)
	if err != nil {
		return "", fmt.Errorf("POST %s: %w", path, err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(response.Body, 8<<20))
	if response.StatusCode >= 400 {
		return "", fmt.Errorf("POST %s returned %s: %s", path, response.Status, summarize(string(body)))
	}
	return string(body), nil
}

// postPreAuth submits the first-run or sign-in form, which use single-use
// tokens issued with the page instead of a session token.
func (c *console) postPreAuth(path string, form url.Values) error {
	page, err := c.get(path)
	if err != nil {
		return err
	}
	match := preAuthTokenPattern.FindStringSubmatch(page)
	if match == nil {
		return fmt.Errorf("no form token on %s", path)
	}
	form.Set("csrf_token", match[1])
	response, err := c.client.PostForm(c.baseURL+path, form)
	if err != nil {
		return fmt.Errorf("POST %s: %w", path, err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if response.StatusCode >= 400 {
		return fmt.Errorf("POST %s returned %s: %s", path, response.Status, summarize(string(body)))
	}
	return nil
}

func (c *console) sessionToken() (string, error) {
	page, err := c.get("/")
	if err != nil {
		return "", err
	}
	match := sessionTokenPattern.FindStringSubmatch(page)
	if match == nil {
		return "", nil
	}
	return match[1], nil
}

// CreateOperator completes first-run setup and names the account.
func (c *console) CreateOperator(username, password, displayName, email string) error {
	if err := c.postPreAuth("/setup", url.Values{
		"username": {username}, "password": {password}, "confirm_password": {password},
	}); err != nil {
		return err
	}
	_, err := c.post("/ui/profile", url.Values{"display_name": {displayName}, "email": {email}})
	return err
}

// StoreUniFiCredentials seals controller credentials in the node's vault. The
// synchronizer refuses to run without them, and they are held outside the
// configuration file, so this is the one part of the UniFi setup that has to go
// through the console rather than the demo's own configuration.
func (c *console) StoreUniFiCredentials(controllerURL, apiKey string) error {
	_, err := c.post("/ui/integrations/unifi/wizard", url.Values{
		"wizard_step":    {"connect"},
		"controller_url": {controllerURL},
		"site":           {"default"},
		"auth_mode":      {"api-key"},
		"api_key":        {apiKey},
	})
	return err
}

// EnableScheduledBackups exercises the same policy form an operator uses and
// gives the Backup tab a real local archive to show in the disposable demo.
func (c *console) EnableScheduledBackups(passphrase string) error {
	_, err := c.post("/ui/backup/schedule", url.Values{
		"enabled":                 {"on"},
		"directory":               {"data/backups"},
		"interval":                {"1d"},
		"run_at":                  {"02:00"},
		"retention_count":         {"7"},
		"passphrase":              {passphrase},
		"passphrase_confirmation": {passphrase},
	})
	return err
}

func (c *console) WaitForScheduledBackup(ctx context.Context) error {
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		page, err := c.get("/settings?tab=backup")
		if err == nil && strings.Contains(page, "sable-scheduled-") {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
	return errors.New("timed out waiting for the first scheduled backup")
}

// InitializeCluster promotes this node to the cluster's primary.
func (c *console) InitializeCluster(domain string, addresses []string) error {
	_, err := c.post("/ui/cluster/initialize", url.Values{
		"domain": {domain}, "addresses": {strings.Join(addresses, "\n")},
	})
	return err
}

// EnrollmentToken mints a joining secret for one replica.
func (c *console) EnrollmentToken(lifetime string) (string, error) {
	body, err := c.post("/ui/cluster/enrollment-tokens", url.Values{"ttl": {lifetime}})
	if err != nil {
		return "", err
	}
	match := enrollmentPattern.FindStringSubmatch(body)
	if match == nil {
		return "", errors.New("the primary did not return an enrollment token")
	}
	return strings.TrimSpace(match[1]), nil
}

// JoinCluster enrolls this node against a primary using a token from it.
func (c *console) JoinCluster(primaryURL, token string, addresses []string) error {
	_, err := c.post("/ui/cluster/join", url.Values{
		"primary_url": {primaryURL}, "token": {token}, "addresses": {strings.Join(addresses, "\n")},
	})
	return err
}

// summarize trims an error body to something worth printing.
func summarize(body string) string {
	body = strings.Join(strings.Fields(stripTags(body)), " ")
	if len(body) > 240 {
		return body[:240] + "…"
	}
	return body
}

var tagPattern = regexp.MustCompile(`<[^>]*>`)

func stripTags(body string) string { return tagPattern.ReplaceAllString(body, " ") }
