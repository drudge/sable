package clustertest

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/drudge/sable/internal/cluster"
	"github.com/drudge/sable/internal/config"
)

// InitializePrimary creates a new cluster on the node at httpsAddress.
func InitializePrimary(t *testing.T, client *http.Client, httpsAddress string) {
	t.Helper()
	RequestJSON(t, client, http.MethodPost, "https://"+httpsAddress+"/api/v1/cluster", map[string]any{
		"domain": "integration.sable.test", "addresses": []string{"127.0.0.1"},
	}, http.StatusCreated, nil)
}

// CreateEnrollmentToken asks the primary for a replica enrollment token.
func CreateEnrollmentToken(t *testing.T, client *http.Client, httpsAddress string) cluster.EnrollmentToken {
	t.Helper()
	var enrollment cluster.EnrollmentToken
	RequestJSON(t, client, http.MethodPost, "https://"+httpsAddress+"/api/v1/cluster/enrollment-tokens", map[string]string{
		"ttl": "5m",
	}, http.StatusCreated, &enrollment)
	if enrollment.Token == "" {
		t.Fatal("primary returned an empty enrollment token")
	}
	return enrollment
}

// JoinReplica enrolls the replica in the primary through the replica UI.
func JoinReplica(t *testing.T, client *http.Client, replicaHTTPSAddress, primaryHTTPSAddress, token string) {
	t.Helper()
	form := url.Values{
		"primary_url": {"https://" + primaryHTTPSAddress},
		"token":       {token},
		"addresses":   {"127.0.0.1"},
	}
	response, err := client.PostForm("https://"+replicaHTTPSAddress+"/ui/cluster/join", form)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		contents, _ := io.ReadAll(response.Body)
		t.Fatalf("join replica = %d: %s", response.StatusCode, contents)
	}
}

// AddBlockedDomain adds a blocked domain through the UI and checks the saved configuration.
func AddBlockedDomain(t *testing.T, client *http.Client, httpsAddress, configurationPath, domain string) {
	t.Helper()
	response, err := client.PostForm("https://"+httpsAddress+"/ui/blocking/domains/add", url.Values{"domain": {domain}})
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		contents, _ := io.ReadAll(response.Body)
		t.Fatalf("add blocked domain = %d: %s", response.StatusCode, contents)
	}
	updated, err := config.Load(configurationPath)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(updated.Blocking.Domains, domain) {
		t.Fatalf("primary configuration does not contain blocked domain %q", domain)
	}
}

// FetchClusterState reads the cluster state from the node at httpsAddress.
func FetchClusterState(t *testing.T, client *http.Client, httpsAddress string) cluster.State {
	t.Helper()
	var state cluster.State
	RequestJSON(t, client, http.MethodGet, "https://"+httpsAddress+"/api/v1/cluster", nil, http.StatusOK, &state)
	return state
}

// RequestJSON sends an optional JSON body, checks the status, and decodes the JSON response.
func RequestJSON(t *testing.T, client *http.Client, method, endpoint string, input any, expectedStatus int, output any) {
	t.Helper()
	var body io.Reader
	if input != nil {
		contents, err := json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
		body = strings.NewReader(string(contents))
	}
	request, err := http.NewRequestWithContext(context.Background(), method, endpoint, body)
	if err != nil {
		t.Fatal(err)
	}
	if input != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != expectedStatus {
		contents, _ := io.ReadAll(response.Body)
		t.Fatalf("%s %s = %d: %s", method, endpoint, response.StatusCode, contents)
	}
	if output != nil {
		if err := json.NewDecoder(response.Body).Decode(output); err != nil {
			t.Fatal(err)
		}
	}
}
