package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

// mockController answers the three UniFi Network endpoints Sable reads. It
// exists so the host synchronizer performs a genuine synchronization for the
// screenshots instead of the console being filled in by hand.
type mockController struct {
	server *http.Server
	// Address is the listening address, resolved after a port of zero.
	Address string
}

func startMockController(address string) (*mockController, error) {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, fmt.Errorf("listen for mock UniFi controller: %w", err)
	}
	controller := &mockController{Address: listener.Addr().String()}
	mux := http.NewServeMux()
	mux.HandleFunc("/", controller.route)
	controller.server = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := controller.server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Println("mock UniFi controller stopped:", err)
		}
	}()
	return controller, nil
}

func (controller *mockController) Close() {
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = controller.server.Shutdown(shutdown)
}

// URL is the controller URL Sable is configured with.
func (controller *mockController) URL() string { return "http://" + controller.Address }

func (controller *mockController) route(writer http.ResponseWriter, request *http.Request) {
	switch {
	case strings.HasSuffix(request.URL.Path, "/rest/networkconf"):
		writeControllerJSON(writer, controllerNetworks())
	case strings.HasSuffix(request.URL.Path, "/rest/user"):
		writeControllerJSON(writer, controllerClients(true))
	case strings.HasSuffix(request.URL.Path, "/stat/sta"):
		writeControllerJSON(writer, controllerClients(false))
	case strings.HasSuffix(request.URL.Path, "/api/auth/login"):
		writer.Header().Set("X-CSRF-Token", "demo-csrf-token")
		writeControllerJSON(writer, map[string]string{"unique_id": "demo"})
	default:
		http.NotFound(writer, request)
	}
}

func writeControllerJSON(writer http.ResponseWriter, data any) {
	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(map[string]any{
		"meta": map[string]string{"rc": "ok"},
		"data": data,
	})
}

func controllerNetworks() []map[string]any {
	payload := make([]map[string]any, 0, len(unifiNetworks))
	for _, network := range unifiNetworks {
		payload = append(payload, map[string]any{
			"_id": network.ID, "name": network.Name, "purpose": network.Purpose,
			"enabled": true, "ip_subnet": network.Subnet,
		})
	}
	return payload
}

// controllerClients renders the fixture as either the reservation list or the
// connected-client list, which are separate endpoints on a real controller.
func controllerClients(reserved bool) []map[string]any {
	payload := make([]map[string]any, 0, len(unifiHosts))
	for _, host := range unifiHosts {
		if host.Reserved != reserved {
			continue
		}
		entry := map[string]any{
			"mac": host.MAC, "name": host.Name, "hostname": host.Name,
			"ip": host.Address, "network_id": host.NetworkID,
		}
		if host.Reserved {
			entry["fixed_ip"] = host.Address
			entry["use_fixedip"] = true
		}
		payload = append(payload, entry)
	}
	return payload
}
