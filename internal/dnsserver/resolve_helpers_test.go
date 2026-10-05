package dnsserver

import (
	"context"

	"github.com/miekg/dns"
)

// Test shorthands for the resolve paths. Production code passes its own
// context and wait; these fill in the defaults a test wants.

func (handler *Handler) resolveUpstreamWithinTimeout(request *dns.Msg, runtime *Runtime, forwarders []string) (*dns.Msg, validationState, error) {
	return handler.resolveUpstream(context.Background(), request, runtime, forwarders, runtime.timeout)
}

func (handler *Handler) resolveNetworkWithinTimeout(request *dns.Msg, runtime *Runtime, forwarders []string) (*dns.Msg, error) {
	ctx, cancel := context.WithTimeout(context.Background(), runtime.timeout)
	defer cancel()
	return handler.resolveNetwork(ctx, request, runtime, forwarders)
}

func (handler *Handler) resolveForClient(request *dns.Msg, runtime *Runtime, clientIP string) resolution {
	return handler.resolveNameForClient(request, questionName(request), runtime, clientIP)
}
