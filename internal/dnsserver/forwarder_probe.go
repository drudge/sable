package dnsserver

import (
	"context"
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// The names a forwarder test asks. example.com is signed, so a validating
// forwarder sets AD on its answer (RFC 4035 §3.2.3). dnssec-failed.org is
// signed with a DNSKEY that does not match its DS, so a validating forwarder
// answers it SERVFAIL (RFC 4035 §5.5) while one that does not validate
// answers NOERROR.
const (
	forwarderProbeSigned = "example.com."
	forwarderProbeBogus  = "dnssec-failed.org."
	// forwarderProbeRepeats is how many times the signed name is asked; the
	// test reports the median, so one slow answer or a connection being
	// set up does not decide the result.
	forwarderProbeRepeats = 3
	// forwarderTestTimeout bounds the whole test.
	forwarderTestTimeout = 10 * time.Second
)

// ForwarderTest is how one forwarder answered a test.
type ForwarderTest struct {
	Forwarder string `json:"forwarder"`
	Route     string `json:"route,omitempty"`
	// OK means it answered the signed name with NOERROR.
	OK bool `json:"ok"`
	// ResponseTime is the median time of its answers to the signed name.
	ResponseTime time.Duration `json:"response_time_ns"`
	ResponseCode string        `json:"response_code,omitempty"`
	// AuthenticatedData means it set AD on the signed name's answer.
	AuthenticatedData bool `json:"authenticated_data"`
	// Validates is "yes" when it set AD on the signed name and refused the
	// bogus one, "no" when it answered the bogus one, and empty when the
	// test could not tell.
	Validates string `json:"validates,omitempty"`
	Error     string `json:"error,omitempty"`
}

// TestForwarders asks every forwarder the active configuration sends to the
// test names over its own transport, all at once, and reports how each
// answered. The queries go straight to each forwarder, past the cache and the
// health tracking, and do not count in the forwarder stats.
func (handler *Handler) TestForwarders(ctx context.Context) []ForwarderTest {
	runtime := handler.runtime.Load()
	if runtime == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, forwarderTestTimeout)
	defer cancel()
	stats := handler.ForwarderStats()
	results := make([]ForwarderTest, len(stats))
	tested := make(map[string]int, len(stats))
	var wait sync.WaitGroup
	for index, forwarder := range stats {
		results[index] = ForwarderTest{Forwarder: forwarder.Forwarder, Route: forwarder.Route}
		// A forwarder several routes share is asked once.
		if _, found := tested[forwarder.Forwarder]; found {
			continue
		}
		tested[forwarder.Forwarder] = index
		wait.Go(func() {
			results[index] = handler.testForwarder(ctx, runtime, results[index])
		})
	}
	wait.Wait()
	for index := range results {
		if first := tested[results[index].Forwarder]; first != index {
			route := results[index].Route
			results[index] = results[first]
			results[index].Route = route
		}
	}
	return results
}

func (handler *Handler) testForwarder(ctx context.Context, runtime *Runtime, result ForwarderTest) ForwarderTest {
	timeout := max(runtime.retryTimeout, 2*time.Second)
	var times []time.Duration
	var signed *dns.Msg
	for range forwarderProbeRepeats {
		started := time.Now()
		response, err := handler.upstreamExchange(ctx, forwarderProbe(forwarderProbeSigned), result.Forwarder, timeout)
		if err != nil {
			if signed == nil {
				result.Error = forwarderTestError(err)
				return result
			}
			break
		}
		times = append(times, time.Since(started))
		signed = response
	}
	slices.Sort(times)
	result.ResponseTime = times[(len(times)-1)/2]
	result.ResponseCode = dns.RcodeToString[signed.Rcode]
	result.OK = signed.Rcode == dns.RcodeSuccess
	result.AuthenticatedData = signed.AuthenticatedData
	if !result.OK {
		return result
	}
	bogus, err := handler.upstreamExchange(ctx, forwarderProbe(forwarderProbeBogus), result.Forwarder, timeout)
	switch {
	case err != nil:
	case bogus.Rcode == dns.RcodeServerFailure && result.AuthenticatedData:
		result.Validates = "yes"
	case bogus.Rcode == dns.RcodeSuccess:
		result.Validates = "no"
	}
	return result
}

// forwarderProbe asks for a name the way a client that wants validated
// answers does: RD set, and DO and AD set so the forwarder reports whether it
// validated (RFC 6840 §5.7).
func forwarderProbe(name string) *dns.Msg {
	message := new(dns.Msg)
	message.SetQuestion(name, dns.TypeA)
	message.RecursionDesired = true
	message.AuthenticatedData = true
	message.SetEdns0(1232, true)
	return message
}

// forwarderTestError says why a forwarder failed in words an operator can
// act on, keeping the transport's own message for the rest.
func forwarderTestError(err error) string {
	if isForwarderTimeout(err) {
		return "no answer in time"
	}
	if errors.Is(err, context.Canceled) {
		return "cancelled"
	}
	return err.Error()
}
