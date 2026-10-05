package dnsserver

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/drudge/sable/internal/dnsname"
	zonemodel "github.com/drudge/sable/internal/zone"
)

const maximumZoneJournalEntries = 128

type zoneDelta struct {
	oldSerial uint32
	newSerial uint32
	oldSOA    dns.RR
	newSOA    dns.RR
	deleted   []dns.RR
	added     []dns.RR
}

func (handler *Handler) recordRuntimeChanges(active, candidate *Runtime, now time.Time) {
	if active == nil || candidate == nil {
		return
	}
	// A journal outlives only the zone it was written for. A deleted zone's
	// deltas go with it, and a zone created under a name the active runtime
	// does not serve starts empty, so IXFR never chains through another
	// zone's history that happens to share its serials.
	handler.journalMu.Lock()
	for name := range handler.zoneJournals {
		if candidate.zones[name] == nil || active.zones[name] == nil {
			delete(handler.zoneJournals, name)
		}
	}
	handler.journalMu.Unlock()
	for name, current := range candidate.zones {
		previous := active.zones[name]
		if previous == nil {
			continue
		}
		oldRecords := previous.transferRecords(now)
		newRecords := current.transferRecords(now)
		_, oldSOA, oldOK := transferSnapshot(oldRecords)
		_, newSOA, newOK := transferSnapshot(newRecords)
		if !oldOK || !newOK || oldSOA.Serial == newSOA.Serial {
			continue
		}
		if !serialLess(oldSOA.Serial, newSOA.Serial) {
			handler.journalMu.Lock()
			delete(handler.zoneJournals, name)
			handler.journalMu.Unlock()
			continue
		}
		delta, changed := makeZoneDelta(oldRecords, newRecords)
		if !changed {
			continue
		}
		handler.journalMu.Lock()
		journal := append(handler.zoneJournals[name], delta)
		if len(journal) > maximumZoneJournalEntries {
			journal = slices.Clone(journal[len(journal)-maximumZoneJournalEntries:])
		}
		handler.zoneJournals[name] = journal
		handler.journalMu.Unlock()
	}
}

func makeZoneDelta(oldTransfer, newTransfer []dns.RR) (zoneDelta, bool) {
	oldRecords, oldSOA, ok := transferSnapshot(oldTransfer)
	if !ok {
		return zoneDelta{}, false
	}
	newRecords, newSOA, ok := transferSnapshot(newTransfer)
	if !ok || !serialLess(oldSOA.Serial, newSOA.Serial) {
		return zoneDelta{}, false
	}
	oldByKey := recordsByKey(oldRecords)
	newByKey := recordsByKey(newRecords)
	delta := zoneDelta{
		oldSerial: oldSOA.Serial, newSerial: newSOA.Serial,
		oldSOA: dns.Copy(oldSOA), newSOA: dns.Copy(newSOA),
	}
	for key, record := range oldByKey {
		if _, found := newByKey[key]; !found && record.Header().Rrtype != dns.TypeSOA {
			delta.deleted = append(delta.deleted, dns.Copy(record))
		}
	}
	for key, record := range newByKey {
		if _, found := oldByKey[key]; !found && record.Header().Rrtype != dns.TypeSOA {
			delta.added = append(delta.added, dns.Copy(record))
		}
	}
	sortRR(delta.deleted)
	sortRR(delta.added)
	return delta, true
}

func serialLess(left, right uint32) bool {
	return left != right && right-left < 1<<31
}

func transferSnapshot(records []dns.RR) ([]dns.RR, *dns.SOA, bool) {
	if len(records) < 2 {
		return nil, nil, false
	}
	soa, ok := records[0].(*dns.SOA)
	if !ok {
		return nil, nil, false
	}
	last, ok := records[len(records)-1].(*dns.SOA)
	if !ok || last.Serial != soa.Serial {
		return nil, nil, false
	}
	return records[:len(records)-1], soa, true
}

func recordsByKey(records []dns.RR) map[string]dns.RR {
	result := make(map[string]dns.RR, len(records))
	for _, record := range records {
		result[recordKey(record)] = record
	}
	return result
}

func recordKey(record dns.RR) string { return strings.ToLower(record.String()) }

func sortRR(records []dns.RR) {
	slices.SortFunc(records, func(left, right dns.RR) int {
		return strings.Compare(recordKey(left), recordKey(right))
	})
}

func (handler *Handler) incrementalTransferRecords(request *dns.Msg, zoneName string, axfr []dns.RR) []dns.RR {
	_, currentSOA, ok := transferSnapshot(axfr)
	if !ok || len(request.Ns) != 1 {
		return axfr
	}
	requested, ok := request.Ns[0].(*dns.SOA)
	if !ok || normalizeName(requested.Hdr.Name) != zoneName {
		return axfr
	}
	if requested.Serial == currentSOA.Serial {
		return []dns.RR{dns.Copy(currentSOA)}
	}
	chain, ok := handler.zoneDeltaChain(zoneName, requested.Serial, currentSOA.Serial)
	if !ok {
		return axfr
	}
	records := []dns.RR{dns.Copy(currentSOA)}
	for _, delta := range chain {
		records = append(records, dns.Copy(delta.oldSOA))
		records = append(records, copyRR(delta.deleted)...)
		records = append(records, dns.Copy(delta.newSOA))
		records = append(records, copyRR(delta.added)...)
	}
	records = append(records, dns.Copy(currentSOA))
	return records
}

func (handler *Handler) zoneDeltaChain(zoneName string, requested, current uint32) ([]zoneDelta, bool) {
	handler.journalMu.RLock()
	journal := slices.Clone(handler.zoneJournals[zoneName])
	handler.journalMu.RUnlock()
	serial := requested
	chain := make([]zoneDelta, 0)
	for _, delta := range journal {
		if delta.oldSerial != serial {
			continue
		}
		chain = append(chain, delta)
		serial = delta.newSerial
		if serial == current {
			return chain, true
		}
	}
	return nil, false
}

func copyRR(records []dns.RR) []dns.RR {
	result := make([]dns.RR, len(records))
	for index, record := range records {
		result[index] = dns.Copy(record)
	}
	return result
}

func (handler *Handler) SetZoneExpired(zoneName string, expired bool) {
	zoneName = normalizeName(zoneName)
	handler.expiredMu.Lock()
	defer handler.expiredMu.Unlock()
	active := handler.expiredZones.Load()
	next := make(map[string]struct{}, len(*active)+1)
	for name := range *active {
		next[name] = struct{}{}
	}
	if expired {
		next[zoneName] = struct{}{}
	} else {
		delete(next, zoneName)
	}
	handler.expiredZones.Store(&next)
}

func (handler *Handler) Notifications() <-chan ZoneNotification { return handler.notifications }

func (handler *Handler) serveNotify(writer dns.ResponseWriter, request *dns.Msg, runtime *Runtime, clientIP string) bool {
	if request.Opcode != dns.OpcodeNotify {
		return false
	}
	response := new(dns.Msg)
	response.SetReply(request)
	response.Authoritative = true
	if len(request.Question) != 1 || request.Question[0].Qtype != dns.TypeSOA || request.Question[0].Qclass != dns.ClassINET {
		response.Rcode = dns.RcodeFormatError
		handler.recordResponseCode(response.Rcode)
		_ = writer.WriteMsg(response)
		return true
	}
	zoneName := normalizeName(request.Question[0].Name)
	managed, found := runtime.managedZones[zoneName]
	if !found {
		response.Rcode = dns.RcodeNotAuth
		handler.recordResponseCode(response.Rcode)
		_ = writer.WriteMsg(response)
		return true
	}
	if !tsigRequestAuthenticated(writer, request, managed.tsigKey) {
		response.Rcode = dns.RcodeRefused
		handler.recordResponseCode(response.Rcode)
		_ = writer.WriteMsg(response)
		return true
	}
	source := clientIP
	if !notifySourceAllowed(source, managed.primaries, runtime.timeout) {
		response.Rcode = dns.RcodeRefused
		handler.recordResponseCode(response.Rcode)
		_ = writer.WriteMsg(response)
		return true
	}
	notification := ZoneNotification{Zone: zoneName, Source: source, ReceivedAt: time.Now()}
	select {
	case handler.notifications <- notification:
		response.Rcode = dns.RcodeSuccess
	default:
		handler.logResolutionFailure(request, source, "zone notification queue is full", "zone", zoneName)
		response.Rcode = dns.RcodeServerFailure
	}
	if signature := request.IsTsig(); signature != nil && writer.TsigStatus() == nil {
		response.SetTsig(signature.Hdr.Name, signature.Algorithm, signature.Fudge, time.Now().Unix())
	}
	handler.recordResponseCode(response.Rcode)
	_ = writer.WriteMsg(response)
	return true
}

func notifySourceAllowed(source string, primaries []string, timeout time.Duration) bool {
	sourceAddress, err := netip.ParseAddr(source)
	if err != nil {
		return false
	}
	sourceAddress = sourceAddress.Unmap()
	for _, primary := range primaries {
		host, _, splitErr := net.SplitHostPort(primary)
		if splitErr != nil {
			continue
		}
		host = strings.Trim(host, "[]")
		if address, parseErr := netip.ParseAddr(host); parseErr == nil {
			if address.Unmap() == sourceAddress {
				return true
			}
			continue
		}
		lookupTimeout := min(timeout, 2*time.Second)
		if lookupTimeout <= 0 {
			lookupTimeout = 2 * time.Second
		}
		ctx, cancel := context.WithTimeout(context.Background(), lookupTimeout)
		addresses, lookupErr := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		cancel()
		if lookupErr != nil {
			continue
		}
		for _, address := range addresses {
			if address.Unmap() == sourceAddress {
				return true
			}
		}
	}
	return false
}

func (handler *Handler) zoneExpired(runtime *Runtime, name string) bool {
	expired := handler.expiredZones.Load()
	if len(*expired) == 0 {
		return false
	}
	name = normalizeName(name)
	for current := name; current != ""; {
		// Consult the same runtime snapshot used to answer this query. A late
		// refresh failure must never expire a newly activated Primary.
		if _, managed := runtime.managedZones[current]; managed {
			_, found := (*expired)[current]
			return found
		}
		if _, authoritative := runtime.zones[current]; authoritative {
			return false
		}
		separator := strings.IndexByte(current, '.')
		if separator < 0 {
			return false
		}
		current = current[separator+1:]
	}
	return false
}

func exchangeIncrementalZoneTransfer(
	ctx context.Context,
	zoneName, primary, protocol string,
	current *dns.SOA,
	auth transferAuth,
	timeout time.Duration,
) ([]dns.RR, error) {
	if current == nil {
		return nil, errors.New("IXFR requires the current SOA")
	}
	if protocol != "tcp" && protocol != "tls" {
		return nil, fmt.Errorf("IXFR protocol must be tcp or tls")
	}
	transfer := &dns.Transfer{DialTimeout: timeout, ReadTimeout: timeout, WriteTimeout: timeout}
	if protocol == "tls" {
		host, _, err := net.SplitHostPort(primary)
		if err != nil {
			return nil, fmt.Errorf("TLS primary address: %w", err)
		}
		transfer.TLS = &tls.Config{MinVersion: tls.VersionTLS13, ServerName: strings.Trim(host, "[]")}
	}
	request := new(dns.Msg)
	request.SetIxfr(dns.Fqdn(zoneName), current.Serial, current.Ns, current.Mbox)
	applyTransferTSIG(request, transfer, auth)
	envelopes, err := transfer.In(request, primary)
	if err != nil {
		return nil, err
	}
	defer transfer.Close()
	var records []dns.RR
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case envelope, open := <-envelopes:
			if !open {
				if len(records) == 0 {
					return nil, errors.New("IXFR returned no records")
				}
				return records, nil
			}
			if envelope.Error != nil {
				return nil, envelope.Error
			}
			records = append(records, envelope.RR...)
		}
	}
}

// RefreshZone synchronizes an existing secondary or stub zone. Secondary zones
// request IXFR at their current serial and atomically apply the returned deltas;
// an AXFR response remains a valid fallback when the primary has no usable journal.
func (handler *Handler) RefreshZone(
	ctx context.Context,
	zoneName, zoneType string,
	primaries []string,
	protocol, tsigKeyName string,
	current []ZoneRecord,
) ([]ZoneRecord, bool, error) {
	zoneName = normalizeName(zoneName)
	zoneType = strings.ToLower(strings.TrimSpace(zoneType))
	// Translated FWD records do not retain the source wire representation needed
	// to match IXFR deletions, so Secondary Forwarders always request AXFR.
	if zoneType == "stub" || zoneType == "secondary_forwarder" {
		fresh, err := handler.FetchZone(ctx, zoneName, zoneType, primaries, protocol, tsigKeyName)
		if err != nil {
			return nil, false, err
		}
		if zoneType == "secondary_forwarder" {
			_, previousSOA, err := zoneRecordsToRR(zoneName, current)
			if err != nil {
				return nil, false, err
			}
			_, nextSOA, err := zoneRecordsToRR(zoneName, fresh)
			if err != nil {
				return nil, false, err
			}
			if nextSOA.Serial != previousSOA.Serial && int32(nextSOA.Serial-previousSOA.Serial) <= 0 {
				return nil, false, errors.New("forwarder transfer returned an older or ambiguous SOA serial")
			}
		}
		return fresh, !zoneRecordSetsEqual(current, fresh), nil
	}
	// Consumer catalog zones are ordinary zones on the wire; only what Sable
	// does with the transferred records differs from a secondary.
	if zoneType != "secondary" && zoneType != "catalog" {
		return nil, false, fmt.Errorf("zone type %q cannot be refreshed", zoneType)
	}
	currentRR, currentSOA, err := zoneRecordsToRR(zoneName, current)
	if err != nil {
		return nil, false, err
	}
	if len(primaries) == 0 {
		return nil, false, errors.New("at least one primary server is required")
	}
	if protocol == "" {
		protocol = "tcp"
	}
	timeout := handler.runtime.Load().timeout
	auth := handler.transferAuth(zoneName, tsigKeyName)
	var failures []error
	for _, primary := range primaries {
		stream, refreshErr := handler.zoneRefresh(ctx, zoneName, primary, protocol, currentSOA, auth, timeout)
		if refreshErr != nil {
			failures = append(failures, fmt.Errorf("%s: %w", primary, refreshErr))
			continue
		}
		updated, changed, applyErr := applyZoneTransfer(zoneName, currentRR, currentSOA.Serial, stream)
		if applyErr != nil {
			failures = append(failures, fmt.Errorf("%s: %w", primary, applyErr))
			continue
		}
		if !changed {
			return slices.Clone(current), false, nil
		}
		converted, convertErr := zoneRecordsFromRR(zoneName, updated)
		if convertErr != nil {
			return nil, false, convertErr
		}
		return converted, true, nil
	}
	return nil, false, fmt.Errorf("refresh secondary zone %q: %w", zoneName, errors.Join(failures...))
}

func zoneRecordsToRR(zoneName string, records []ZoneRecord) ([]dns.RR, *dns.SOA, error) {
	result := make([]dns.RR, 0, len(records))
	var soa *dns.SOA
	for _, record := range records {
		if record.Disabled || (!record.ExpiresAt.IsZero() && !record.ExpiresAt.After(time.Now())) {
			continue
		}
		owner, err := authoritativeOwner(zoneName, record.Name)
		if err != nil {
			return nil, nil, err
		}
		typeName := strings.ToUpper(strings.TrimSpace(record.Type))
		if _, found := dns.StringToType[typeName]; !found {
			continue
		}
		rr, err := dns.NewRR(fmt.Sprintf("%s %d IN %s %s", dns.Fqdn(owner), record.TTL, typeName, record.Value))
		if err != nil {
			return nil, nil, fmt.Errorf("parse current zone record: %w", err)
		}
		result = append(result, rr)
		if candidate, ok := rr.(*dns.SOA); ok && normalizeName(candidate.Hdr.Name) == zoneName {
			soa = candidate
		}
	}
	if soa == nil {
		return nil, nil, errors.New("current zone has no apex SOA")
	}
	return result, soa, nil
}

func applyZoneTransfer(zoneName string, current []dns.RR, currentSerial uint32, stream []dns.RR) ([]dns.RR, bool, error) {
	if len(stream) == 0 {
		return nil, false, errors.New("zone transfer returned no records")
	}
	remoteSOA, ok := stream[0].(*dns.SOA)
	if !ok || normalizeName(remoteSOA.Hdr.Name) != zoneName {
		return nil, false, errors.New("zone transfer did not begin with the zone SOA")
	}
	if len(stream) == 1 {
		if remoteSOA.Serial != currentSerial {
			return nil, false, errors.New("single-record IXFR response has a different serial")
		}
		return current, false, nil
	}
	markers := soaMarkerIndexes(stream)
	if len(markers) == 2 {
		closing := stream[markers[1]].(*dns.SOA)
		if markers[0] != 0 || markers[1] != len(stream)-1 || closing.Serial != remoteSOA.Serial {
			return nil, false, errors.New("invalid AXFR fallback framing")
		}
		return copyRR(stream[:len(stream)-1]), remoteSOA.Serial != currentSerial || !rrSetsEqual(current, stream[:len(stream)-1]), nil
	}
	if len(markers) < 4 || len(markers)%2 != 0 || markers[len(markers)-1] != len(stream)-1 {
		return nil, false, errors.New("invalid IXFR framing")
	}
	closing := stream[len(stream)-1].(*dns.SOA)
	if closing.Serial != remoteSOA.Serial {
		return nil, false, errors.New("IXFR closing SOA does not match current SOA")
	}
	records := recordsByKey(current)
	expected := currentSerial
	for marker := 1; marker < len(markers)-1; marker += 2 {
		oldSOA := stream[markers[marker]].(*dns.SOA)
		newSOA := stream[markers[marker+1]].(*dns.SOA)
		if oldSOA.Serial != expected {
			return nil, false, fmt.Errorf("IXFR delta begins at serial %d, expected %d", oldSOA.Serial, expected)
		}
		if !serialLess(oldSOA.Serial, newSOA.Serial) {
			return nil, false, fmt.Errorf("IXFR serial did not advance from %d to %d", oldSOA.Serial, newSOA.Serial)
		}
		removeSOA(records, zoneName)
		for _, record := range stream[markers[marker]+1 : markers[marker+1]] {
			delete(records, recordKey(record))
		}
		records[recordKey(newSOA)] = dns.Copy(newSOA)
		for _, record := range stream[markers[marker+1]+1 : markers[marker+2]] {
			records[recordKey(record)] = dns.Copy(record)
		}
		expected = newSOA.Serial
	}
	if expected != remoteSOA.Serial {
		return nil, false, fmt.Errorf("IXFR ended at serial %d, current serial is %d", expected, remoteSOA.Serial)
	}
	result := make([]dns.RR, 0, len(records))
	for _, record := range records {
		result = append(result, record)
	}
	sortRR(result)
	return result, true, nil
}

func soaMarkerIndexes(records []dns.RR) []int {
	result := make([]int, 0)
	for index, record := range records {
		if _, ok := record.(*dns.SOA); ok {
			result = append(result, index)
		}
	}
	return result
}

func removeSOA(records map[string]dns.RR, zoneName string) {
	for key, record := range records {
		if record.Header().Rrtype == dns.TypeSOA && normalizeName(record.Header().Name) == zoneName {
			delete(records, key)
		}
	}
}

func rrSetsEqual(left, right []dns.RR) bool {
	if len(left) != len(right) {
		return false
	}
	leftSet := recordsByKey(left)
	for _, record := range right {
		if _, found := leftSet[recordKey(record)]; !found {
			return false
		}
	}
	return true
}

func zoneRecordSetsEqual(left, right []ZoneRecord) bool {
	key := func(record ZoneRecord) string {
		return strings.ToLower(fmt.Sprintf("%s\x00%s\x00%s\x00%d", record.Name, record.Type, record.Value, record.TTL))
	}
	if len(left) != len(right) {
		return false
	}
	values := make(map[string]struct{}, len(left))
	for _, record := range left {
		values[key(record)] = struct{}{}
	}
	for _, record := range right {
		if _, found := values[key(record)]; !found {
			return false
		}
	}
	return true
}

func (handler *Handler) serveZoneTransfer(writer dns.ResponseWriter, request *dns.Msg, runtime *Runtime, clientIP string) bool {
	if request.Opcode != dns.OpcodeQuery || len(request.Question) != 1 {
		return false
	}
	question := request.Question[0]
	if question.Qtype != dns.TypeAXFR && question.Qtype != dns.TypeIXFR {
		return false
	}
	zone := runtime.zones[normalizeName(question.Name)]
	// A transfer streams many messages, but a DoH response carries exactly one,
	// so DoH is refused even though its local address is a TCP socket. TSIG is
	// not the reason: DoH reports a signed request as unverified.
	if zone == nil || isDoHWriter(writer) || !zone.transferAllowed(clientIP) ||
		writer.LocalAddr() == nil || !strings.HasPrefix(writer.LocalAddr().Network(), "tcp") ||
		handler.zoneExpired(runtime, question.Name) {
		_ = writer.WriteMsg(errorResponse(request, dns.RcodeRefused))
		handler.refused.Add(1)
		return true
	}
	if !tsigRequestAuthenticated(writer, request, zone.tsigKey) {
		_ = writer.WriteMsg(errorResponse(request, dns.RcodeRefused))
		handler.refused.Add(1)
		return true
	}
	records := zone.transferRecords(time.Now())
	if question.Qtype == dns.TypeIXFR {
		records = handler.incrementalTransferRecords(request, zone.name, records)
	}
	if len(records) == 0 || (question.Qtype == dns.TypeAXFR && len(records) < 2) {
		handler.logResolutionFailure(request, clientIP, "zone transfer has no records to send", "records", len(records))
		_ = writer.WriteMsg(errorResponse(request, dns.RcodeServerFailure))
		handler.serverFailures.Add(1)
		return true
	}
	envelopes := make(chan *dns.Envelope, (len(records)+127)/128)
	for len(records) > 0 {
		count := min(128, len(records))
		envelopes <- &dns.Envelope{RR: records[:count]}
		records = records[count:]
	}
	close(envelopes)
	if err := new(dns.Transfer).Out(writer, request, envelopes); err != nil {
		handler.failures.Add(1)
		return true
	}
	handler.authoritativeAnswers.Add(1)
	handler.noError.Add(1)
	return true
}

func (zone *authoritativeZone) transferAllowed(client string) bool {
	address, err := netip.ParseAddr(client)
	if err != nil {
		return false
	}
	address = address.Unmap()
	switch zone.transferMode {
	case "allow":
		return true
	case "private":
		return address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast()
	case "acl":
		for _, prefix := range zone.transferACL {
			if prefix.Contains(address) {
				return true
			}
		}
	}
	return false
}

func (zone *authoritativeZone) transferRecords(now time.Time) []dns.RR {
	soa := cloneRecords(zone.soa, "", now)
	if len(soa) != 1 {
		return nil
	}
	body := make([]dns.RR, 0, len(zone.owners))
	for _, typed := range zone.records {
		for recordType, records := range typed {
			if recordType == dns.TypeSOA {
				continue
			}
			body = append(body, cloneRecords(records, "", now)...)
		}
	}
	slices.SortFunc(body, func(left, right dns.RR) int { return strings.Compare(left.String(), right.String()) })
	result := make([]dns.RR, 0, len(body)+2)
	result = append(result, soa[0])
	result = append(result, body...)
	result = append(result, dns.Copy(soa[0]))
	return result
}

func (handler *Handler) NotifyZone(ctx context.Context, zoneName string, targets []string) []error {
	auth := handler.transferAuth(zoneName, "")
	errorsByTarget := make([]error, 0)
	for _, target := range targets {
		message := new(dns.Msg)
		message.SetNotify(dns.Fqdn(zoneName))
		var response *dns.Msg
		var err error
		if auth.keyName == "" {
			response, err = handler.upstreamExchange(ctx, message, "udp://"+target, 2*time.Second)
		} else {
			message.SetTsig(auth.keyName, auth.algorithm, 300, time.Now().Unix())
			client := &dns.Client{
				Net: "udp", Timeout: 2 * time.Second,
				TsigSecret: map[string]string{auth.keyName: auth.secret},
			}
			response, _, err = client.ExchangeContext(ctx, message, target)
		}
		if err != nil {
			errorsByTarget = append(errorsByTarget, fmt.Errorf("%s: %w", target, err))
			continue
		}
		if response.Rcode != dns.RcodeSuccess {
			errorsByTarget = append(errorsByTarget, fmt.Errorf("%s returned %s", target, dns.RcodeToString[response.Rcode]))
		}
	}
	return errorsByTarget
}

func (handler *Handler) FetchZone(
	ctx context.Context,
	zoneName, zoneType string,
	primaries []string,
	protocol, tsigKeyName string,
) ([]ZoneRecord, error) {
	zoneName, err := dnsname.Normalize(zoneName)
	if err != nil {
		return nil, err
	}
	zoneType = strings.ToLower(strings.TrimSpace(zoneType))
	protocol = strings.ToLower(strings.TrimSpace(protocol))
	if protocol == "" {
		if zoneType == "stub" {
			protocol = "udp"
		} else {
			protocol = "tcp"
		}
	}
	if len(primaries) == 0 {
		return nil, errors.New("at least one primary server is required")
	}
	timeout := handler.runtime.Load().timeout
	var failures []error
	auth := handler.transferAuth(zoneName, tsigKeyName)
	for _, primary := range primaries {
		var records []dns.RR
		if zoneType == "secondary" || zoneType == zonemodel.TypeSecondaryForwarder || zoneType == "catalog" {
			records, err = handler.zoneTransfer(ctx, zoneName, primary, protocol, auth, timeout)
		} else if zoneType == "stub" {
			records, err = handler.fetchStubZone(ctx, zoneName, primary, protocol, timeout)
		} else {
			return nil, fmt.Errorf("zone type %q cannot be synchronized", zoneType)
		}
		if err == nil {
			return zoneRecordsFromRR(zoneName, records)
		}
		failures = append(failures, fmt.Errorf("%s: %w", primary, err))
	}
	return nil, fmt.Errorf("synchronize %s zone %q: %w", zoneType, zoneName, errors.Join(failures...))
}

func exchangeZoneTransfer(
	ctx context.Context,
	zoneName, primary, protocol string,
	auth transferAuth,
	timeout time.Duration,
) ([]dns.RR, error) {
	if protocol != "tcp" && protocol != "tls" {
		return nil, fmt.Errorf("AXFR protocol must be tcp or tls")
	}
	transfer := &dns.Transfer{DialTimeout: timeout, ReadTimeout: timeout, WriteTimeout: timeout}
	if protocol == "tls" {
		host, _, err := net.SplitHostPort(primary)
		if err != nil {
			return nil, fmt.Errorf("TLS primary address: %w", err)
		}
		transfer.TLS = &tls.Config{MinVersion: tls.VersionTLS13, ServerName: strings.Trim(host, "[]")}
	}
	request := new(dns.Msg)
	request.SetAxfr(dns.Fqdn(zoneName))
	applyTransferTSIG(request, transfer, auth)
	envelopes, err := transfer.In(request, primary)
	if err != nil {
		return nil, err
	}
	defer transfer.Close()
	var records []dns.RR
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case envelope, open := <-envelopes:
			if !open {
				if len(records) < 2 || records[0].Header().Rrtype != dns.TypeSOA || records[len(records)-1].Header().Rrtype != dns.TypeSOA {
					return nil, errors.New("AXFR did not contain opening and closing SOA records")
				}
				return records[:len(records)-1], nil
			}
			if envelope.Error != nil {
				return nil, envelope.Error
			}
			records = append(records, envelope.RR...)
		}
	}
}

func (handler *Handler) fetchStubZone(
	ctx context.Context,
	zoneName, primary, protocol string,
	timeout time.Duration,
) ([]dns.RR, error) {
	endpoint := protocol + "://" + primary
	var records []dns.RR
	for _, recordType := range []uint16{dns.TypeSOA, dns.TypeNS} {
		request := new(dns.Msg)
		request.SetQuestion(dns.Fqdn(zoneName), recordType)
		response, err := handler.upstreamExchange(ctx, request, endpoint, timeout)
		if err != nil {
			return nil, err
		}
		if response.Rcode != dns.RcodeSuccess {
			return nil, fmt.Errorf("%s query returned %s", dns.TypeToString[recordType], dns.RcodeToString[response.Rcode])
		}
		for _, section := range [][]dns.RR{response.Answer, response.Ns, response.Extra} {
			for _, record := range section {
				if record.Header().Rrtype == recordType || record.Header().Rrtype == dns.TypeA || record.Header().Rrtype == dns.TypeAAAA {
					records = append(records, record)
				}
			}
		}
	}
	return uniqueZoneRR(records), nil
}

func uniqueZoneRR(records []dns.RR) []dns.RR {
	seen := make(map[string]struct{}, len(records))
	result := make([]dns.RR, 0, len(records))
	for _, record := range records {
		key := strings.ToLower(record.String())
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, record)
	}
	return result
}

func zoneRecordsFromRR(zoneName string, records []dns.RR) ([]ZoneRecord, error) {
	result := make([]ZoneRecord, 0, len(records))
	for _, record := range uniqueZoneRR(records) {
		owner := normalizeName(record.Header().Name)
		if owner != zoneName && !strings.HasSuffix(owner, "."+zoneName) {
			continue
		}
		name := "@"
		if owner != zoneName {
			name = strings.TrimSuffix(owner, "."+zoneName)
		}
		fields := strings.Fields(record.String())
		if len(fields) < 5 {
			return nil, fmt.Errorf("invalid transferred record %q", record.String())
		}
		recordType := dns.Type(record.Header().Rrtype).String()
		result = append(result, ZoneRecord{
			Name: name, Type: recordType,
			Value: strings.Join(fields[4:], " "), TTL: record.Header().Ttl,
		})
	}
	return result, nil
}
