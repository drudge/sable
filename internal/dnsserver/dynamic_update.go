package dnsserver

import (
	"context"
	"time"

	"github.com/miekg/dns"

	"github.com/drudge/sable/internal/querylog"
)

const dynamicUpdateTimeout = 15 * time.Second

type ZoneUpdateRequest struct {
	Zone          string
	Prerequisites []dns.RR
	Updates       []dns.RR
	KeyName       string
	Source        string
}

type ZoneUpdateResult struct {
	Rcode   int
	Changed bool
}

type ZoneUpdateFunc func(context.Context, ZoneUpdateRequest) ZoneUpdateResult

type ZoneUpdateAuditFunc func(context.Context, ZoneUpdateRequest, ZoneUpdateResult)

type zoneUpdaterHolder struct {
	update ZoneUpdateFunc
}

type zoneUpdateAuditorHolder struct {
	audit ZoneUpdateAuditFunc
}

func (handler *Handler) SetZoneUpdater(update ZoneUpdateFunc) {
	if update == nil {
		handler.zoneUpdater.Store(nil)
		return
	}
	handler.zoneUpdater.Store(&zoneUpdaterHolder{update: update})
}

func (handler *Handler) SetZoneUpdateAuditor(audit ZoneUpdateAuditFunc) {
	if audit == nil {
		handler.zoneUpdateAuditor.Store(nil)
		return
	}
	handler.zoneUpdateAuditor.Store(&zoneUpdateAuditorHolder{audit: audit})
}

func (handler *Handler) serveDynamicUpdate(
	writer dns.ResponseWriter,
	request *dns.Msg,
	runtime *Runtime,
	observer querylog.Observer,
	client queryClient,
	startedAt time.Time,
) bool {
	if request.Opcode != dns.OpcodeUpdate {
		return false
	}

	response := new(dns.Msg)
	response.SetReply(request)
	response.Authoritative = true
	result := ZoneUpdateResult{Rcode: dns.RcodeFormatError}
	updateRequest := ZoneUpdateRequest{
		Prerequisites: request.Answer, Updates: request.Ns, Source: client.ip,
	}
	if signature := request.IsTsig(); signature != nil {
		updateRequest.KeyName = signature.Hdr.Name
	}

	if len(request.Question) == 1 && request.Question[0].Qtype == dns.TypeSOA && request.Question[0].Qclass == dns.ClassINET {
		zoneName := normalizeName(request.Question[0].Name)
		updateRequest.Zone = zoneName
		zone := runtime.zones[zoneName]
		switch {
		case zone == nil || zone.kind != "primary":
			result.Rcode = dns.RcodeNotAuth
		case !zone.dynamic:
			result.Rcode = dns.RcodeRefused
		case zone.tsigKey == "":
			result.Rcode = dns.RcodeRefused
		case isDoHWriter(writer) || !tsigRequestAuthenticated(writer, request, zone.tsigKey):
			result.Rcode = dns.RcodeRefused
		case !validUpdateAdditionalSection(request.Extra):
			result.Rcode = dns.RcodeFormatError
		default:
			updater := handler.zoneUpdater.Load()
			if updater == nil {
				result.Rcode = dns.RcodeServerFailure
			} else {
				ctx, cancel := context.WithTimeout(context.Background(), dynamicUpdateTimeout)
				result = updater.update(ctx, updateRequest)
				cancel()
			}
		}
	}

	response.Rcode = result.Rcode
	if auditor := handler.zoneUpdateAuditor.Load(); auditor != nil {
		ctx, cancel := context.WithTimeout(context.Background(), dynamicUpdateTimeout)
		auditor.audit(ctx, updateRequest, result)
		cancel()
	}
	if signature := request.IsTsig(); signature != nil && writer.TsigStatus() == nil {
		response.SetTsig(signature.Hdr.Name, signature.Algorithm, signature.Fudge, time.Now().Unix())
	}
	handler.recordResponseCode(response.Rcode)
	handler.writeResponse(writer, request, response)
	if observer != nil {
		handler.recordQuery(observer, client, request, resolution{response: response, source: querylog.SourceAuthoritative}, startedAt)
	}
	return true
}

func validUpdateAdditionalSection(records []dns.RR) bool {
	for index, record := range records {
		switch record.Header().Rrtype {
		case dns.TypeOPT:
		case dns.TypeTSIG:
			if index != len(records)-1 {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func isDoHWriter(writer dns.ResponseWriter) bool {
	_, ok := writer.(*dohResponseWriter)
	return ok
}
