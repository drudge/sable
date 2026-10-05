package dnsserver

import (
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/drudge/sable/internal/querylog"
)

func resolverDecision(runtime *Runtime, forwarders []string) querylog.ResolverDecision {
	if len(forwarders) > 0 || runtime.mode == "forward" {
		return querylog.ResolverForwarded
	}
	return querylog.ResolverRecursive
}

func dnssecDecision(validation validationState) querylog.DNSSECDecision {
	switch validation {
	case validationSecure:
		return querylog.DNSSECSecure
	case validationInsecure:
		return querylog.DNSSECInsecure
	case validationBogus:
		return querylog.DNSSECBogus
	default:
		return querylog.DNSSECIndeterminate
	}
}

type queryClient struct {
	ip       string
	protocol string
}

func (handler *Handler) recordQuery(
	observer querylog.Observer,
	client queryClient,
	request *dns.Msg,
	name string,
	result resolution,
	startedAt time.Time,
) {
	if len(request.Question) == 0 {
		return
	}
	question := request.Question[0]
	decision := result.decision
	if decision.Policy == "" {
		decision.Policy = querylog.PolicyNotEvaluated
	}
	if decision.Resolver == "" {
		decision.Resolver = resolverDecisionForSource(result.source)
	}
	observer.Record(querylog.Event{
		OccurredAt:   startedAt,
		ClientIP:     client.ip,
		Name:         name,
		RecordType:   question.Qtype,
		Class:        question.Qclass,
		ResponseCode: result.response.Rcode,
		Source:       result.source,
		Protocol:     client.protocol,
		Duration:     time.Since(startedAt),
		Decision:     decision,
		AnswerSource: (*loggedResponse)(result.response),
	})
}

// loggedResponse hands a written response to the query log, which formats its
// answer on the log writer's goroutine rather than the one serving the query.
// Nothing changes a response once the handler has written it, so the writer
// can read it later without a copy.
type loggedResponse dns.Msg

func (response *loggedResponse) QueryAnswer() string {
	return queryAnswer((*dns.Msg)(response))
}

func resolverDecisionForSource(source querylog.Source) querylog.ResolverDecision {
	switch source {
	case querylog.SourceAuthoritative:
		return querylog.ResolverAuthoritative
	case querylog.SourceLocal:
		return querylog.ResolverLocal
	case querylog.SourceBlocked:
		return querylog.ResolverBlocked
	case querylog.SourceCache:
		return querylog.ResolverCache
	case querylog.SourceUpstream:
		return querylog.ResolverForwarded
	default:
		return querylog.ResolverError
	}
}

func queryProtocol(writer dns.ResponseWriter) string {
	if marked, ok := writer.(interface{ QueryProtocol() string }); ok {
		return marked.QueryProtocol()
	}
	if _, ok := writer.(*dohResponseWriter); ok {
		return "HTTPS"
	}
	if address := writer.LocalAddr(); address != nil {
		network := strings.ToLower(address.Network())
		if strings.HasPrefix(network, "udp") {
			return "UDP"
		}
		if strings.HasPrefix(network, "tcp") {
			return "TCP"
		}
	}
	return ""
}

func queryAnswer(response *dns.Msg) string {
	if response == nil || len(response.Answer) == 0 {
		return ""
	}
	const maximumAnswerBytes = 16 << 10
	var result strings.Builder
	for index, record := range response.Answer {
		if index == 64 {
			break
		}
		value := queryRecordAnswer(record)
		if value == "" {
			continue
		}
		if result.Len()+len(value)+1 > maximumAnswerBytes {
			break
		}
		if result.Len() > 0 {
			result.WriteByte('\n')
		}
		result.WriteString(value)
	}
	return result.String()
}

func queryRecordAnswer(record dns.RR) string {
	switch value := record.(type) {
	case *dns.A:
		if value.A == nil {
			return "A"
		}
		return "A " + value.A.String()
	case *dns.AAAA:
		if value.AAAA == nil {
			return "AAAA"
		}
		address := value.AAAA.String()
		if value.AAAA.To4() != nil {
			address = "::ffff:" + address
		}
		return "AAAA " + address
	default:
		return queryRecordAnswerString(record.String())
	}
}

func queryRecordAnswerString(record string) string {
	index := 0
	for field := 0; field < 3; field++ {
		index = skipQueryAnswerSpace(record, index)
		index = skipQueryAnswerField(record, index)
	}
	var answer strings.Builder
	answer.Grow(len(record) - index)
	for {
		index = skipQueryAnswerSpace(record, index)
		if index == len(record) {
			break
		}
		fieldEnd := skipQueryAnswerField(record, index)
		if answer.Len() > 0 {
			answer.WriteByte(' ')
		}
		answer.WriteString(record[index:fieldEnd])
		index = fieldEnd
	}
	return answer.String()
}

func skipQueryAnswerSpace(value string, index int) int {
	for index < len(value) && isQueryAnswerSpace(value[index]) {
		index++
	}
	return index
}

func skipQueryAnswerField(value string, index int) int {
	for index < len(value) && !isQueryAnswerSpace(value[index]) {
		index++
	}
	return index
}

func isQueryAnswerSpace(value byte) bool {
	return value == ' ' || value == '\t' || value == '\n' || value == '\r'
}

func (handler *Handler) activeQueryObserver() querylog.Observer {
	holder := handler.observer.Load()
	if holder == nil || !holder.observer.Enabled() {
		return nil
	}
	return holder.observer
}
