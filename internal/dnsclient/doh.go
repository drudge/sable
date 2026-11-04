package dnsclient

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"

	"github.com/miekg/dns"
)

// maxDoHMessage is the largest DNS message a DoH response may carry. RFC 8484
// §6 drops UDP's size limit and truncation: an answer travels whole, up to the
// 65535 octets a DNS message can be (RFC 1035 §4.2.2's two-byte length).
const maxDoHMessage = dns.MaxMsgSize

// ErrDoHAnswer wraps every failure after the server answered over HTTP, such
// as a non-200 status or a malformed body, apart from failures to reach it.
var ErrDoHAnswer = errors.New("DoH server answered")

// ExchangeDoH sends message to an RFC 8484 server with POST and returns its
// answer. message is not modified.
//
//   - The body is the DNS wire format with media type application/dns-message,
//     and the same type is the only one accepted back (RFC 8484 §4.1, §4.2.1,
//     §6).
//   - The message ID on the wire is 0, which RFC 8484 §4.1 asks for so
//     identical queries are identical HTTP requests and cache well. The
//     answer gets message's own ID back.
//   - Only HTTP 200 carries an answer. Any other status, including a DNS
//     error carried in a 2xx, is a failed exchange (RFC 8484 §4.2.1).
//
// Errors leave out the request URL, which can carry a per-account path or
// query on some public resolvers.
func ExchangeDoH(ctx context.Context, client *http.Client, endpoint string, message *dns.Msg) (*dns.Msg, error) {
	wire, err := message.Pack()
	if err != nil {
		return nil, fmt.Errorf("pack DNS request: %w", err)
	}
	wire[0], wire[1] = 0, 0
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(wire))
	if err != nil {
		return nil, errors.New("create HTTPS request: invalid DoH URL")
	}
	request.Header.Set("Accept", dohMediaType)
	request.Header.Set("Content-Type", dohMediaType)

	response, err := client.Do(request)
	if err != nil {
		if urlErr, ok := errors.AsType[*url.Error](err); ok {
			err = urlErr.Err
		}
		return nil, fmt.Errorf("DoH request: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4<<10))
		return nil, fmt.Errorf("%w with HTTP %d", ErrDoHAnswer, response.StatusCode)
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != dohMediaType {
		return nil, fmt.Errorf("%w with content type %q", ErrDoHAnswer, response.Header.Get("Content-Type"))
	}
	if response.ContentLength > maxDoHMessage {
		return nil, fmt.Errorf("%w with an oversized DNS response", ErrDoHAnswer)
	}
	responseWire, err := io.ReadAll(io.LimitReader(response.Body, maxDoHMessage+1))
	if err != nil {
		return nil, fmt.Errorf("read DNS response: %w", err)
	}
	if len(responseWire) > maxDoHMessage {
		return nil, fmt.Errorf("%w with an oversized DNS response", ErrDoHAnswer)
	}
	answer := new(dns.Msg)
	if err := answer.Unpack(responseWire); err != nil {
		return nil, fmt.Errorf("%w with a malformed DNS message: %w", ErrDoHAnswer, err)
	}
	// A server echoes the 0 it was sent. Anything else answers some other
	// request, the way a mismatched ID does on any other transport.
	if answer.Id != 0 && answer.Id != message.Id {
		return nil, fmt.Errorf("%w with a message ID that does not match the request", ErrDoHAnswer)
	}
	answer.Id = message.Id
	return answer, nil
}
