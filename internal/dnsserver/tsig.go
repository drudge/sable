package dnsserver

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"hash"
	"strings"
	"time"

	"github.com/miekg/dns"
)

type transferAuth struct {
	keyName   string
	algorithm string
	secret    string
}

func (handler *Handler) Generate(message []byte, record *dns.TSIG) ([]byte, error) {
	key, found := handler.tsigKey(record.Hdr.Name)
	if !found {
		return nil, dns.ErrSecret
	}
	return tsigMAC(message, record.Algorithm, key.secret)
}

func (handler *Handler) Verify(message []byte, record *dns.TSIG) error {
	expected, err := handler.Generate(message, record)
	if err != nil {
		return err
	}
	actual, err := hex.DecodeString(record.MAC)
	if err != nil {
		return err
	}
	if !hmac.Equal(expected, actual) {
		return dns.ErrSig
	}
	return nil
}

func (handler *Handler) tsigKey(name string) (tsigKey, bool) {
	key, found := handler.runtime.Load().tsigKeys[strings.ToLower(dns.Fqdn(name))]
	return key, found
}

func (handler *Handler) transferAuth(zoneName, configuredKey string) transferAuth {
	runtime := handler.runtime.Load()
	keyName := configuredKey
	if keyName == "" {
		if managed, found := runtime.managedZones[normalizeName(zoneName)]; found {
			keyName = managed.tsigKey
		} else if zone := runtime.zones[normalizeName(zoneName)]; zone != nil {
			keyName = zone.tsigKey
		}
	}
	if keyName == "" {
		return transferAuth{}
	}
	key, found := runtime.tsigKeys[strings.ToLower(dns.Fqdn(keyName))]
	if !found {
		return transferAuth{}
	}
	return transferAuth{keyName: strings.ToLower(dns.Fqdn(keyName)), algorithm: key.algorithm, secret: key.secret}
}

func tsigMAC(message []byte, algorithm, secret string) ([]byte, error) {
	rawSecret, err := base64.StdEncoding.DecodeString(secret)
	if err != nil {
		return nil, err
	}
	var digest hash.Hash
	switch strings.ToLower(dns.Fqdn(algorithm)) {
	case dns.HmacSHA256:
		digest = hmac.New(sha256.New, rawSecret)
	case dns.HmacSHA384:
		digest = hmac.New(sha512.New384, rawSecret)
	case dns.HmacSHA512:
		digest = hmac.New(sha512.New, rawSecret)
	default:
		return nil, dns.ErrKeyAlg
	}
	_, _ = digest.Write(message)
	return digest.Sum(nil), nil
}

func tsigRequestAuthenticated(writer dns.ResponseWriter, request *dns.Msg, expectedKey string) bool {
	if expectedKey == "" {
		return true
	}
	record := request.IsTsig()
	return record != nil && strings.EqualFold(record.Hdr.Name, dns.Fqdn(expectedKey)) && writer.TsigStatus() == nil
}

func applyTransferTSIG(request *dns.Msg, transfer *dns.Transfer, auth transferAuth) {
	if auth.keyName == "" {
		return
	}
	transfer.TsigSecret = map[string]string{auth.keyName: auth.secret}
	request.SetTsig(auth.keyName, auth.algorithm, 300, timeNowUnix())
}

var timeNowUnix = func() int64 { return time.Now().Unix() }
