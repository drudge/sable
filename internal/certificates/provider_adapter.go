package certificates

import "github.com/drudge/sable/internal/dnsprovider"

type dnsProvider = dnsprovider.Provider

func validateCredentials(name string, credentials Credentials) error {
	return dnsprovider.ValidateCredentials(name, credentials)
}

func newDNSProvider(name string, credentials Credentials) (dnsProvider, error) {
	return dnsprovider.New(name, credentials)
}
