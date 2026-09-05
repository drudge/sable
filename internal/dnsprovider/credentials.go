package dnsprovider

// Credentials contains the union of fields used by supported external DNS
// providers. Values are sealed in Sable's secret vault rather than serialized
// into the runtime configuration.
type Credentials struct {
	APIToken          string `json:"api_token,omitempty"`
	APIKey            string `json:"api_key,omitempty"`
	Secret            string `json:"secret,omitempty"`
	Username          string `json:"username,omitempty"`
	ClientIP          string `json:"client_ip,omitempty"`
	ZoneID            string `json:"zone_id,omitempty"`
	Server            string `json:"server,omitempty"`
	TSIGName          string `json:"tsig_name,omitempty"`
	TSIGSecret        string `json:"tsig_secret,omitempty"`
	TSIGAlgorithm     string `json:"tsig_algorithm,omitempty"`
	AccessKeyID       string `json:"access_key_id,omitempty"`
	SecretAccessKey   string `json:"secret_access_key,omitempty"`
	SessionToken      string `json:"session_token,omitempty"`
	Endpoint          string `json:"endpoint,omitempty"`
	ApplicationKey    string `json:"application_key,omitempty"`
	ApplicationSecret string `json:"application_secret,omitempty"`
	ConsumerKey       string `json:"consumer_key,omitempty"`
}
