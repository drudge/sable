package blocking

import "strings"

// HageziProURL is shared by the catalog and the migration of retired subscriptions.
const HageziProURL = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.txt"

// URLhausURL is the malware-filter mirror of URLhaus's online malware hosts.
// abuse.ch retired its keyless downloads on 2026-10-21, so the hostfile it
// replaces answers 410 Gone.
const URLhausURL = "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-hosts-online.txt"

// AbuseCHKeyPlaceholder stands in for the operator's abuse.ch Auth-Key in a
// saved list URL. The updater fills it in at download time, so the key stays
// in the vault and never reaches sable.toml, the console, or the logs.
const AbuseCHKeyPlaceholder = "{abusech_auth_key}"

// URLhausKeyedURL is URLhaus's own hostfile, served to holders of an abuse.ch
// Auth-Key.
const URLhausKeyedURL = "https://urlhaus-api.abuse.ch/v2/files/exports/" + AbuseCHKeyPlaceholder + "/hostfile.txt"

// NeedsAbuseCHKey reports whether a list URL downloads only with an abuse.ch
// Auth-Key.
func NeedsAbuseCHKey(url string) bool { return strings.Contains(url, AbuseCHKeyPlaceholder) }

// RetiredURLs maps subscriptions whose upstream went away to the catalog
// entry that replaces them, so saved configurations keep refreshing.
var RetiredURLs = map[string]string{
	"https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/pro.txt": HageziProURL,
	"https://urlhaus.abuse.ch/downloads/hostfile/":                               URLhausURL,
}
