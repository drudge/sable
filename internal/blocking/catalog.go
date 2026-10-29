package blocking

// HageziProURL is shared by the catalog and the migration of retired subscriptions.
const HageziProURL = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.txt"

// URLhausURL is the malware-filter mirror of URLhaus's online malware hosts.
// abuse.ch retired its keyless downloads on 2026-10-21, so the hostfile it
// replaces answers 410 Gone.
const URLhausURL = "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-hosts-online.txt"

// RetiredURLs maps subscriptions whose upstream went away to the catalog
// entry that replaces them, so saved configurations keep refreshing.
var RetiredURLs = map[string]string{
	"https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/pro.txt": HageziProURL,
	"https://urlhaus.abuse.ch/downloads/hostfile/":                               URLhausURL,
}
