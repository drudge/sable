package blocking

// HageziProURL is shared by the catalog and the migration of retired subscriptions.
const HageziProURL = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.txt"

// CatalogEntry is a block list the console offers to add with one click.
type CatalogEntry struct{ Name, Description, URL, Category string }

// Catalog is the console's list of popular block lists. The catalog smoke test
// (go tool mage catalogSmoke) downloads every one through Sable itself, so a
// change that breaks them shows up before a release.
var Catalog = []CatalogEntry{
	{"OISD Big", "Comprehensive list blocking ads, trackers, and malware", "https://big.oisd.nl/", "popular"},
	{"OISD Small", "Lightweight version with fewer false positives", "https://small.oisd.nl/", "popular"},
	{"Steven Black Unified", "Unified hosts file with adware and malware extensions", "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts", "popular"},
	{"Hagezi Pro", "Multi-source blocklist with strong protection", HageziProURL, "popular"},
	{"AdGuard DNS Filter", "Official AdGuard DNS filter list", "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt", "ads"},
	{"AdAway Default", "Default blocklist from the AdAway project", "https://adaway.org/hosts.txt", "ads"},
	{"EasyList", "Primary advertising filter list", "https://easylist.to/easylist/easylist.txt", "ads"},
	{"Peter Lowe Ad/Tracking", "Known advertising and tracking servers", "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0", "ads"},
	{"URLhaus Malicious URLs", "Malware distribution sites from abuse.ch", "https://urlhaus.abuse.ch/downloads/hostfile/", "malware"},
	{"Phishing Army", "Community phishing domain blocklist", "https://phishing.army/download/phishing_army_blocklist.txt", "malware"},
	{"EasyPrivacy", "Tracking and privacy protection", "https://easylist.to/easylist/easyprivacy.txt", "privacy"},
	{"Steven Black + Social", "Base list with social media sites blocked", "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/social/hosts", "social"},
}
