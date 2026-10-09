// Package services names the apps and services behind domain names, so
// Insights can say "started using Discord" instead of listing the fourteen
// domains Discord happens to use. The catalog is a fixed local table matched
// by domain suffix: no lookups leave the machine, and a name matches only
// domains its service owns, never shared hosting or content networks that
// would mislabel unrelated traffic.
package services

import (
	"cmp"
	"slices"
	"strings"
)

// Categories group services by what people use them for.
const (
	CategoryStreaming    = "Streaming"
	CategoryMusic        = "Music"
	CategorySocial       = "Social"
	CategoryMessaging    = "Messaging"
	CategoryCalls        = "Video calls"
	CategoryGaming       = "Gaming"
	CategoryShopping     = "Shopping"
	CategorySmartHome    = "Smart home"
	CategoryCameras      = "Cameras"
	CategoryCloud        = "Cloud storage"
	CategoryProductivity = "Productivity"
	CategoryDeveloper    = "Developer"
	CategoryAI           = "AI assistants"
	CategoryNews         = "News"
	CategorySearch       = "Search"
	CategoryPlatform     = "Device platform"
	CategorySecurity     = "Security"
	CategoryFinance      = "Finance"
	// CategoryRemoteAccess is tunnels and remote control tools, which can let
	// someone reach the network from outside. Insights treats a device that
	// starts using one as worth a look.
	CategoryRemoteAccess = "Remote access"
)

// BlockCategories are the categories a rule set offers to block, in the
// order the console shows them: apps people limit for kids, guests, or work.
// Device platforms, smart home, cameras, security, and work tools are left
// out, since blocking them breaks the devices that rely on them, though a
// rule set may still name any app in the catalog.
var BlockCategories = []string{
	CategorySocial, CategoryStreaming, CategoryGaming, CategoryMessaging, CategoryMusic,
	CategoryCalls, CategoryAI, CategoryShopping, CategoryNews, CategoryRemoteAccess,
}

// Service is one app or service people would recognize by name.
type Service struct {
	ID       string
	Name     string
	Category string
}

// ForSuffix names the service one of whose own domains is exactly domain,
// not a parent of it, so a rule that blocks that domain can name the app.
func ForSuffix(domain string) (Service, bool) {
	index, found := bySuffix[strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")]
	if !found {
		return Service{}, false
	}
	return catalog[index].service, true
}

// Lookup names the service that owns a domain, matching the domain itself and
// then each parent, so "rr3---sn-abc.googlevideo.com" is YouTube.
func Lookup(name string) (Service, bool) {
	name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	for name != "" {
		if index, found := bySuffix[name]; found {
			return catalog[index].service, true
		}
		_, parent, found := strings.Cut(name, ".")
		if !found {
			break
		}
		name = parent
	}
	return Service{}, false
}

// All lists every service Sable recognizes, in catalog order.
func All() []Service {
	all := make([]Service, 0, len(catalog))
	for _, entry := range catalog {
		all = append(all, entry.service)
	}
	return all
}

// InCategory lists the IDs of the services in a category, in catalog order.
func InCategory(category string) []string {
	ids := make([]string, 0)
	for _, entry := range catalog {
		if entry.service.Category == category {
			ids = append(ids, entry.service.ID)
		}
	}
	return ids
}

// Find returns a service by its ID.
func Find(id string) (Service, bool) {
	for _, entry := range catalog {
		if entry.service.ID == id {
			return entry.service, true
		}
	}
	return Service{}, false
}

// Domain is one name and how often it was queried.
type Domain struct {
	Name    string
	Queries uint64
}

// Usage is one service and the domains that showed it being used.
type Usage struct {
	Service Service
	Queries uint64
	// Domains are the matched names, busiest first.
	Domains []Domain
}

// Group gathers domains into the services that own them, busiest first.
// Domains no service owns are left out.
func Group(domains []Domain) []Usage {
	byService := make(map[string]*Usage)
	for _, domain := range domains {
		service, found := Lookup(domain.Name)
		if !found {
			continue
		}
		usage := byService[service.ID]
		if usage == nil {
			usage = &Usage{Service: service}
			byService[service.ID] = usage
		}
		usage.Queries += domain.Queries
		usage.Domains = append(usage.Domains, domain)
	}
	usages := make([]Usage, 0, len(byService))
	for _, usage := range byService {
		slices.SortFunc(usage.Domains, func(left, right Domain) int {
			if order := cmp.Compare(right.Queries, left.Queries); order != 0 {
				return order
			}
			return cmp.Compare(left.Name, right.Name)
		})
		usages = append(usages, *usage)
	}
	slices.SortFunc(usages, func(left, right Usage) int {
		if order := cmp.Compare(right.Queries, left.Queries); order != 0 {
			return order
		}
		return cmp.Compare(left.Service.Name, right.Service.Name)
	})
	return usages
}

type catalogEntry struct {
	service  Service
	suffixes []string
}

var bySuffix = func() map[string]int {
	index := make(map[string]int)
	for position, entry := range catalog {
		for _, suffix := range entry.suffixes {
			index[suffix] = position
		}
	}
	return index
}()

// Suffixes lists the domains the given services own, so a caller can read
// just the names that could belong to them.
func Suffixes(ids []string) []string {
	suffixes := make([]string, 0)
	for _, entry := range catalog {
		if slices.Contains(ids, entry.service.ID) {
			suffixes = append(suffixes, entry.suffixes...)
		}
	}
	slices.Sort(suffixes)
	return suffixes
}
