package zone

import (
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/drudge/sable/internal/dnsname"
)

// CatalogSchemaVersion is the only RFC 9432 schema version Sable implements.
// A catalog carrying any other value is not processed at all, because a future
// schema may reinterpret records this one already understands.
const CatalogSchemaVersion = "2"

// SourceCatalog marks the records a producer catalog derives from its member
// zones. They are replaced wholesale on every reconciliation, so the apex SOA
// and NS records an operator authored must not carry this source.
const SourceCatalog = "catalog"

// catalogMemberPrefix is the fixed label RFC 9432 places between a member's
// unique label and the catalog apex.
const catalogMemberPrefix = "zones"

// catalogLabelEncoding produces lowercase base32hex labels. Its alphabet is
// restricted to digits and letters, so every label it emits is a legal DNS
// label without escaping.
var catalogLabelEncoding = base32.HexEncoding.WithPadding(base32.NoPadding)

// IsCatalog reports whether the zone is an RFC 9432 catalog zone in either
// role.
func IsCatalog(current Zone) bool { return current.Type == "catalog" }

// IsConsumerCatalog reports whether the zone is a catalog transferred from a
// remote producer. Membership changes in a consumer catalog provision and
// remove local zones.
func IsConsumerCatalog(current Zone) bool {
	return current.Type == "catalog" && len(current.PrimaryServers) > 0
}

// IsProducerCatalog reports whether the zone is a catalog published from this
// server. Its member records are derived from the zones that name it, so they
// are rebuilt on every mutation rather than edited by hand.
func IsProducerCatalog(current Zone) bool {
	return current.Type == "catalog" && len(current.PrimaryServers) == 0
}

// AwaitingFirstTransfer reports whether a zone exists only as a catalog
// membership that has not been transferred yet. A catalog tells a consumer
// which zones to serve but carries none of their content, so a freshly
// provisioned member holds no records until the refresher reaches it. Such a
// zone answers nothing and is exempt from the record rules every other zone
// must satisfy.
func AwaitingFirstTransfer(current Zone) bool {
	return current.CatalogZone != "" && current.Type == "secondary" && len(current.Records) == 0
}

// MemberLabel returns the <unique-N> label identifying a member zone inside a
// catalog. RFC 9432 only requires the label to be unique within the catalog,
// so deriving it from the member name keeps materialization idempotent: the
// same membership always produces the same records, and a member that never
// changed never looks to a consumer like a remove-then-add.
func MemberLabel(memberName string) string {
	digest := sha256.Sum256([]byte(normalizeDomain(memberName)))
	return strings.ToLower(catalogLabelEncoding.EncodeToString(digest[:10]))
}

// CatalogMember is one entry parsed out of a catalog zone.
type CatalogMember struct {
	// Label is the <unique-N> owner label the producer assigned.
	Label string
	// Zone is the member zone name the PTR record points at.
	Zone string
	// Group carries the optional group property, empty when absent.
	Group string
	// ChangeOwner names the catalog this member is being handed to, empty when
	// the producer published no coo property.
	ChangeOwner string
}

// CatalogContents is the processed view of a catalog zone.
type CatalogContents struct {
	Members []CatalogMember
}

// ParseCatalog reads the RFC 9432 content of a catalog zone. It returns an
// error for every condition the RFC calls a broken catalog, because a broken
// catalog must be left entirely unprocessed rather than partially applied.
func ParseCatalog(catalogName string, records []Record) (CatalogContents, error) {
	catalogName = normalizeDomain(catalogName)
	if catalogName == "" {
		return CatalogContents{}, errors.New("catalog zone name is required")
	}
	versions := make([]string, 0, 1)
	pointers := make(map[string]string)
	groups := make(map[string][]string)
	changeOwners := make(map[string][]string)
	for _, record := range records {
		if record.Disabled {
			continue
		}
		owner := catalogRelativeName(catalogName, record.Name)
		recordType := strings.ToUpper(strings.TrimSpace(record.Type))
		switch {
		case owner == "version" && recordType == "TXT":
			versions = append(versions, catalogTextValue(record.Value))
		case recordType == "PTR":
			label, property, ok := splitCatalogMemberName(owner)
			if !ok {
				continue
			}
			target, err := dnsname.Normalize(record.Value)
			if err != nil {
				return CatalogContents{}, fmt.Errorf("member %q has an unusable target %q", label, record.Value)
			}
			switch property {
			case "":
				// "This PTR record MUST be the only record in the PTR RRset
				// with the same name", so a second one makes the catalog
				// broken even when both point at the same member.
				if _, duplicate := pointers[label]; duplicate {
					return CatalogContents{}, fmt.Errorf("member %q has more than one PTR record", label)
				}
				pointers[label] = target
			case "coo":
				changeOwners[label] = append(changeOwners[label], target)
			}
		case recordType == "TXT":
			label, property, ok := splitCatalogMemberName(owner)
			if !ok || property != "group" {
				continue
			}
			groups[label] = append(groups[label], catalogTextValue(record.Value))
		}
	}
	// "All catalog zones MUST have a TXT RRset named version.$CATZ with exactly
	// one RR", and a version this build does not implement must not be applied.
	if len(versions) == 0 {
		return CatalogContents{}, errors.New("catalog zone has no version property")
	}
	if len(versions) > 1 {
		return CatalogContents{}, errors.New("catalog zone version property has more than one record")
	}
	if versions[0] != CatalogSchemaVersion {
		return CatalogContents{}, fmt.Errorf("unsupported catalog schema version %q", versions[0])
	}

	members := make([]CatalogMember, 0, len(pointers))
	seenZones := make(map[string]string, len(pointers))
	for label, target := range pointers {
		if previous, duplicate := seenZones[target]; duplicate {
			// Two labels pointing at one member zone is explicitly a broken
			// catalog, because neither label can be treated as authoritative
			// for the member's state.
			return CatalogContents{}, fmt.Errorf(
				"member zone %q is listed under both %q and %q", target, previous, label,
			)
		}
		seenZones[target] = label
		if target == catalogName {
			return CatalogContents{}, fmt.Errorf("catalog zone %q lists itself as a member", catalogName)
		}
		member := CatalogMember{Label: label, Zone: target}
		if values := groups[label]; len(values) > 0 {
			// A member may carry several groups. Sable applies one member
			// template per catalog, so the lowest-sorting value is recorded for
			// display and the rest are ignored rather than silently merged.
			slices.Sort(values)
			member.Group = values[0]
		}
		if values := changeOwners[label]; len(values) == 1 {
			// "The PTR RRset MUST consist of a single PTR record." More than
			// one makes the property unusable, so the handoff is ignored and
			// the member stays with its current owner.
			member.ChangeOwner = values[0]
		}
		members = append(members, member)
	}
	slices.SortFunc(members, func(left, right CatalogMember) int {
		return strings.Compare(left.Zone, right.Zone)
	})
	return CatalogContents{Members: members}, nil
}

// splitCatalogMemberName decomposes an owner name relative to the catalog apex
// into the member's unique label and an optional property prefix. It reports
// false for any name that does not describe a member node.
func splitCatalogMemberName(owner string) (label, property string, ok bool) {
	if !strings.HasSuffix(owner, "."+catalogMemberPrefix) {
		return "", "", false
	}
	remainder := strings.TrimSuffix(owner, "."+catalogMemberPrefix)
	if remainder == "" {
		return "", "", false
	}
	labels := strings.Split(remainder, ".")
	switch len(labels) {
	case 1:
		return labels[0], "", true
	case 2:
		// Property nodes are <property>.<unique-N>.zones, so the member label
		// is the last remaining label.
		return labels[1], labels[0], true
	default:
		// Anything deeper is either an "ext" custom property or a name this
		// schema version does not define. Both are ignored rather than treated
		// as an error, so an unknown extension cannot break a valid catalog.
		return "", "", false
	}
}

// catalogRelativeName renders a record owner relative to the catalog apex.
func catalogRelativeName(catalogName, recordName string) string {
	recordName = strings.ToLower(strings.TrimSpace(recordName))
	if recordName == "" || recordName == "@" {
		return "@"
	}
	if !strings.HasSuffix(recordName, ".") {
		return recordName
	}
	owner := strings.TrimSuffix(recordName, ".")
	if owner == catalogName {
		return "@"
	}
	if !strings.HasSuffix(owner, "."+catalogName) {
		return ""
	}
	return strings.TrimSuffix(owner, "."+catalogName)
}

// catalogTextValue strips the quoting a TXT record carries in presentation
// form. Catalog properties are single short strings, so the whole value is
// taken verbatim once the surrounding quotes are removed.
func catalogTextValue(value string) string {
	value = strings.TrimSpace(value)
	if len(value) >= 2 && strings.HasPrefix(value, `"`) && strings.HasSuffix(value, `"`) {
		unquoted := value[1 : len(value)-1]
		if !strings.Contains(unquoted, `"`) {
			return unquoted
		}
	}
	return value
}

// MaterializeCatalogs rebuilds the derived content of every producer catalog
// from the zones that name it. Like alias mirroring it runs on every catalog
// mutation and must be idempotent, so the SOA serial only advances when the
// published membership actually changed.
func MaterializeCatalogs(zones *[]Zone, now time.Time) error {
	if zones == nil {
		return nil
	}
	producers := make(map[string]struct{})
	for _, current := range *zones {
		if IsProducerCatalog(current) {
			producers[current.Name] = struct{}{}
		}
	}
	memberships := make(map[string][]CatalogMember)
	for index := range *zones {
		member := &(*zones)[index]
		if member.Type == "catalog" || member.CatalogZone == "" {
			continue
		}
		if _, published := producers[member.CatalogZone]; !published {
			// The zone belongs to a consumer catalog, which assigned its label
			// remotely. Deriving one here would overwrite the producer's.
			continue
		}
		label := MemberLabel(member.Name)
		member.CatalogMemberID = label
		if member.Disabled {
			// A disabled zone answers nothing here, so listing it would tell
			// every secondary to serve a zone this server has switched off.
			continue
		}
		memberships[member.CatalogZone] = append(memberships[member.CatalogZone], CatalogMember{
			Label: label, Zone: member.Name, Group: member.CatalogGroup,
		})
	}
	for index := range *zones {
		catalog := &(*zones)[index]
		if !IsProducerCatalog(*catalog) {
			continue
		}
		members := memberships[catalog.Name]
		slices.SortFunc(members, func(left, right CatalogMember) int {
			return strings.Compare(left.Zone, right.Zone)
		})
		if err := materializeCatalog(catalog, members, now); err != nil {
			return fmt.Errorf("publish catalog zone %q: %w", catalog.Name, err)
		}
	}
	return nil
}

func materializeCatalog(catalog *Zone, members []CatalogMember, now time.Time) error {
	ttl := catalog.DefaultTTL
	if ttl == 0 {
		ttl = defaultTTL
	}
	published := make([]Record, 0, len(members)*2+1)
	published = append(published, Record{
		Name: "version", Type: "TXT", TTL: ttl,
		Value: `"` + CatalogSchemaVersion + `"`, Source: SourceCatalog,
	})
	for _, member := range members {
		node := member.Label + "." + catalogMemberPrefix
		published = append(published, Record{
			Name: node, Type: "PTR", TTL: ttl,
			Value: dns.Fqdn(member.Zone), Source: SourceCatalog,
		})
		if member.Group == "" {
			continue
		}
		published = append(published, Record{
			Name: "group." + node, Type: "TXT", TTL: ttl,
			Value: `"` + member.Group + `"`, Source: SourceCatalog,
		})
	}
	slices.SortFunc(published, compareRecords)

	retained := make([]Record, 0, len(catalog.Records)+len(published))
	previous := make([]Record, 0, len(catalog.Records))
	for _, record := range catalog.Records {
		if record.Source == SourceCatalog {
			previous = append(previous, record)
			continue
		}
		retained = append(retained, record)
	}
	slices.SortFunc(previous, compareRecords)
	if slices.EqualFunc(previous, published, sameMirroredRecord) {
		return nil
	}
	catalog.Records = append(retained, published...)
	slices.SortFunc(catalog.Records, compareRecords)
	AdvanceSerial(catalog, now)
	return nil
}

// NewCatalog builds an empty catalog zone. RFC 9432 recommends an apex NS of
// "invalid." because a catalog zone is only ever transferred, never resolved,
// and Sable refuses ordinary queries against it for the same reason.
func NewCatalog(name string, now time.Time) (Zone, error) {
	catalog, err := NewPrimary(name, defaultTTL, "invalid.", "hostmaster."+normalizeDomain(name), now)
	if err != nil {
		return Zone{}, err
	}
	catalog.Type = "catalog"
	return catalog, nil
}

func validateCatalogZone(field string, current Zone, zoneTypes map[string]string) []error {
	var result []error
	if current.CatalogZone != "" {
		if current.CatalogZone == current.Name {
			result = append(result, fmt.Errorf("%s cannot be a member of itself", field))
		} else if catalogType, found := zoneTypes[current.CatalogZone]; !found {
			result = append(result, fmt.Errorf("%s belongs to unknown catalog zone %q", field, current.CatalogZone))
		} else if catalogType != "catalog" {
			result = append(result, fmt.Errorf(
				"%s names %q as its catalog, but that zone is a %s zone", field, current.CatalogZone, catalogType,
			))
		}
	}
	if current.Type != "catalog" {
		return result
	}
	if current.DNSSEC {
		// Catalog zones are never resolved, so signing them buys nothing and
		// the extra RRSIGs only inflate every transfer.
		result = append(result, fmt.Errorf("%s DNSSEC signing is not supported for catalog zones", field))
	}
	if current.DynamicUpdates {
		result = append(result, fmt.Errorf("%s dynamic updates are not supported for catalog zones", field))
	}
	// A consumer catalog holds whatever its producer sent. Its contents are
	// deliberately not validated here: rejecting the transfer would strand the
	// zone on stale records, so reconciliation reports a broken catalog and
	// leaves the previously provisioned members untouched.
	return result
}

// CatalogEventKind classifies what reconciliation did to a catalog membership.
type CatalogEventKind string

const (
	// CatalogMemberAdded reports a zone provisioned from a catalog.
	CatalogMemberAdded CatalogEventKind = "member_added"
	// CatalogMemberRemoved reports a zone withdrawn from a catalog.
	CatalogMemberRemoved CatalogEventKind = "member_removed"
	// CatalogMemberHandedOver reports a member migrated between catalogs
	// through a change of ownership.
	CatalogMemberHandedOver CatalogEventKind = "member_handed_over"
	// CatalogMemberConflict reports a member this server already serves under
	// different ownership, which the RFC forbids taking over.
	CatalogMemberConflict CatalogEventKind = "member_conflict"
	// CatalogBroken reports a catalog left entirely unprocessed.
	CatalogBroken CatalogEventKind = "catalog_broken"
)

// CatalogEvent describes one reconciliation outcome for the operator log.
type CatalogEvent struct {
	Kind    CatalogEventKind
	Catalog string
	Zone    string
	Detail  string
}

// ReconcileCatalogs applies the membership of every consumer catalog to the
// local zone set, provisioning zones the catalog lists and withdrawing zones it
// no longer lists. It returns the events worth logging rather than logging them
// itself, so it stays usable inside a zone transaction.
//
// A catalog that fails to parse is skipped whole. RFC 9432 is explicit that a
// previously correct catalog turning broken must not remove or reconfigure any
// member, because a truncated or malformed transfer would otherwise tear down
// production zones.
func ReconcileCatalogs(zones *[]Zone) []CatalogEvent {
	if zones == nil {
		return nil
	}
	catalogs := make([]Zone, 0)
	for _, current := range *zones {
		if IsConsumerCatalog(current) && !current.Disabled {
			catalogs = append(catalogs, current)
		}
	}
	slices.SortFunc(catalogs, func(left, right Zone) int { return strings.Compare(left.Name, right.Name) })

	var events []CatalogEvent
	for _, catalog := range catalogs {
		contents, err := ParseCatalog(catalog.Name, catalog.Records)
		if err != nil {
			events = append(events, CatalogEvent{
				Kind: CatalogBroken, Catalog: catalog.Name, Detail: err.Error(),
			})
			continue
		}
		events = append(events, reconcileCatalog(zones, catalog, contents)...)
	}
	return events
}

func reconcileCatalog(zones *[]Zone, catalog Zone, contents CatalogContents) []CatalogEvent {
	var events []CatalogEvent
	desired := make(map[string]CatalogMember, len(contents.Members))
	for _, member := range contents.Members {
		desired[member.Zone] = member
	}
	retained := make([]Zone, 0, len(*zones))
	for _, current := range *zones {
		if current.CatalogZone != catalog.Name || current.Type == "catalog" {
			retained = append(retained, current)
			continue
		}
		if _, listed := desired[current.Name]; listed {
			retained = append(retained, current)
			continue
		}
		// Only zones this catalog provisioned are withdrawn. A zone that
		// carries another catalog's name, or none, never reaches this branch.
		events = append(events, CatalogEvent{
			Kind: CatalogMemberRemoved, Catalog: catalog.Name, Zone: current.Name,
		})
	}
	*zones = retained

	existing := make(map[string]int, len(*zones))
	for index, current := range *zones {
		existing[current.Name] = index
	}
	for _, member := range contents.Members {
		index, found := existing[member.Zone]
		if !found {
			*zones = append(*zones, catalogMemberZone(catalog, member))
			events = append(events, CatalogEvent{
				Kind: CatalogMemberAdded, Catalog: catalog.Name, Zone: member.Zone, Detail: member.Group,
			})
			continue
		}
		current := &(*zones)[index]
		if current.CatalogZone == catalog.Name {
			applyCatalogMembership(current, catalog, member)
			continue
		}
		if current.CatalogZone == "" {
			// The operator configured this zone by hand. Adopting it would
			// silently hand local configuration to a remote producer.
			events = append(events, CatalogEvent{
				Kind: CatalogMemberConflict, Catalog: catalog.Name, Zone: member.Zone,
				Detail: "zone is configured locally and was not adopted",
			})
			continue
		}
		if member.ChangeOwner == current.CatalogZone {
			// This catalog published the handoff that moved the member to its
			// current owner. Listing it until the producer drops the entry is
			// expected, so it is not a conflict.
			continue
		}
		if current.CatalogChangeOwner != catalog.Name {
			events = append(events, CatalogEvent{
				Kind: CatalogMemberConflict, Catalog: catalog.Name, Zone: member.Zone,
				Detail: "zone belongs to catalog " + current.CatalogZone + " and was not handed over",
			})
			continue
		}
		// The owning catalog published a change of ownership naming this
		// catalog, so the handoff the RFC describes is complete.
		previous := current.CatalogZone
		applyCatalogMembership(current, catalog, member)
		current.CatalogChangeOwner = member.ChangeOwner
		events = append(events, CatalogEvent{
			Kind: CatalogMemberHandedOver, Catalog: catalog.Name, Zone: member.Zone,
			Detail: "handed over from " + previous,
		})
	}
	return events
}

// catalogMemberZone builds the secondary zone a catalog membership implies. The
// member inherits the catalog's own transfer settings, because in practice the
// server that publishes a catalog also serves the zones it lists.
func catalogMemberZone(catalog Zone, member CatalogMember) Zone {
	return Zone{
		Name: member.Zone, Type: "secondary", DefaultTTL: catalog.DefaultTTL,
		PrimaryServers: slices.Clone(catalog.PrimaryServers), PrimaryProtocol: catalog.PrimaryProtocol,
		TSIGKey: catalog.TSIGKey, ZoneTransfer: catalog.ZoneTransfer,
		TransferACL: slices.Clone(catalog.TransferACL), Notify: slices.Clone(catalog.Notify),
		CatalogZone: catalog.Name, CatalogGroup: member.Group,
		CatalogMemberID: member.Label, CatalogChangeOwner: member.ChangeOwner,
	}
}

// applyCatalogMembership refreshes the membership metadata and the inherited
// transfer settings of a zone this catalog already owns. Records are left alone
// because they belong to the member's own transfer, not to the catalog.
func applyCatalogMembership(current *Zone, catalog Zone, member CatalogMember) {
	if current.CatalogMemberID != "" && current.CatalogMemberID != member.Label {
		// "When the member node's label value changes ... catalog consumers
		// MUST process this as a member zone removal ... and then immediately
		// process the member as a newly added zone." Dropping the records
		// forces a fresh transfer, which is what a re-add means here.
		current.Records = nil
	}
	current.Type = "secondary"
	current.CatalogZone = catalog.Name
	current.CatalogGroup = member.Group
	current.CatalogMemberID = member.Label
	current.CatalogChangeOwner = member.ChangeOwner
	current.PrimaryServers = slices.Clone(catalog.PrimaryServers)
	current.PrimaryProtocol = catalog.PrimaryProtocol
	current.TSIGKey = catalog.TSIGKey
	current.ZoneTransfer = catalog.ZoneTransfer
	current.TransferACL = slices.Clone(catalog.TransferACL)
	current.Notify = slices.Clone(catalog.Notify)
	if current.DefaultTTL == 0 {
		current.DefaultTTL = catalog.DefaultTTL
	}
}
