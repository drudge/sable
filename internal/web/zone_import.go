package web

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/drudge/sable/internal/auth"
	"github.com/drudge/sable/internal/dnsname"
	"github.com/drudge/sable/internal/forwarding"
	zonemodel "github.com/drudge/sable/internal/zone"
)

func (server *Server) exportZone(writer http.ResponseWriter, request *http.Request) {
	name := normalizeZoneName(request.URL.Query().Get("zone"))
	zone := findZone(server.zones.Current().Zones, name)
	if zone == nil {
		http.Error(writer, "zone was not found", http.StatusNotFound)
		return
	}
	if !server.authorizeZoneRequest(request, auth.PermissionZonesExport, *zone) {
		http.Error(writer, "permission denied", http.StatusForbidden)
		return
	}
	writer.Header().Set("Content-Type", "text/dns; charset=utf-8")
	writer.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", zone.Name+".zone"))
	_, _ = fmt.Fprintf(writer, "$ORIGIN %s.\n$TTL %d\n", zone.Name, zone.DefaultTTL)
	for _, record := range zone.Records {
		_, _ = fmt.Fprintf(writer, "%s\t%d\tIN\t%s\t%s\n", record.Name, record.TTL, record.Type, record.Value)
	}
}

func (server *Server) importZone(writer http.ResponseWriter, request *http.Request) {
	zoneText, err := readZoneImportText(writer, request)
	selected := normalizeZoneName(request.FormValue("zone"))
	if err != nil {
		server.logZoneOperation(request, selected, err)
		server.renderZoneMutation(writer, request, http.StatusBadRequest, selected, "", err.Error())
		return
	}
	if err := server.authorizeZoneMutation(request); err != nil {
		server.logZoneOperation(request, selected, err)
		server.renderZoneMutation(writer, request, http.StatusForbidden, selected, "", err.Error())
		return
	}
	editor, ok := server.zones.(zoneEditor)
	if !ok {
		server.logZoneOperation(request, selected, errors.New("zone catalog is read-only"))
		server.renderZoneMutation(writer, request, http.StatusNotImplemented, selected, "", "This configuration source is read-only.")
		return
	}
	overwriteSets := request.FormValue("overwrite") == "true"
	overwriteZone := request.FormValue("overwrite_zone") == "true"
	overwriteSOASerial := request.FormValue("overwrite_soa_serial") == "true"
	var skippedAPPRecords []string
	err = editor.UpdateZones(request.Context(), func(zones *[]zonemodel.Zone) error {
		zone := findZone(*zones, selected)
		if zone == nil {
			return errors.New("zone was not found")
		}
		if !zoneRecordsEditable(zone.Type) {
			return errors.New("records synchronized from a primary server are read-only")
		}
		imported, skipped, err := parseZoneFile(*zone, strings.NewReader(zoneText))
		if err != nil {
			return err
		}
		skippedAPPRecords = skipped
		return mergeImportedRecords(zone, imported, overwriteSets, overwriteZone, overwriteSOASerial, time.Now())
	})
	if err != nil {
		server.logZoneOperation(request, selected, err)
		server.renderZoneMutation(writer, request, http.StatusUnprocessableEntity, selected, "", err.Error())
		return
	}
	server.logZoneOperation(request, selected, nil)
	server.auditZoneMutation(request, selected)
	server.notifyZoneChange(request.Context(), selected)
	message := zoneImportMessage("Records imported into "+selected, skippedAPPRecords)
	server.renderZoneMutation(writer, request, http.StatusOK, selected, message, "")
}

func (server *Server) importNewZone(writer http.ResponseWriter, request *http.Request) {
	zoneText, err := readZoneImportText(writer, request)
	if err != nil {
		server.logZoneOperation(request, "", err)
		server.renderZoneMutation(writer, request, http.StatusBadRequest, "", "", err.Error())
		return
	}
	if err := server.authorizeZoneMutation(request); err != nil {
		server.logZoneOperation(request, "", err)
		server.renderZoneMutation(writer, request, http.StatusForbidden, "", "", err.Error())
		return
	}
	editor, ok := server.zones.(zoneEditor)
	if !ok {
		server.logZoneOperation(request, "", errors.New("zone catalog is read-only"))
		server.renderZoneMutation(writer, request, http.StatusNotImplemented, "", "", "This configuration source is read-only.")
		return
	}
	selected := ""
	var skippedAPPRecords []string
	err = editor.UpdateZones(request.Context(), func(zones *[]zonemodel.Zone) error {
		name, err := importedZoneName(request.FormValue("zone"), zoneText)
		if err != nil {
			return err
		}
		selected = name
		if slices.ContainsFunc(*zones, func(zone zonemodel.Zone) bool { return zone.Name == name }) {
			return errors.New("zone already exists")
		}
		zone := zonemodel.Zone{Name: name, Type: "primary", DefaultTTL: defaultZoneTTL}
		imported, skipped, err := parseZoneFile(zone, strings.NewReader(zoneText))
		if err != nil {
			return err
		}
		skippedAPPRecords = skipped
		for _, record := range imported {
			if record.Name == "@" && record.Type == "SOA" && record.TTL > 0 {
				zone.DefaultTTL = record.TTL
				break
			}
		}
		if err := mergeImportedRecords(&zone, imported, false, true, true, time.Now()); err != nil {
			return err
		}
		*zones = append(*zones, zone)
		return nil
	})
	if err != nil {
		server.logZoneOperation(request, selected, err)
		server.renderZoneMutation(writer, request, http.StatusUnprocessableEntity, selected, "", err.Error())
		return
	}
	server.logZoneOperation(request, selected, nil)
	server.auditZoneMutation(request, selected)
	server.notifyZoneChange(request.Context(), selected)
	message := zoneImportMessage("Zone "+selected+" imported", skippedAPPRecords)
	server.renderZoneMutation(writer, request, http.StatusOK, selected, message, "")
}

func readZoneImportText(writer http.ResponseWriter, request *http.Request) (string, error) {
	if err := request.ParseMultipartForm(maximumZoneImportBytes); err != nil {
		return "", errors.New("the zone file is too large or invalid")
	}
	zoneText := strings.TrimSpace(request.FormValue("zone_text"))
	if zoneText != "" {
		return zoneText, nil
	}
	file, _, err := request.FormFile("file")
	if err != nil {
		return "", errors.New("paste or select a zone file to import")
	}
	defer file.Close()
	contents, err := io.ReadAll(io.LimitReader(file, maximumZoneImportBytes+1))
	if err != nil || len(contents) > maximumZoneImportBytes {
		return "", errors.New("the selected zone file could not be read")
	}
	zoneText = strings.TrimSpace(string(contents))
	if zoneText == "" {
		return "", errors.New("the selected zone file is empty")
	}
	return zoneText, nil
}

func importedZoneName(supplied, contents string) (string, error) {
	candidate := strings.TrimSpace(supplied)
	if candidate == "" {
		for _, line := range strings.Split(contents, "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 2 && strings.EqualFold(fields[0], "$ORIGIN") {
				candidate = fields[1]
				break
			}
		}
	}
	if candidate == "" {
		filtered, _ := filterTechnitiumAPPRecords(contents)
		parser := dns.NewZoneParser(strings.NewReader(filtered), ".", "zone import")
		parser.SetDefaultTTL(defaultZoneTTL)
		parser.SetIncludeAllowed(false)
		for record, ok := parser.Next(); ok; record, ok = parser.Next() {
			if record.Header().Rrtype == dns.TypeSOA {
				candidate = record.Header().Name
				break
			}
		}
	}
	if candidate == "" || candidate == "." || candidate == "@" {
		return "", errors.New("zone name could not be inferred; enter a Zone Name or include $ORIGIN in the file")
	}
	name, err := dnsname.Normalize(strings.TrimSuffix(candidate, "."))
	if err != nil {
		return "", fmt.Errorf("zone name: %w", err)
	}
	return name, nil
}

func zoneImportMessage(base string, skippedAPPRecords []string) string {
	if len(skippedAPPRecords) == 0 {
		return base
	}
	recordLabel := "records"
	if len(skippedAPPRecords) == 1 {
		recordLabel = "record"
	}
	return base + fmt.Sprintf("; skipped %d unsupported Technitium APP %s (%s)", len(skippedAPPRecords), recordLabel, strings.Join(skippedAPPRecords, ", "))
}

func parseZoneFile(zone zonemodel.Zone, reader io.Reader) ([]zonemodel.Record, []string, error) {
	contents, err := io.ReadAll(io.LimitReader(reader, maximumZoneImportBytes+1))
	if err != nil {
		return nil, nil, fmt.Errorf("read zone file: %w", err)
	}
	if len(contents) > maximumZoneImportBytes {
		return nil, nil, errors.New("the zone file is too large")
	}
	filtered, skippedAPPRecords, customForwarders := filterTechnitiumZoneRecords(string(contents), zone)
	filtered = normalizeImportedSOAOwner(filtered, zone.Name)
	parser := dns.NewZoneParser(strings.NewReader(filtered), dns.Fqdn(zone.Name), "zone import")
	parser.SetDefaultTTL(zone.DefaultTTL)
	parser.SetIncludeAllowed(false)
	records := make([]zonemodel.Record, 0, 32)
	for rr, ok := parser.Next(); ok; rr, ok = parser.Next() {
		header := rr.Header()
		if header.Class != dns.ClassINET {
			return nil, nil, fmt.Errorf("record %q must use the IN class", header.Name)
		}
		owner := strings.TrimSuffix(strings.ToLower(header.Name), ".")
		name := "@"
		if owner != zone.Name {
			suffix := "." + zone.Name
			if !strings.HasSuffix(owner, suffix) {
				return nil, nil, fmt.Errorf("record owner %q is outside zone %q", header.Name, zone.Name)
			}
			name = strings.TrimSuffix(owner, suffix)
		}
		value, err := zoneFileRecordValue(rr)
		if err != nil {
			return nil, nil, err
		}
		comment := strings.TrimSpace(strings.TrimPrefix(parser.Comment(), ";"))
		records = append(records, zonemodel.Record{
			Name: name, Type: dns.TypeToString[header.Rrtype], Value: value, TTL: header.Ttl, Comments: comment,
		})
	}
	if err := parser.Err(); err != nil {
		return nil, nil, fmt.Errorf("parse zone file: %w", err)
	}
	for _, record := range customForwarders {
		if _, err := forwarding.ParseRecord(record.Value); err != nil {
			return nil, nil, fmt.Errorf("invalid imported FWD record for %q: %w", record.Name, err)
		}
		records = append(records, record)
	}
	if len(records) == 0 {
		return nil, nil, errors.New("the zone file did not contain any supported records")
	}
	return records, skippedAPPRecords, nil
}

// Some exports omit the terminal dot on an otherwise fully qualified SOA
// owner. Only normalize that apex SOA; other relative owners and record data
// must still resolve against the zone origin.
func normalizeImportedSOAOwner(contents, zoneName string) string {
	lines := strings.SplitAfter(contents, "\n")
	for index, line := range lines {
		recordText, _, _ := strings.Cut(line, ";")
		fields := strings.Fields(recordText)
		if len(fields) < 2 || !strings.EqualFold(fields[0], zoneName) {
			continue
		}
		for field := 1; field < len(fields) && field <= 3; field++ {
			if strings.EqualFold(fields[field], "SOA") && zoneRecordPreamble(fields[1:field]) {
				lines[index] = strings.Replace(line, fields[0], dns.Fqdn(fields[0]), 1)
				break
			}
		}
	}
	return strings.Join(lines, "")
}

func filterTechnitiumAPPRecords(contents string) (string, []string) {
	filtered, skipped, _ := filterTechnitiumZoneRecords(contents, zonemodel.Zone{DefaultTTL: defaultZoneTTL})
	return filtered, skipped
}

func filterTechnitiumZoneRecords(contents string, zone zonemodel.Zone) (string, []string, []zonemodel.Record) {
	var filtered strings.Builder
	skipped := make([]string, 0, 2)
	forwarders := make([]zonemodel.Record, 0, 2)
	for _, line := range strings.SplitAfter(contents, "\n") {
		recordText, comment, _ := strings.Cut(line, ";")
		fields := strings.Fields(recordText)
		customField := -1
		for index := 1; len(fields) > 0 && !strings.HasPrefix(fields[0], "$") && index < len(fields) && index <= 3; index++ {
			if (strings.EqualFold(fields[index], "APP") || strings.EqualFold(fields[index], "FWD")) && zoneRecordPreamble(fields[1:index]) {
				customField = index
				break
			}
		}
		if customField >= 0 {
			if strings.EqualFold(fields[customField], "APP") {
				skipped = append(skipped, strings.TrimSuffix(fields[0], "."))
			} else {
				ttl := zone.DefaultTTL
				for _, field := range fields[1:customField] {
					if parsed, err := strconv.ParseUint(field, 10, 32); err == nil {
						ttl = uint32(parsed)
					}
				}
				forwarders = append(forwarders, zonemodel.Record{
					Name: normalizeZoneRecordOwner(zone.Name, fields[0]), Type: "FWD",
					Value: strings.Join(fields[customField+1:], " "), TTL: ttl,
					Comments: strings.TrimSpace(comment),
				})
			}
			if strings.HasSuffix(line, "\n") {
				filtered.WriteByte('\n')
			}
			continue
		}
		filtered.WriteString(line)
	}
	return filtered.String(), skipped, forwarders
}

func zoneRecordPreamble(fields []string) bool {
	for _, field := range fields {
		if _, found := dns.StringToClass[strings.ToUpper(field)]; found {
			continue
		}
		if _, err := strconv.ParseUint(field, 10, 32); err == nil {
			continue
		}
		return false
	}
	return true
}

func zoneFileRecordValue(record dns.RR) (string, error) {
	parts := strings.SplitN(record.String(), "\t", 5)
	if len(parts) == 5 {
		return strings.TrimSpace(parts[4]), nil
	}
	fields := strings.Fields(record.String())
	if len(fields) < 5 {
		return "", fmt.Errorf("could not render imported %s record", dns.TypeToString[record.Header().Rrtype])
	}
	return strings.Join(fields[4:], " "), nil
}

func mergeImportedRecords(zone *zonemodel.Zone, imported []zonemodel.Record, overwriteSets, overwriteZone, overwriteSOASerial bool, now time.Time) error {
	currentSerial := uint32(0)
	for _, record := range zone.Records {
		if record.Name == "@" && record.Type == "SOA" {
			currentSerial = zoneRecordSOASerial(record.Value)
			break
		}
	}
	importedSOA := -1
	for index, record := range imported {
		if record.Name == "@" && record.Type == "SOA" {
			if importedSOA >= 0 {
				return errors.New("the zone file contains more than one apex SOA record")
			}
			importedSOA = index
		}
	}
	if overwriteZone && importedSOA < 0 {
		return errors.New("overwriting the entire zone requires an apex SOA record")
	}
	if overwriteZone && zone.Type == "forwarder" && !slices.ContainsFunc(imported, func(record zonemodel.Record) bool {
		return record.Name == "@" && record.Type == "FWD"
	}) {
		return errors.New("overwriting a forwarder zone requires an apex FWD record")
	}
	if overwriteZone && zone.Type != "forwarder" && !slices.ContainsFunc(imported, func(record zonemodel.Record) bool {
		return record.Name == "@" && record.Type == "NS"
	}) {
		return errors.New("overwriting the entire zone requires an apex NS record")
	}
	if !overwriteSOASerial && currentSerial != 0 {
		for index := range imported {
			if imported[index].Name == "@" && imported[index].Type == "SOA" {
				imported[index].Value = replaceZoneRecordSOASerial(imported[index].Value, currentSerial)
			}
		}
	}
	merged := append([]zonemodel.Record(nil), zone.Records...)
	if overwriteZone {
		merged = nil
	} else if overwriteSets {
		sets := make(map[string]struct{}, len(imported))
		for _, record := range imported {
			sets[record.Name+"\x00"+record.Type] = struct{}{}
		}
		merged = slices.DeleteFunc(merged, func(record zonemodel.Record) bool {
			_, replace := sets[record.Name+"\x00"+record.Type]
			return replace
		})
	}
	for index, record := range imported {
		if !overwriteZone && !overwriteSets && index == importedSOA && currentSerial != 0 {
			if overwriteSOASerial {
				importedSerial := zoneRecordSOASerial(record.Value)
				for mergedIndex := range merged {
					if merged[mergedIndex].Name == "@" && merged[mergedIndex].Type == "SOA" {
						merged[mergedIndex].Value = replaceZoneRecordSOASerial(merged[mergedIndex].Value, importedSerial)
						break
					}
				}
			}
			continue
		}
		duplicate := slices.ContainsFunc(merged, func(existing zonemodel.Record) bool {
			return existing.Name == record.Name && existing.Type == record.Type && existing.Value == record.Value && existing.TTL == record.TTL
		})
		if !duplicate {
			merged = append(merged, record)
		}
	}
	zone.Records = merged
	// Only the names the import wrote are checked, so a conflict that predates
	// this import never blocks records elsewhere in the zone.
	checked := make(map[string]struct{}, len(imported))
	for _, record := range imported {
		if _, done := checked[record.Name]; done {
			continue
		}
		checked[record.Name] = struct{}{}
		if err := zonemodel.CheckCNAMEExclusivity(*zone, record.Name, now); err != nil {
			return err
		}
	}
	if !overwriteSOASerial || importedSOA < 0 {
		advanceSOASerial(zone, now)
	}
	return nil
}

func zoneRecordSOASerial(value string) uint32 {
	fields := strings.Fields(value)
	if len(fields) != 7 {
		return 0
	}
	serial, _ := strconv.ParseUint(fields[2], 10, 32)
	return uint32(serial)
}

func replaceZoneRecordSOASerial(value string, serial uint32) string {
	fields := strings.Fields(value)
	if len(fields) != 7 {
		return value
	}
	fields[2] = strconv.FormatUint(uint64(serial), 10)
	return strings.Join(fields, " ")
}
