package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/drudge/sable/internal/auth"
	dnssecstate "github.com/drudge/sable/internal/dnssec"
	"github.com/drudge/sable/internal/durationfmt"
	"github.com/drudge/sable/internal/web/pages"
	zonemodel "github.com/drudge/sable/internal/zone"
)

type dnssecController interface {
	KeyStatus(context.Context, zonemodel.Zone) (dnssecstate.Status, error)
	RequestRollover(context.Context, zonemodel.Zone, string) error
}

func (server *Server) populateZoneDNSSECView(ctx context.Context, zone zonemodel.Zone, view *pages.ZoneView, display pages.TimeDisplay) {
	if server.dnssec != nil && zone.DNSSEC {
		status, err := server.dnssec.KeyStatus(ctx, zone)
		if err == nil {
			populateManagedKeyView(status, view, display)
			populateZoneSignatureExpiration(zone, view, display)
			return
		}
		server.logger.Warn("load DNSSEC key status", "zone", zone.Name, "error", err)
	}
	populateLegacyDNSSECView(zone, view, display)
}

func populateManagedKeyView(status dnssecstate.Status, view *pages.ZoneView, display pages.TimeDisplay) {
	view.DNSSECNextAction = status.NextAction
	view.DNSSECParentDSKeyTag = status.ParentDSKeyTag
	for _, key := range status.Keys {
		item := pages.DNSSECKeyView{
			Role: strings.ToUpper(key.Role), State: key.State, KeyTag: key.KeyTag,
			DNSKEY: key.DNSKEY, DS: key.DS,
		}
		if !key.ReadyAt.IsZero() {
			item.Timing = "ready " + pages.FormatDateTimeZoned(key.ReadyAt, display)
		} else if !key.RemoveAt.IsZero() {
			item.Timing = "remove after " + pages.FormatDateTimeZoned(key.RemoveAt, display)
		} else if !key.ActivatedAt.IsZero() {
			item.Timing = "active since " + pages.FormatDateTimeZoned(key.ActivatedAt, display)
		}
		view.DNSSECKeys = append(view.DNSSECKeys, item)
		if key.Role == dnssecstate.RoleKSK && key.State == dnssecstate.StateActive {
			view.DNSSECKeyTag, view.DNSSECDNSKEY, view.DNSSECDS = key.KeyTag, key.DNSKEY, key.DS
		}
	}
	view.DNSSEC = len(view.DNSSECKeys) > 0
}

func populateZoneSignatureExpiration(zone zonemodel.Zone, view *pages.ZoneView, display pages.TimeDisplay) {
	var expiration time.Time
	for _, record := range zone.Records {
		rr, err := zoneRecordRR(zone, record)
		if err != nil {
			continue
		}
		if signature, ok := rr.(*dns.RRSIG); ok {
			candidate := time.Unix(int64(signature.Expiration), 0)
			if expiration.IsZero() || candidate.Before(expiration) {
				expiration = candidate
			}
		}
	}
	if !expiration.IsZero() {
		view.DNSSECExpires = pages.FormatDateTimeZoned(expiration, display)
	}
}

func populateLegacyDNSSECView(zone zonemodel.Zone, view *pages.ZoneView, display pages.TimeDisplay) {
	var key *dns.DNSKEY
	var expiration time.Time
	hasSignature := false
	for _, record := range zone.Records {
		rr, err := zoneRecordRR(zone, record)
		if err != nil {
			continue
		}
		switch typed := rr.(type) {
		case *dns.DNSKEY:
			key = typed
		case *dns.RRSIG:
			hasSignature = true
			candidate := time.Unix(int64(typed.Expiration), 0)
			if expiration.IsZero() || candidate.Before(expiration) {
				expiration = candidate
			}
		}
	}
	if key == nil || !hasSignature {
		return
	}
	view.DNSSEC = true
	view.DNSSECKeyTag = key.KeyTag()
	view.DNSSECDNSKEY = key.String()
	if ds := key.ToDS(dns.SHA256); ds != nil {
		view.DNSSECDS = ds.String()
	}
	if !expiration.IsZero() {
		view.DNSSECExpires = pages.FormatDateTimeZoned(expiration, display)
	}
}

func (server *Server) updateZoneDNSSEC(writer http.ResponseWriter, request *http.Request) {
	selected := ""
	server.updateZones(writer, request, &selected, "DNSSEC settings updated", func(zones *[]zonemodel.Zone) error {
		selected = normalizeZoneName(request.FormValue("zone"))
		zone := findZone(*zones, selected)
		if zone == nil {
			return errors.New("zone was not found")
		}
		// Forwarder and stub zones are answered upstream rather than signed, so
		// their DNSSEC dialog carries the validation switch instead. The paired
		// hidden field distinguishes an unchecked switch from a form that never
		// rendered one, so an unrelated submission cannot silently turn
		// validation off.
		if zone.Type == "forwarder" || zone.Type == "stub" {
			if request.Form.Has("dnssec_validation_present") {
				zone.DNSSECValidationDisabled = request.FormValue("dnssec_validation") != "true"
			}
			return nil
		}
		if zone.Type != "primary" {
			return errors.New("only primary zones can be signed by Sable")
		}
		enabled := request.FormValue("enabled") == "true"
		algorithm := strings.ToLower(strings.TrimSpace(request.FormValue("algorithm")))
		denial := strings.ToLower(strings.TrimSpace(request.FormValue("denial")))
		if enabled {
			switch algorithm {
			case "", "ed25519":
				algorithm = "ed25519"
			case "ecdsa-p256-sha256", "ecdsa-p384-sha384":
			default:
				return errors.New("unsupported DNSSEC signing algorithm")
			}
			if denial == "" {
				denial = "nsec"
			}
			if denial != "nsec" && denial != "nsec3" {
				return errors.New("unsupported DNSSEC denial mode")
			}
			if zone.DNSSEC && hasManagedZoneDNSSECRecords(*zone) && algorithm != zone.DNSSECAlgorithm {
				return errors.New("DNSSEC algorithm rollover is not supported; keep the current signing algorithm")
			}
		}
		iterations, err := strconv.ParseUint(strings.TrimSpace(request.FormValue("nsec3_iterations")), 10, 16)
		if request.FormValue("nsec3_iterations") == "" {
			iterations = 0
			err = nil
		}
		if err != nil || iterations != 0 {
			return errors.New("NSEC3 iterations must be 0")
		}
		zone.DNSSEC = enabled
		zone.DNSSECAlgorithm = algorithm
		zone.DNSSECDenial = denial
		zone.NSEC3Iterations = uint16(iterations)
		zone.NSEC3Salt = strings.ToUpper(strings.TrimSpace(request.FormValue("nsec3_salt")))
		if enabled {
			policies := []struct {
				name   string
				target *zonemodel.Duration
			}{
				{"ZSK lifetime", &zone.ZSKLifetime},
				{"KSK lifetime", &zone.KSKLifetime},
				{"key prepublication", &zone.KeyPrepublish},
				{"key retirement", &zone.KeyRetireAfter},
			}
			values := []string{
				request.FormValue("zsk_lifetime"), request.FormValue("ksk_lifetime"),
				request.FormValue("key_prepublish"), request.FormValue("key_retire_after"),
			}
			for index, policy := range policies {
				parsed, parseErr := durationfmt.Parse(values[index])
				if parseErr != nil || parsed <= 0 {
					return fmt.Errorf("%s must be a positive duration such as 30d", policy.name)
				}
				policy.target.Duration = parsed
			}
		}
		return nil
	})
}

func hasManagedZoneDNSSECRecords(zone zonemodel.Zone) bool {
	return slices.ContainsFunc(zone.Records, func(record zonemodel.Record) bool {
		return strings.HasPrefix(record.Comments, "sable:dnssec")
	})
}

func (server *Server) rolloverZoneDNSSECKey(writer http.ResponseWriter, request *http.Request) {
	selected := ""
	server.updateZones(writer, request, &selected, "DNSSEC key rollover started", func(zones *[]zonemodel.Zone) error {
		selected = normalizeZoneName(request.FormValue("zone"))
		zone := findZone(*zones, selected)
		if zone == nil || zone.Type != "primary" || !zone.DNSSEC {
			return errors.New("DNSSEC signing is not enabled for this primary zone")
		}
		if server.dnssec == nil {
			return errors.New("DNSSEC key management is unavailable")
		}
		role := strings.ToLower(strings.TrimSpace(request.FormValue("role")))
		return server.dnssec.RequestRollover(request.Context(), *zone, role)
	})
}

func (server *Server) confirmZoneDNSSECDS(writer http.ResponseWriter, request *http.Request) {
	selected := ""
	server.updateZones(writer, request, &selected, "Parent DS key confirmed", func(zones *[]zonemodel.Zone) error {
		selected = normalizeZoneName(request.FormValue("zone"))
		zone := findZone(*zones, selected)
		if zone == nil || zone.Type != "primary" || !zone.DNSSEC {
			return errors.New("DNSSEC signing is not enabled for this primary zone")
		}
		if server.dnssec == nil {
			return errors.New("DNSSEC key management is unavailable")
		}
		parsed, err := strconv.ParseUint(strings.TrimSpace(request.FormValue("key_tag")), 10, 16)
		if err != nil {
			return errors.New("a valid KSK key tag is required")
		}
		keyTag := uint16(parsed)
		status, err := server.dnssec.KeyStatus(request.Context(), *zone)
		if err != nil {
			return err
		}
		valid := slices.ContainsFunc(status.Keys, func(key dnssecstate.KeyStatus) bool {
			return key.Role == dnssecstate.RoleKSK && key.KeyTag == keyTag && (key.State == dnssecstate.StateActive || key.State == dnssecstate.StateReady)
		})
		if !valid {
			return errors.New("the selected KSK is not active or ready for parent DS publication")
		}
		zone.ParentDSKeyTag = keyTag
		return nil
	})
}

func (server *Server) zoneDS(writer http.ResponseWriter, request *http.Request) {
	name := normalizeZoneName(request.URL.Query().Get("zone"))
	requestedKeyTag, _ := strconv.ParseUint(strings.TrimSpace(request.URL.Query().Get("key_tag")), 10, 16)
	zone := findZone(server.zones.Current().Zones, name)
	if zone == nil {
		http.Error(writer, "zone was not found", http.StatusNotFound)
		return
	}
	if !server.authorizeZoneRequest(request, auth.PermissionZonesExport, *zone) {
		http.Error(writer, "permission denied", http.StatusForbidden)
		return
	}
	if requestedKeyTag == 0 && server.dnssec != nil && zone.DNSSEC {
		if status, err := server.dnssec.KeyStatus(request.Context(), *zone); err == nil {
			for _, key := range status.Keys {
				if key.Role == dnssecstate.RoleKSK && key.State == dnssecstate.StateActive {
					requestedKeyTag = uint64(key.KeyTag)
					break
				}
			}
		}
	}
	for _, record := range zone.Records {
		if record.Type != "DNSKEY" || !strings.HasPrefix(record.Comments, "sable:dnssec") {
			continue
		}
		rr, err := zoneRecordRR(*zone, record)
		if err != nil {
			continue
		}
		key, ok := rr.(*dns.DNSKEY)
		if !ok || key.Flags&dns.SEP == 0 || (requestedKeyTag != 0 && key.KeyTag() != uint16(requestedKeyTag)) {
			continue
		}
		ds := key.ToDS(dns.SHA256)
		if ds == nil {
			break
		}
		writer.Header().Set("Content-Type", "text/dns; charset=utf-8")
		writer.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", zone.Name+".ds"))
		_, _ = fmt.Fprintln(writer, ds.String())
		return
	}
	http.Error(writer, "zone is not signed by Sable", http.StatusNotFound)
}

func (server *Server) zoneDNSSECStatus(writer http.ResponseWriter, request *http.Request) {
	name := normalizeZoneName(request.URL.Query().Get("zone"))
	zone := findZone(server.zones.Current().Zones, name)
	if zone == nil {
		apiError(writer, http.StatusNotFound, "zone was not found")
		return
	}
	if !server.authorizeZoneRequest(request, auth.PermissionZonesRead, *zone) {
		apiError(writer, http.StatusForbidden, "permission denied")
		return
	}
	if !zone.DNSSEC || server.dnssec == nil {
		apiError(writer, http.StatusNotFound, "zone is not managed by Sable DNSSEC")
		return
	}
	status, err := server.dnssec.KeyStatus(request.Context(), *zone)
	if err != nil {
		server.logger.Error("read zone DNSSEC status", "zone", zone.Name, "error", err)
		apiError(writer, http.StatusInternalServerError, "DNSSEC status is unavailable")
		return
	}
	writeJSON(writer, http.StatusOK, status)
}
