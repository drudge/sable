package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/drudge/sable/internal/auth"
	zonemodel "github.com/drudge/sable/internal/zone"
)

const conversionSyncTimeout = 30 * time.Second

func (server *Server) reviewZoneConversion(writer http.ResponseWriter, request *http.Request) {
	current := findZone(server.zones.Current().Zones, normalizeZoneName(request.URL.Query().Get("zone")))
	if current == nil {
		writeJSON(writer, http.StatusNotFound, map[string]string{"error": "zone was not found"})
		return
	}
	if !server.authorizeZoneRequest(request, auth.PermissionZonesRead, *current) {
		writeJSON(writer, http.StatusForbidden, map[string]string{"error": "permission denied"})
		return
	}
	if err := zonemodel.CheckPrimaryConversion(*current); err != nil {
		writeJSON(writer, http.StatusUnprocessableEntity, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{
		"zone": current.Name, "confirmation": zonemodel.ConversionFingerprint(*current),
		"source": current.PrimaryServers, "serial": conversionSerial(*current), "record_count": len(current.Records),
	})
}

func conversionSerial(current zonemodel.Zone) uint32 {
	for _, record := range current.Records {
		if record.Name == "@" && record.Type == "SOA" && !record.Disabled {
			return zoneRecordSOASerial(record.Value)
		}
	}
	return 0
}

func (server *Server) convertZoneToPrimary(writer http.ResponseWriter, request *http.Request) {
	selected := ""
	server.updateZones(writer, request, &selected, "Zone converted to Primary; verify answers before moving clients and update writers", func(zones *[]zonemodel.Zone) error {
		selected = normalizeZoneName(request.FormValue("zone"))
		current := findZone(*zones, selected)
		if current == nil {
			return errors.New("zone was not found")
		}
		// Check permissions against the locked identity as well as at request entry.
		if !server.authorizeZoneRequest(request, auth.PermissionZonesSettings, *current) || !server.authorizeZoneRequest(request, auth.PermissionZonesRecords, *current) {
			return auth.ErrForbidden
		}
		if err := zonemodel.CheckPrimaryConversion(*current); err != nil {
			return err
		}
		if request.FormValue("confirmation") != zonemodel.ConversionFingerprint(*current) {
			return errors.New("zone changed since review; reopen Convert to Primary and review the current source, serial, and records")
		}
		if request.FormValue("freeze_confirmed") != "true" {
			return errors.New("confirm that source edits and automatic update writers are frozen")
		}
		reviewedSerial := conversionSerial(*current)
		synchronize := request.FormValue("final_sync")
		if synchronize != "true" && synchronize != "false" {
			return errors.New("choose whether to synchronize before conversion")
		}
		if synchronize == "true" {
			if !server.authorizeZoneRequest(request, auth.PermissionZonesTransfer, *current) {
				return auth.ErrForbidden
			}
			synchronizer, ok := any(server.stats).(zoneSynchronizer)
			if !ok {
				return errors.New("final synchronization is unavailable; the zone remains Secondary")
			}
			ctx, cancel := context.WithTimeout(request.Context(), conversionSyncTimeout)
			defer cancel()
			records, err := synchronizer.FetchZone(ctx, current.Name, current.Type, current.PrimaryServers, current.PrimaryProtocol, current.TSIGKey)
			if err != nil {
				return fmt.Errorf("final synchronization failed; the zone remains Secondary: %w", err)
			}
			transferred := configuredZoneRecords(records)
			// Retain local metadata for records that survive the final snapshot.
			metadata := make(map[string]zonemodel.Record, len(current.Records))
			var soaMetadata zonemodel.Record
			for _, record := range current.Records {
				if record.Name == "@" && record.Type == "SOA" {
					soaMetadata = record
				}
				metadata[zonemodel.RecordID(record)] = record
			}
			for index, record := range transferred {
				if record.Name == "@" && record.Type == "SOA" {
					transferred[index].Comments = soaMetadata.Comments
				}
				if prior, found := metadata[zonemodel.RecordID(record)]; found {
					transferred[index].Comments = prior.Comments
					transferred[index].Source = prior.Source
					transferred[index].Disabled = prior.Disabled
					transferred[index].ExpiresAt = prior.ExpiresAt
				}
			}
			current.Records = transferred
			if int32(conversionSerial(*current)-reviewedSerial) < 0 {
				return errors.New("final synchronization returned an older or ambiguous SOA serial; the zone remains Secondary. Verify the source server before retrying")
			}
		}
		if err := zonemodel.ConvertToPrimary(current, time.Now()); err != nil {
			return err
		}
		if int32(conversionSerial(*current)-reviewedSerial) <= 0 {
			return errors.New("converted SOA serial would not advance beyond the reviewed serial; verify the source serial before retrying")
		}
		return nil
	})
}
