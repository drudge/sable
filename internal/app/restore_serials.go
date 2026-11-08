package app

import (
	"strings"
	"time"

	"github.com/drudge/sable/internal/zone"
)

// advanceRestoredSerials moves the serial of every restored zone Sable
// issues past the serial of the zone it displaces. A restore brings back
// content, not history: secondaries only transfer a zone whose serial has
// gone up (RFC 1034 §4.3.5), and serving the backup's older serial would
// leave them on the displaced content and reuse serials already served for
// it. Zones the node did not hold keep the backup's serial.
func advanceRestoredSerials(restored, displaced []zone.Zone, now time.Time) {
	served := make(map[string]uint32, len(displaced))
	for _, current := range displaced {
		if serial, ok := zone.Serial(current); ok {
			served[strings.ToLower(current.Name)] = serial
		}
	}
	for index := range restored {
		floor, ok := served[strings.ToLower(restored[index].Name)]
		if ok && zone.OwnsSerial(restored[index]) {
			zone.AdvanceSerialPast(&restored[index], floor, now)
		}
	}
}
