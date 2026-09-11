package zone

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// ConversionFingerprint binds a review to the complete persisted zone, including
// identity and revision, so a same-serial refresh or delete/recreate invalidates it.
func ConversionFingerprint(current Zone) string {
	encoded, _ := json.Marshal(current)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func CheckPrimaryConversion(current Zone) error {
	if current.Type != "secondary" {
		return errors.New("only an independent Secondary zone can be converted to Primary")
	}
	if current.CatalogZone != "" || current.CatalogMemberID != "" || current.CatalogChangeOwner != "" {
		return errors.New("this zone belongs to a Sable catalog; catalog detachment is not supported by conversion. Stage an individually configured Secondary instead")
	}
	if current.DNSSEC {
		return errors.New("signed zones cannot be converted: plan a DNSSEC transition first; transferred public signatures do not include private signing keys")
	}
	hasSOA := false
	for _, record := range current.Records {
		switch strings.ToUpper(record.Type) {
		case "DNSKEY", "RRSIG", "NSEC", "NSEC3", "NSEC3PARAM", "SIG", "KEY", "CDNSKEY", "CDS":
			return errors.New("zone contains DNSSEC signing material; plan a DNSSEC transition before converting. Public records do not provide private signing keys")
		}
		if record.Name == "@" && strings.EqualFold(record.Type, "SOA") && !record.Disabled {
			hasSOA = true
		}
	}
	if !hasSOA {
		return errors.New("synchronize the Secondary before conversion: an active apex SOA is required")
	}
	return nil
}

// ConvertToPrimary must run inside Manager.UpdateZones, after any final transfer.
func ConvertToPrimary(current *Zone, now time.Time) error {
	if err := CheckPrimaryConversion(*current); err != nil {
		return err
	}
	current.Type = "primary"
	current.PrimaryServers = nil
	current.PrimaryProtocol = ""
	// TSIGKey authenticates outgoing transfers as well as upstream requests.
	// Preserve it and all access policy; conversion must not grant new access.
	AdvanceSerial(current, now)
	return nil
}
