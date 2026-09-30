package cluster

import (
	"encoding/json"
	"net/netip"
)

// maximumSharedNetworks bounds what a replica takes from one synchronization.
// A LAN host has a handful.
const maximumSharedNetworks = 64

// AttachedNetworks connects the cluster to the IPv6 networks private
// recursion admits. Own reads this node's, which the lead hands every
// replica, and Lead takes what a replica is handed. A replica in a container
// can't see the LAN it serves, so it admits the lead's networks too.
type AttachedNetworks struct {
	Own  func() []netip.Prefix
	Lead func(node string, prefixes []netip.Prefix)
}

// SetAttachedNetworks has the lead hand its attached networks to every
// replica, and a replica take what it is handed.
func (service *Service) SetAttachedNetworks(networks AttachedNetworks) {
	service.mu.Lock()
	defer service.mu.Unlock()
	service.attachedNetworks = networks
}

// encodeAttachedNetworks writes the lead's networks for a replica. An empty
// list is still sent, so a replica drops networks the lead no longer has.
func encodeAttachedNetworks(prefixes []netip.Prefix) json.RawMessage {
	written := make([]string, 0, len(prefixes))
	for _, prefix := range prefixes {
		written = append(written, prefix.String())
	}
	encoded, err := json.Marshal(written)
	if err != nil {
		return nil
	}
	return encoded
}

// receiveAttachedNetworks hands a replica what the lead shared. A lead too old
// to share any sends nothing, which leaves the replica only its own.
func (service *Service) receiveAttachedNetworks(node string, encoded json.RawMessage) {
	service.mu.RLock()
	lead := service.attachedNetworks.Lead
	service.mu.RUnlock()
	if lead == nil {
		return
	}
	var written []string
	if len(encoded) > 0 {
		if err := json.Unmarshal(encoded, &written); err != nil {
			if service.logger != nil {
				service.logger.Warn("read attached networks from the cluster primary", "error", err)
			}
			return
		}
	}
	prefixes := make([]netip.Prefix, 0, min(len(written), maximumSharedNetworks))
	for _, value := range written {
		if len(prefixes) == maximumSharedNetworks {
			break
		}
		prefix, err := netip.ParsePrefix(value)
		if err != nil || !prefix.Addr().Is6() || !prefix.Addr().IsGlobalUnicast() || prefix.Addr().IsPrivate() || prefix.Bits() < 48 {
			continue
		}
		prefixes = append(prefixes, prefix.Masked())
	}
	lead(node, prefixes)
}
