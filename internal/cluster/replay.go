package cluster

import (
	"encoding/hex"
	"strings"
	"time"
)

// replayGuard remembers each member's heartbeats that are still inside the
// accepted clock window, by signature, so a captured heartbeat can't be sent
// again. It doesn't order heartbeats by SentAt: a member whose clock steps
// back sends heartbeats older than its last one, and those must still count
// (#580). A heartbeat older than the window is refused before this guard is
// asked, so forgetting it then is safe.
type replayGuard map[string]map[string]time.Time

// seen reports whether the member already sent a heartbeat with this
// signature.
func (guard replayGuard) seen(nodeID, signature string) bool {
	_, seen := guard[nodeID][signatureKey(signature)]
	return seen
}

// record remembers a heartbeat the member sent at sentAt and forgets the
// member's heartbeats that have left the clock window.
func (guard replayGuard) record(nodeID, signature string, sentAt, now time.Time) {
	signatures := guard[nodeID]
	if signatures == nil {
		signatures = make(map[string]time.Time)
		guard[nodeID] = signatures
	}
	oldest := now.Add(-heartbeatClockSkew)
	for key, at := range signatures {
		if at.Before(oldest) {
			delete(signatures, key)
		}
	}
	signatures[signatureKey(signature)] = sentAt
}

// signatureKey is the signature's bytes, so two spellings of one signature
// (hex case, surrounding space) are one heartbeat, as validHeartbeatSignature
// treats them.
func signatureKey(signature string) string {
	decoded, err := hex.DecodeString(strings.TrimSpace(signature))
	if err != nil {
		return signature
	}
	return string(decoded)
}
