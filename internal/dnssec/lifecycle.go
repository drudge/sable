package dnssec

import "time"

const (
	RoleKSK = "ksk"
	RoleZSK = "zsk"
)

// KeyState is where a managed key is in its rollover, following RFC 7583:
// section 3.3.1 (ZSK pre-publish) and section 3.3.2 (double-KSK, gated on the
// parent DS). A key only ever moves forward:
//
//	published -> ready -> active -> retiring -> removed
//
// A ZSK is activated in the same pass that makes it ready, so ready is only
// ever stored for a KSK, which waits there until the parent DS names it. The
// values are stored in the vault, so they must not change.
type KeyState string

const (
	StatePublished KeyState = "published"
	StateReady     KeyState = "ready"
	StateActive    KeyState = "active"
	StateRetiring  KeyState = "retiring"
)

// Valid reports whether state is one of the four stored states.
func (state KeyState) Valid() bool {
	switch state {
	case StatePublished, StateReady, StateActive, StateRetiring:
		return true
	}
	return false
}

// Pending reports whether a key in state is published but not yet active.
func (state KeyState) Pending() bool { return state == StatePublished || state == StateReady }

// CanMoveTo reports whether a key may move from state to next. Retiring keys
// leave by removal, not by a state change.
func (state KeyState) CanMoveTo(next KeyState) bool {
	switch state {
	case StatePublished:
		return next == StateReady
	case StateReady:
		return next == StateActive
	case StateActive:
		return next == StateRetiring
	}
	return false
}

type Key struct {
	Role        string    `json:"role"`
	State       KeyState  `json:"state"`
	DNSKEY      string    `json:"dnskey"`
	PrivateKey  string    `json:"private_key"`
	CreatedAt   time.Time `json:"created_at"`
	PublishedAt time.Time `json:"published_at"`
	ActivatedAt time.Time `json:"activated_at,omitempty"`
	RemoveAt    time.Time `json:"remove_at,omitempty"`
}

type State struct {
	Version   int    `json:"version"`
	Zone      string `json:"zone"`
	Algorithm string `json:"algorithm"`
	Keys      []Key  `json:"keys"`
}

type KeyStatus struct {
	Role        string    `json:"role"`
	State       KeyState  `json:"state"`
	KeyTag      uint16    `json:"key_tag"`
	DNSKEY      string    `json:"dnskey"`
	DS          string    `json:"ds,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	ReadyAt     time.Time `json:"ready_at,omitempty"`
	ActivatedAt time.Time `json:"activated_at,omitempty"`
	RemoveAt    time.Time `json:"remove_at,omitempty"`
}

type Status struct {
	Keys           []KeyStatus `json:"keys"`
	ParentDSKeyTag uint16      `json:"parent_ds_key_tag,omitempty"`
	NextAction     string      `json:"next_action"`
}
