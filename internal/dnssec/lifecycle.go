package dnssec

import "time"

const (
	RoleKSK = "ksk"
	RoleZSK = "zsk"

	StatePublished = "published"
	StateReady     = "ready"
	StateActive    = "active"
	StateRetiring  = "retiring"
)

type Key struct {
	Role        string    `json:"role"`
	State       string    `json:"state"`
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
	State       string    `json:"state"`
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
