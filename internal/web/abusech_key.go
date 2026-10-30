package web

import (
	"context"
	"errors"
	"net/http"
	"strings"

	blockcompiler "github.com/drudge/sable/internal/blocking"
	"github.com/drudge/sable/internal/config"
)

// abuseCHKeyStore keeps the abuse.ch Auth-Key in the encrypted vault.
type abuseCHKeyStore interface {
	Get(context.Context) (string, bool)
	Put(context.Context, string) error
	Clear(context.Context) error
	Lookup(context.Context) string
}

// SetAbuseCHKeyStore attaches the abuse.ch Auth-Key store and lets the
// block-list updater complete keyed URLs with it.
func (server *Server) SetAbuseCHKeyStore(store abuseCHKeyStore) {
	server.abuseCHKeys = store
	server.blockLists.SetAbuseCHKey(store.Lookup)
}

func (server *Server) abuseCHKeyConfigured(ctx context.Context) bool {
	if server.abuseCHKeys == nil {
		return false
	}
	_, found := server.abuseCHKeys.Get(ctx)
	return found
}

// abuseCHKeyChange is what a Settings save does to the stored key.
type abuseCHKeyChange int

const (
	abuseCHKeyKept abuseCHKeyChange = iota
	abuseCHKeySaved
	abuseCHKeyRemoved
)

// saveAbuseCHKey stores or forgets the key before the configuration changes,
// so the URLhaus list it moves can download straight away.
func (server *Server) saveAbuseCHKey(request *http.Request) (abuseCHKeyChange, error) {
	key := strings.TrimSpace(request.FormValue("blocking_abusech_key"))
	remove := request.FormValue("blocking_abusech_key_remove") == "true"
	if key == "" && !remove {
		return abuseCHKeyKept, nil
	}
	if server.abuseCHKeys == nil {
		return abuseCHKeyKept, errors.New("Secret vault is unavailable.")
	}
	if remove {
		return abuseCHKeyRemoved, server.abuseCHKeys.Clear(request.Context())
	}
	return abuseCHKeySaved, server.abuseCHKeys.Put(request.Context(), key)
}

// moveURLhaus points URLhaus at abuse.ch once a key is saved and back to the
// mirror once it is removed. The list keeps its cache path, so it keeps
// blocking with what it has until the new source downloads.
func moveURLhaus(policy *config.Blocking, change abuseCHKeyChange) bool {
	from, to := blockcompiler.URLhausURL, blockcompiler.URLhausKeyedURL
	switch change {
	case abuseCHKeySaved:
	case abuseCHKeyRemoved:
		from, to = to, from
	default:
		return false
	}
	moved := false
	for index := range policy.Lists {
		if policy.Lists[index].URL == from {
			policy.Lists[index].URL = to
			moved = true
		}
	}
	return moved
}
