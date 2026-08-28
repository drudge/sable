package zone

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"sync/atomic"
	"time"
)

type Repository interface {
	ListZones(context.Context) ([]Zone, error)
	ReplaceZones(context.Context, []Zone, []Zone) ([]Zone, error)
}

type revisionRepository interface {
	ListZoneRevisions(context.Context, string, int) ([]Revision, error)
	ZoneRevision(context.Context, string, uint64) (Revision, error)
	PreviousZoneRevision(context.Context, string, uint64) (Revision, error)
}

type PrepareFunc func(context.Context, *[]Zone) error
type ValidateFunc func([]Zone) error
type ApplyFunc func(context.Context, []Zone, []Zone) error

// Manager owns the durable zone catalog and publishes immutable snapshots to
// readers. Mutations are serialized, persisted transactionally, and activated
// only after the database commit succeeds.
type Manager struct {
	repository Repository
	prepare    PrepareFunc
	validate   ValidateFunc
	apply      ApplyFunc
	current    atomic.Pointer[Snapshot]
	revision   atomic.Uint64
	mu         sync.Mutex
}

func NewManager(
	ctx context.Context,
	repository Repository,
	prepare PrepareFunc,
	validate ValidateFunc,
	apply ApplyFunc,
) (*Manager, error) {
	zones, err := repository.ListZones(ctx)
	if err != nil {
		return nil, fmt.Errorf("load zones: %w", err)
	}
	NormalizeAll(zones)
	loaded := Clone(zones)
	if prepare != nil {
		if err := prepare(ctx, &zones); err != nil {
			return nil, fmt.Errorf("prepare zones: %w", err)
		}
		NormalizeAll(zones)
	}
	if validate != nil {
		if err := validate(zones); err != nil {
			return nil, fmt.Errorf("validate zones: %w", err)
		}
	}
	if !reflect.DeepEqual(loaded, zones) {
		zones, err = repository.ReplaceZones(ctx, loaded, zones)
		if err != nil {
			return nil, fmt.Errorf("persist prepared zones: %w", err)
		}
	}
	manager := &Manager{repository: repository, prepare: prepare, validate: validate, apply: apply}
	manager.revision.Store(1)
	manager.current.Store(&Snapshot{Zones: Clone(zones), Revision: 1, LoadedAt: time.Now()})
	return manager, nil
}

func (manager *Manager) Current() Snapshot {
	active := manager.current.Load()
	return Snapshot{Zones: Clone(active.Zones), Revision: active.Revision, LoadedAt: active.LoadedAt}
}

// CurrentRef returns the active snapshot without copying its zones. Updates
// replace the snapshot pointer atomically rather than mutating it in place, so a
// caller that only reads the zones (for example serializing them) always sees a
// consistent set and avoids the deep copy Current makes. The returned zones must
// not be mutated.
func (manager *Manager) CurrentRef() Snapshot {
	return *manager.current.Load()
}

func (manager *Manager) ListZoneRevisions(ctx context.Context, name string, limit int) ([]Revision, error) {
	repository, ok := manager.repository.(revisionRepository)
	if !ok {
		return nil, ErrRevisionHistoryUnavailable
	}
	return repository.ListZoneRevisions(ctx, name, limit)
}

func (manager *Manager) ZoneRevision(ctx context.Context, name string, revision uint64) (Revision, error) {
	repository, ok := manager.repository.(revisionRepository)
	if !ok {
		return Revision{}, ErrRevisionHistoryUnavailable
	}
	return repository.ZoneRevision(ctx, name, revision)
}

func (manager *Manager) PreviousZoneRevision(ctx context.Context, name string, revision uint64) (Revision, error) {
	repository, ok := manager.repository.(revisionRepository)
	if !ok {
		return Revision{}, ErrRevisionHistoryUnavailable
	}
	return repository.PreviousZoneRevision(ctx, name, revision)
}

func (manager *Manager) UpdateZones(ctx context.Context, mutate func(*[]Zone) error) error {
	manager.mu.Lock()
	defer manager.mu.Unlock()

	active := manager.current.Load()
	previous := Clone(active.Zones)
	candidate := Clone(active.Zones)
	if err := mutate(&candidate); err != nil {
		return err
	}
	NormalizeAll(candidate)
	if manager.prepare != nil {
		if err := manager.prepare(ctx, &candidate); err != nil {
			return err
		}
		NormalizeAll(candidate)
	}
	if manager.validate != nil {
		if err := manager.validate(candidate); err != nil {
			return err
		}
	}
	if reflect.DeepEqual(previous, candidate) {
		return nil
	}
	persisted, err := manager.repository.ReplaceZones(ctx, previous, candidate)
	if err != nil {
		return err
	}
	if manager.apply != nil {
		if err := manager.apply(ctx, previous, persisted); err != nil {
			_, rollbackErr := manager.repository.ReplaceZones(ctx, persisted, previous)
			return errors.Join(fmt.Errorf("activate zones: %w", err), rollbackErr)
		}
	}
	revision := manager.revision.Add(1)
	manager.current.Store(&Snapshot{Zones: Clone(persisted), Revision: revision, LoadedAt: time.Now()})
	return nil
}
