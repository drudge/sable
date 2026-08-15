package zone

import (
	"context"
	"errors"
	"reflect"
	"regexp"
	"testing"
)

type memoryRepository struct{ zones []Zone }

func TestRecordIDIsCompactAndIgnoresPresentationMetadata(t *testing.T) {
	t.Parallel()
	record := Record{Name: "@", Type: "SOA", Value: "ns1.example.test. hostmaster.example.test. 2026081201 900 300 604800 900", TTL: 300}
	id := RecordID(record)
	if len(id) != 16 || !regexp.MustCompile(`^[A-Za-z0-9_-]+$`).MatchString(id) {
		t.Fatalf("RecordID() = %q, want 16 URL-safe characters", id)
	}
	presentationEdit := record
	presentationEdit.TTL = 900
	presentationEdit.Comments = "updated"
	presentationEdit.Disabled = true
	if got := RecordID(presentationEdit); got != id {
		t.Fatalf("presentation metadata changed record ID: got %q want %q", got, id)
	}
	valueEdit := record
	valueEdit.Value = "ns2.example.test. hostmaster.example.test. 2026081202 900 300 604800 900"
	if got := RecordID(valueEdit); got == id {
		t.Fatalf("different record content produced the same ID %q", got)
	}
}

func (repository *memoryRepository) ListZones(context.Context) ([]Zone, error) {
	return Clone(repository.zones), nil
}

func (repository *memoryRepository) ReplaceZones(_ context.Context, _, candidate []Zone) ([]Zone, error) {
	repository.zones = Clone(candidate)
	return Clone(candidate), nil
}

func TestManagerRollsBackPersistenceWhenActivationFails(t *testing.T) {
	t.Parallel()
	initial := validManagerZone()
	repository := &memoryRepository{zones: []Zone{initial}}
	activationErr := errors.New("runtime rejected")
	manager, err := NewManager(
		context.Background(), repository, nil,
		func(zones []Zone) error { return ValidateAll(zones, nil) },
		func(context.Context, []Zone, []Zone) error { return activationErr },
	)
	if err != nil {
		t.Fatal(err)
	}
	err = manager.UpdateZones(context.Background(), func(zones *[]Zone) error {
		(*zones)[0].Records[2].Value = "192.0.2.99"
		return nil
	})
	if !errors.Is(err, activationErr) {
		t.Fatalf("UpdateZones() error = %v, want activation failure", err)
	}
	if !reflect.DeepEqual(repository.zones, manager.Current().Zones) || repository.zones[0].Records[2].Value != "192.0.2.10" {
		t.Fatalf("failed activation escaped rollback: repository=%#v snapshot=%#v", repository.zones, manager.Current().Zones)
	}
}

func validManagerZone() Zone {
	return Zone{
		Name: "example.test", Type: "primary", DefaultTTL: 300, ZoneTransfer: "deny",
		Records: []Record{
			{Name: "@", Type: "SOA", Value: "ns1.example.test. hostmaster.example.test. 1 3600 600 1209600 300", TTL: 300},
			{Name: "@", Type: "NS", Value: "ns1.example.test.", TTL: 300},
			{Name: "www", Type: "A", Value: "192.0.2.10", TTL: 300},
		},
	}
}
