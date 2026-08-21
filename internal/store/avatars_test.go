package store

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/drudge/sable/internal/auth"
)

func storedAvatar() auth.Avatar {
	return auth.Avatar{
		ContentType: "image/png",
		Data:        []byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a},
		ETag:        `"first"`,
		SourceURL:   "https://id.example.com/avatar/casey.png",
	}
}

func TestAvatarRoundTripsAndTagsTheProfile(t *testing.T) {
	store := openIdentityStore(t)
	ctx := context.Background()
	admin := seedAdministrator(t, store)
	avatar := storedAvatar()

	if err := store.SaveAvatar(ctx, admin.ID, avatar, time.Now()); err != nil {
		t.Fatalf("save avatar: %v", err)
	}
	read, err := store.Avatar(ctx, admin.ID)
	if err != nil {
		t.Fatalf("read avatar: %v", err)
	}
	if !bytes.Equal(read.Data, avatar.Data) || read.ContentType != avatar.ContentType || read.ETag != avatar.ETag {
		t.Errorf("read back %+v, want %+v", read, avatar)
	}
	if read.SourceURL != avatar.SourceURL {
		t.Errorf("source url = %q, want %q", read.SourceURL, avatar.SourceURL)
	}
}

// The tag lives on the profile so a session lookup can tell whether a picture
// exists without dragging the bytes through every authenticated request.
func TestSavingAnAvatarPublishesItsTagToTheSession(t *testing.T) {
	store := openIdentityStore(t)
	ctx := context.Background()
	now := time.Now()
	created, err := store.CreateFederatedUser(ctx, "casey", "Casey Jones", "casey@example.com",
		[]string{"Administrator"}, "pocket-id", "subject-1", "https://id.example.com", now)
	if err != nil {
		t.Fatalf("provision federated user: %v", err)
	}
	if err := store.SaveAvatar(ctx, created.ID, storedAvatar(), now); err != nil {
		t.Fatalf("save avatar: %v", err)
	}

	linked, err := store.UserByIdentity(ctx, "pocket-id", "subject-1")
	if err != nil {
		t.Fatalf("look up by identity: %v", err)
	}
	if linked.AvatarETag != `"first"` {
		t.Errorf("identity lookup avatar tag = %q, want %q", linked.AvatarETag, `"first"`)
	}

	if err := store.CreateSession(ctx, "hash-1", created.ID, "csrf", now, now.Add(time.Hour)); err != nil {
		t.Fatalf("create session: %v", err)
	}
	session, err := store.SessionByHash(ctx, "hash-1", now)
	if err != nil {
		t.Fatalf("read session: %v", err)
	}
	if session.User.AvatarETag != `"first"` {
		t.Errorf("session avatar tag = %q, want %q", session.User.AvatarETag, `"first"`)
	}
}

func TestSavingAnAvatarReplacesTheOldOne(t *testing.T) {
	store := openIdentityStore(t)
	ctx := context.Background()
	admin := seedAdministrator(t, store)
	if err := store.SaveAvatar(ctx, admin.ID, storedAvatar(), time.Now()); err != nil {
		t.Fatalf("save first avatar: %v", err)
	}
	replacement := storedAvatar()
	replacement.ContentType, replacement.ETag = "image/jpeg", `"second"`
	replacement.Data = []byte{0xff, 0xd8, 0xff}
	if err := store.SaveAvatar(ctx, admin.ID, replacement, time.Now()); err != nil {
		t.Fatalf("save second avatar: %v", err)
	}

	read, err := store.Avatar(ctx, admin.ID)
	if err != nil {
		t.Fatalf("read avatar: %v", err)
	}
	if read.ETag != `"second"` || read.ContentType != "image/jpeg" {
		t.Errorf("read back %+v, want the replacement", read)
	}
}

func TestDeleteAvatarClearsBothTheImageAndTheTag(t *testing.T) {
	store := openIdentityStore(t)
	ctx := context.Background()
	admin := seedAdministrator(t, store)
	if err := store.SaveAvatar(ctx, admin.ID, storedAvatar(), time.Now()); err != nil {
		t.Fatalf("save avatar: %v", err)
	}
	if err := store.DeleteAvatar(ctx, admin.ID, time.Now()); err != nil {
		t.Fatalf("delete avatar: %v", err)
	}

	if _, err := store.Avatar(ctx, admin.ID); !errors.Is(err, auth.ErrNotFound) {
		t.Fatalf("error = %v, want ErrNotFound", err)
	}
	// Removing a picture nobody has is the ordinary case on every sign-in from
	// a provider that never sends one, so it must not be an error.
	if err := store.DeleteAvatar(ctx, admin.ID, time.Now()); err != nil {
		t.Fatalf("second delete: %v", err)
	}
}

func TestAvatarIsMissingUntilOneIsStored(t *testing.T) {
	store := openIdentityStore(t)
	admin := seedAdministrator(t, store)

	if _, err := store.Avatar(context.Background(), admin.ID); !errors.Is(err, auth.ErrNotFound) {
		t.Fatalf("error = %v, want ErrNotFound", err)
	}
}

func TestSaveAvatarRefusesAnEmptyImage(t *testing.T) {
	store := openIdentityStore(t)
	admin := seedAdministrator(t, store)

	if err := store.SaveAvatar(context.Background(), admin.ID, auth.Avatar{ETag: `"x"`}, time.Now()); err == nil {
		t.Fatal("an avatar with no bytes was stored")
	}
}
