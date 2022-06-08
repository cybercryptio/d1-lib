package id

import (
	"testing"

	"github.com/gofrs/uuid"
)

func TestGetIDs(t *testing.T) {
	iid := uuid.Must(uuid.NewV4())
	gids := []uuid.UUID{uuid.Must(uuid.NewV4()), uuid.Must(uuid.NewV4()), uuid.Must(uuid.NewV4())}

	identity := &Identity{
		ID:     iid,
		Scopes: ScopeNone,
		Groups: map[uuid.UUID]AccessGroup{
			gids[0]: {gids[0], ScopeNone},
			gids[1]: {gids[1], ScopeNone},
			gids[2]: {gids[2], ScopeNone},
		},
	}

	ids := identity.GetIDs()
	if len(ids) != len(gids)+1 {
		t.Fatalf("Wrong number of IDs, expected %d but got %d", len(gids)+1, len(ids))
	}
	if _, ok := ids[iid]; !ok {
		t.Fatal("Identity ID missing")
	}
	for _, gid := range gids {
		if _, ok := ids[gid]; !ok {
			t.Fatal("Group ID missing")
		}
	}
}

func TestIDScope(t *testing.T) {
	iid := uuid.Must(uuid.NewV4())
	gid := uuid.Must(uuid.NewV4())

	identity := &Identity{
		ID:     iid,
		Scopes: ScopeEncrypt,
		Groups: map[uuid.UUID]AccessGroup{
			gid: {gid, ScopeDecrypt},
		},
	}

	if scope := identity.GetIDScope(iid); scope != ScopeEncrypt {
		t.Fatalf("Expected scope %b but got %b", ScopeEncrypt, scope)
	}
	if scope := identity.GetIDScope(gid); scope != ScopeDecrypt {
		t.Fatalf("Expected scope %b but got %b", ScopeDecrypt, scope)
	}
	if scope := identity.GetIDScope(uuid.Must(uuid.NewV4())); scope != ScopeNone {
		t.Fatalf("Expected scope %b but got %b", ScopeNone, scope)
	}
}
