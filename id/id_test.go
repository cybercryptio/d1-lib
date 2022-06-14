// Copyright (C) 2022 CYBERCRYPT
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

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
