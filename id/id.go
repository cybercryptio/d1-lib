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
	"github.com/gofrs/uuid"
)

type AccessGroup struct {
	ID     uuid.UUID
	Scopes Scope
}

type Identity struct {
	ID     uuid.UUID
	Scopes Scope
	Groups map[uuid.UUID]AccessGroup
}

// GetIDs returns all IDs related to the identity, i.e. the identity ID and all its group IDs.
func (i *Identity) GetIDs() map[uuid.UUID]struct{} {
	ids := make(map[uuid.UUID]struct{}, len(i.Groups)+1)
	ids[i.ID] = struct{}{}
	for gid := range i.Groups {
		ids[gid] = struct{}{}
	}
	return ids
}

// GetIDScope returns the scopes associated with a given ID (identity or group ID).
func (i *Identity) GetIDScope(id uuid.UUID) Scope {
	if id == i.ID {
		return i.Scopes
	}
	if group, ok := i.Groups[id]; ok {
		return group.Scopes
	}
	return ScopeNone
}

type Provider interface {
	GetIdentity(token string) (Identity, error)
}
