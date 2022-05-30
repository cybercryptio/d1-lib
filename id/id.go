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

func (i *Identity) GetIDs() map[uuid.UUID]struct{} {
	ids := make(map[uuid.UUID]struct{}, len(i.Groups)+1)
	ids[i.ID] = struct{}{}
	for gid := range i.Groups {
		ids[gid] = struct{}{}
	}
	return ids
}

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
