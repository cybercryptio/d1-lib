// Copyright 2020-2022 CYBERCRYPT
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package common

import (
	"github.com/gofrs/uuid"
)

type AccessObject struct {
	GroupIDs map[uuid.UUID]bool
	Woek     []byte
	Version  uint64
}

type ProtectedAccessObject struct {
	ObjectID     uuid.UUID
	AccessObject []byte
	WrappedKey   []byte
}

// AccessObject instantiates a new Access Object with given groupID and WOEK.
// A new object starts with Version: 0
func NewAccessObject(groupID uuid.UUID, woek []byte) *AccessObject {
	return &AccessObject{
		GroupIDs: map[uuid.UUID]bool{groupID: true},
		Woek:     woek,
		Version:  0,
	}
}

// AddGroup adds a new groupID to an Access Object
func (a *AccessObject) AddGroup(groupID uuid.UUID) {
	a.GroupIDs[groupID] = true
}

// ContainsGroup returns whether a groupID is in the AccessObject
func (a *AccessObject) ContainsGroup(groupID uuid.UUID) bool {
	_, ok := a.GroupIDs[groupID]
	return ok
}

// RemoveGroup removes a groupID from an Access Object
func (a *AccessObject) RemoveGroup(groupID uuid.UUID) {
	delete(a.GroupIDs, groupID)
}

// GetGroups returns a set of groupIDs that may access the Object
func (a *AccessObject) GetGroups() map[uuid.UUID]bool {
	return a.GroupIDs
}

// GetWOEK returns the wrapped object encryption key
func (a *AccessObject) GetWOEK() []byte {
	return a.Woek
}
