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
package encryptonize

import (
	"reflect"
	"testing"

	"github.com/gofrs/uuid"
)

var access = &Access{
	groups: map[uuid.UUID]bool{
		uuid.Must(uuid.FromString("10000000-0000-0000-0000-000000000000")): true,
		uuid.Must(uuid.FromString("20000000-0000-0000-0000-000000000000")): true,
		uuid.Must(uuid.FromString("30000000-0000-0000-0000-000000000000")): true,
		uuid.Must(uuid.FromString("40000000-0000-0000-0000-000000000000")): true,
	},
	wrappedOEK: []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
}

func TestContainsGroupTrue(t *testing.T) {
	for groupID := range access.groups {
		exists := access.containsGroup(groupID)

		if !exists {
			t.Error("ContainsGroup returned false")
		}
	}
}

func TestContainsGroupFalse(t *testing.T) {
	exists := access.containsGroup(uuid.Must(uuid.NewV4()))
	if exists {
		t.Error("ContainsGroup returned true")
	}
}

func TestAdd(t *testing.T) {
	access := &Access{
		groups: map[uuid.UUID]bool{},
	}

	expected := map[uuid.UUID]bool{}
	for i := 0; i < 256; i++ {
		g := uuid.Must(uuid.NewV4())
		access.addGroup(g)

		expected[g] = true

		if !reflect.DeepEqual(expected, access.groups) {
			t.Error("AddGroup failed")
		}
	}
}

func TestAddDuplicate(t *testing.T) {
	expected := access.groups
	access.addGroup(uuid.Must(uuid.FromString("10000000-0000-0000-0000-000000000000")))

	if !reflect.DeepEqual(expected, access.groups) {
		t.Error("AddGroupDuplicate failed")
	}
}

func TestNew(t *testing.T) {
	groupID := uuid.Must(uuid.NewV4())
	woek := []byte{1, 2, 3, 4}

	access := newAccess(groupID, woek)

	expected := Access{
		groups: map[uuid.UUID]bool{
			groupID: true,
		},
		wrappedOEK: woek,
	}

	if !reflect.DeepEqual(expected, access) {
		t.Error("New failed")
	}
}

//nolint: gosec
func TestRemoveGroup(t *testing.T) {
	for groupID := range access.groups {
		access.removeGroup(groupID)
		exists := access.containsGroup(groupID)
		if exists {
			t.Error("RemoveGroup failed")
		}
	}
}
