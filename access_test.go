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
	"reflect"
	"testing"

	"github.com/gofrs/uuid"
)

var accessObject = &AccessObject{
	Version: 1337,
	GroupIDs: map[uuid.UUID]bool{
		uuid.Must(uuid.FromString("10000000-0000-0000-0000-000000000000")): true,
		uuid.Must(uuid.FromString("20000000-0000-0000-0000-000000000000")): true,
		uuid.Must(uuid.FromString("30000000-0000-0000-0000-000000000000")): true,
		uuid.Must(uuid.FromString("40000000-0000-0000-0000-000000000000")): true,
	},
	Woek: []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
}

func TestContainsGroupTrue(t *testing.T) {
	for groupID := range accessObject.GroupIDs {
		exists := accessObject.ContainsGroup(groupID)

		if !exists {
			t.Error("ContainsGroup returned false")
		}
	}
}

func TestContainsGroupFalse(t *testing.T) {
	exists := accessObject.ContainsGroup(uuid.Must(uuid.NewV4()))
	if exists {
		t.Error("ContainsGroup returned true")
	}
}

func TestAdd(t *testing.T) {
	accessObject := &AccessObject{
		GroupIDs: map[uuid.UUID]bool{},
	}

	expected := map[uuid.UUID]bool{}
	for i := 0; i < 256; i++ {
		g := uuid.Must(uuid.NewV4())
		accessObject.AddGroup(g)

		expected[g] = true

		if !reflect.DeepEqual(expected, accessObject.GroupIDs) {
			t.Error("AddGroup failed")
		}
	}
}

func TestAddDuplicate(t *testing.T) {
	expected := accessObject.GroupIDs
	accessObject.AddGroup(uuid.Must(uuid.FromString("10000000-0000-0000-0000-000000000000")))

	if !reflect.DeepEqual(expected, accessObject.GroupIDs) {
		t.Error("AddGroupDuplicate failed")
	}
}

func TestNew(t *testing.T) {
	groupID := uuid.Must(uuid.NewV4())
	woek := []byte{1, 2, 3, 4}

	accessObject := NewAccessObject(groupID, woek)

	expected := &AccessObject{
		GroupIDs: map[uuid.UUID]bool{
			groupID: true,
		},
		Woek:    woek,
		Version: 0,
	}

	if !reflect.DeepEqual(expected, accessObject) {
		t.Error("New failed")
	}
}

//nolint: gosec
func TestRemoveGroup(t *testing.T) {
	for groupID := range accessObject.GroupIDs {
		accessObject.RemoveGroup(groupID)
		exists := accessObject.ContainsGroup(groupID)
		if exists {
			t.Error("RemoveGroup failed")
		}
	}
}
