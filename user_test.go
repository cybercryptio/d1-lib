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
	"testing"

	"reflect"

	"github.com/gofrs/uuid"

	"encryptonize/crypto"
)

var userGroups = []uuid.UUID{
	uuid.Must(uuid.FromString("10000000-0000-0000-0000-000000000000")),
	uuid.Must(uuid.FromString("20000000-0000-0000-0000-000000000000")),
	uuid.Must(uuid.FromString("30000000-0000-0000-0000-000000000000")),
	uuid.Must(uuid.FromString("40000000-0000-0000-0000-000000000000")),
}

func TestGetGroupIDs(t *testing.T) {
	groupID := uuid.Must(uuid.NewV4())
	user, _, err := newUser(groupID)
	if err != nil {
		t.Fatal(err)
	}

	uuids := user.getGroups()
	if _, ok := uuids[groupID]; len(uuids) == 0 || !ok {
		t.Error("Expected getGroups to return a group ID")
	}
}

func TestGetZeroGroupIDs(t *testing.T) {
	user, _, err := newUser()
	if err != nil {
		t.Fatal(err)
	}

	uuids := user.getGroups()
	if len(uuids) != 0 {
		t.Error("getGroups should have returned empty array")
	}
}

func TestUserContainsGroup(t *testing.T) {
	user, _, err := newUser(userGroups...)
	if err != nil {
		t.Fatal(err)
	}

	if !user.containsGroups(userGroups...) {
		t.Error("ContainsGroup returned false")
	}

	if user.containsGroups(uuid.Must(uuid.NewV4())) {
		t.Error("ContainsGroup returned true")
	}
}

func TestUserAdd(t *testing.T) {
	user, _, err := newUser()
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 256; i++ {
		g := uuid.Must(uuid.NewV4())
		user.addGroups(g)
		if !user.containsGroups(g) {
			t.Error("AddGroup failed")
		}
	}
}

func TestUserAddDuplicate(t *testing.T) {
	user, _, err := newUser()
	if err != nil {
		t.Fatal(err)
	}
	g := uuid.Must(uuid.NewV4())
	user.addGroups(g)
	user.addGroups(g)
	if !user.containsGroups(g) {
		t.Error("calling AddGroup twice with same ID failed")
	}
}

func TestUserRemoveGroup(t *testing.T) {
	user, _, err := newUser(userGroups...)
	if err != nil {
		t.Fatal(err)
	}

	for _, g := range userGroups {
		user.removeGroups(g)
		if user.containsGroups(g) {
			t.Error("RemoveGroup failed")
		}
	}
}

func TestUserSeal(t *testing.T) {
	key := make([]byte, 32)
	cryptor, err := crypto.NewAESCryptor(key)
	if err != nil {
		t.Fatal(err)
	}

	user, _, err := newUser(userGroups...)
	if err != nil {
		t.Fatal(err)
	}

	id := uuid.Must(uuid.NewV4())
	sealed, err := user.seal(id, &cryptor)
	if err != nil {
		t.Fatal(err)
	}
	if sealed.ID != id {
		t.Fatalf("Wrong ID: %s != %s", sealed.ID, id)
	}

	unsealed, err := sealed.unseal(&cryptor)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(user, unsealed) {
		t.Fatal("Unsealed object not equal to original")
	}
}

func TestUserVerifyCiphertext(t *testing.T) {
	key := make([]byte, 32)
	cryptor, err := crypto.NewAESCryptor(key)
	if err != nil {
		t.Fatal(err)
	}

	user, _, err := newUser(userGroups...)
	if err != nil {
		t.Fatal(err)
	}

	id := uuid.Must(uuid.NewV4())
	sealed, err := user.seal(id, &cryptor)
	if err != nil {
		t.Fatal(err)
	}

	if !sealed.verify(&cryptor) {
		t.Fatal("Verification failed")
	}
	sealed.Ciphertext[0] = sealed.Ciphertext[0] ^ 1
	if sealed.verify(&cryptor) {
		t.Fatal("Verification should have failed")
	}
}

func TestUserVerifyID(t *testing.T) {
	key := make([]byte, 32)
	cryptor, err := crypto.NewAESCryptor(key)
	if err != nil {
		t.Fatal(err)
	}

	user, _, err := newUser(userGroups...)
	if err != nil {
		t.Fatal(err)
	}

	id := uuid.Must(uuid.NewV4())
	sealed, err := user.seal(id, &cryptor)
	if err != nil {
		t.Fatal(err)
	}

	if !sealed.verify(&cryptor) {
		t.Fatal("Verification failed")
	}
	sealed.ID = uuid.Must(uuid.NewV4())
	if sealed.verify(&cryptor) {
		t.Fatal("Verification should have failed")
	}
}
