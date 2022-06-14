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

package data

import (
	"testing"

	"reflect"

	"github.com/gofrs/uuid"

	"github.com/cybercryptio/d1-lib/crypto"
)

var accessGroups = []uuid.UUID{
	uuid.Must(uuid.FromString("10000000-0000-0000-0000-000000000000")),
	uuid.Must(uuid.FromString("20000000-0000-0000-0000-000000000000")),
	uuid.Must(uuid.FromString("30000000-0000-0000-0000-000000000000")),
	uuid.Must(uuid.FromString("40000000-0000-0000-0000-000000000000")),
}

func TestAccessGetGroupIDs(t *testing.T) {
	groupID := uuid.Must(uuid.NewV4())
	access := NewAccess(nil)
	access.AddGroups(groupID)

	uuids := access.GetGroups()
	if _, ok := uuids[groupID]; len(uuids) == 0 || !ok {
		t.Error("Expected GetGroups to return a group ID")
	}
}

func TestAccessGetZeroGroupIDs(t *testing.T) {
	access := NewAccess(nil)
	uuids := access.GetGroups()
	if len(uuids) != 0 {
		t.Error("GetGroups should have returned empty array")
	}
}

func TestAccessContainsGroup(t *testing.T) {
	access := NewAccess(nil)
	access.AddGroups(accessGroups...)

	if !access.ContainsGroups(accessGroups...) {
		t.Error("ContainsGroup returned false")
	}

	if access.ContainsGroups(uuid.Must(uuid.NewV4())) {
		t.Error("ContainsGroup returned true")
	}
}

func TestAccessAdd(t *testing.T) {
	access := NewAccess(nil)

	for i := 0; i < 256; i++ {
		g := uuid.Must(uuid.NewV4())
		access.AddGroups(g)
		if !access.ContainsGroups(g) {
			t.Error("AddGroup failed")
		}
	}
}

func TestAccessAddDuplicate(t *testing.T) {
	access := NewAccess(nil)
	g := uuid.Must(uuid.NewV4())
	access.AddGroups(g)
	access.AddGroups(g)
	if !access.ContainsGroups(g) {
		t.Error("calling AddGroup twice with same ID failed")
	}
}

func TestAccessRemoveGroup(t *testing.T) {
	access := NewAccess(nil)
	access.AddGroups(accessGroups...)

	for _, g := range accessGroups {
		access.RemoveGroups(g)
		if access.ContainsGroups(g) {
			t.Error("RemoveGroup failed")
		}
	}
}

func TestAccessSeal(t *testing.T) {
	key := make([]byte, 32)
	cryptor, err := crypto.NewAESCryptor(key)
	if err != nil {
		t.Fatal(err)
	}

	access := NewAccess(nil)
	access.AddGroups(accessGroups...)

	id := uuid.Must(uuid.NewV4())
	sealed, err := access.Seal(id, &cryptor)
	if err != nil {
		t.Fatal(err)
	}
	if sealed.OID != id {
		t.Fatalf("Wrong ID: %s != %s", sealed.OID, id)
	}

	unsealed, err := sealed.Unseal(&cryptor)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(access, unsealed) {
		t.Fatal("Unsealed object not equal to original")
	}
}

func TestAccessVerifyCiphertext(t *testing.T) {
	key := make([]byte, 32)
	cryptor, err := crypto.NewAESCryptor(key)
	if err != nil {
		t.Fatal(err)
	}

	access := NewAccess(nil)
	access.AddGroups(accessGroups...)

	id := uuid.Must(uuid.NewV4())
	sealed, err := access.Seal(id, &cryptor)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := sealed.Unseal(&cryptor); err != nil {
		t.Fatal("Verification failed")
	}
	sealed.Ciphertext[0] = sealed.Ciphertext[0] ^ 1
	if _, err := sealed.Unseal(&cryptor); err == nil {
		t.Fatal("Verification should have failed")
	}
}

func TestAccessVerifyID(t *testing.T) {
	key := make([]byte, 32)
	cryptor, err := crypto.NewAESCryptor(key)
	if err != nil {
		t.Fatal(err)
	}

	access := NewAccess(nil)
	access.AddGroups(accessGroups...)

	id := uuid.Must(uuid.NewV4())
	sealed, err := access.Seal(id, &cryptor)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := sealed.Unseal(&cryptor); err != nil {
		t.Fatal("Verification failed")
	}
	sealed.OID = uuid.Must(uuid.NewV4())
	if _, err := sealed.Unseal(&cryptor); err == nil {
		t.Fatal("Verification should have failed")
	}
}
