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
	"fmt"
	"testing"

	"reflect"

	"github.com/gofrs/uuid"

	"github.com/cybercryptio/d1-lib/v2/crypto"
)

var groupIDs = []string{
	"groupID1",
	"groupID2",
	"groupID3",
	"groupID4",
}

func TestAccessGetGroupIDs(t *testing.T) {
	groupID := "groupID"
	access := NewAccess(nil)
	access.AddGroups(groupID)

	accessGroups := access.GetGroups()
	if _, ok := accessGroups[groupID]; len(accessGroups) == 0 || !ok {
		t.Error("Expected GetGroups to return a group ID")
	}
}

func TestAccessGetZeroGroupIDs(t *testing.T) {
	access := NewAccess(nil)
	accessGroups := access.GetGroups()
	if len(accessGroups) != 0 {
		t.Error("GetGroups should have returned empty array")
	}
}

func TestAccessContainsGroup(t *testing.T) {
	access := NewAccess(nil)
	access.AddGroups(groupIDs...)

	if !access.ContainsGroups(groupIDs...) {
		t.Error("ContainsGroup returned false")
	}

	if access.ContainsGroups("non-existent group ID") {
		t.Error("ContainsGroup returned true")
	}
}

func TestAccessAdd(t *testing.T) {
	access := NewAccess(nil)

	for i := 0; i < 256; i++ {
		g := fmt.Sprintf("groupID%d", i)
		access.AddGroups(g)
		if !access.ContainsGroups(g) {
			t.Error("AddGroup failed")
		}
	}
}

func TestAccessAddDuplicate(t *testing.T) {
	access := NewAccess(nil)
	g := "groupID"
	access.AddGroups(g)
	access.AddGroups(g)
	if !access.ContainsGroups(g) {
		t.Error("calling AddGroup twice with same ID failed")
	}
}

func TestAccessRemoveGroup(t *testing.T) {
	access := NewAccess(nil)
	access.AddGroups(groupIDs...)

	for _, g := range groupIDs {
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
	access.AddGroups(groupIDs...)

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
	access.AddGroups(groupIDs...)

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
	access.AddGroups(groupIDs...)

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
