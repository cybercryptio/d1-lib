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

package encryptonize

import (
	"testing"

	"errors"
	"reflect"

	"github.com/gofrs/uuid"

	"github.com/cybercryptio/d1-lib/data"
	"github.com/cybercryptio/d1-lib/id"
	"github.com/cybercryptio/d1-lib/io"
	"github.com/cybercryptio/d1-lib/key"
)

func newTestEncryptonize(t *testing.T) Encryptonize {
	keyProvider := key.NewStatic(key.Keys{
		KEK: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		AEK: []byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
		TEK: []byte{2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2},
		IEK: []byte{3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3},
	})
	ioProvider := io.NewMem()
	idProvider, err := id.NewStandalone(
		[]byte{4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4},
		[]byte{5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5},
		[]byte{6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6},
		&ioProvider,
	)
	if err != nil {
		t.Fatal(err)
	}

	encryptonize, err := New(&keyProvider, &ioProvider, &idProvider)
	if err != nil {
		t.Fatal(err)
	}
	return encryptonize
}

func newTestUser(t *testing.T, encryptonize *Encryptonize, scopes ...id.Scope) (uuid.UUID, string) {
	idProvider := encryptonize.idProvider.(*id.Standalone)

	id, password, err := idProvider.NewUser(scopes...)
	if err != nil {
		t.Fatal(err)
	}

	token, _, err := idProvider.LoginUser(id, password)
	if err != nil {
		t.Fatal(err)
	}

	return id, token
}

func newTestGroup(t *testing.T, encryptonize *Encryptonize, token string, scope id.Scope, uids ...uuid.UUID) uuid.UUID {
	idProvider := encryptonize.idProvider.(*id.Standalone)

	gid, err := idProvider.NewGroup(token, scope)
	if err != nil {
		t.Fatal(err)
	}

	for _, uid := range uids {
		err := idProvider.AddUserToGroups(token, uid, gid)
		if err != nil {
			t.Fatal(err)
		}
	}

	return gid
}

////////////////////////////////////////////////////////
//                       Encrypt                      //
////////////////////////////////////////////////////////

// It is verified that plain objects with the following properties can be encrypted:
// 1) Plaintext is empty
// 2) Associated data is empty
// 3) Both are empty
// 4) Both are non-empty
func TestPlainObject(t *testing.T) {
	enc := newTestEncryptonize(t)
	_, token := newTestUser(t, &enc, id.ScopeEncrypt)

	type testData struct {
		description string
		data        data.Object
	}

	tests := []testData{
		{
			description: "Plaintext=nil",
			data:        data.Object{Plaintext: nil, AssociatedData: []byte("associated_data")},
		},
		{
			description: "AssociatedData=nil",
			data:        data.Object{Plaintext: []byte("plaintext"), AssociatedData: nil},
		},
		{
			description: "Plaintext=nil AssociatedData=nil",
			data:        data.Object{Plaintext: nil, AssociatedData: nil},
		},
		{
			description: "Plaintext!=nil AssociatedData!=nil",
			data:        data.Object{Plaintext: []byte("plaintext"), AssociatedData: []byte("associated_data")},
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			if _, err := enc.Encrypt(token, &test.data); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestEncryptUnauthenticated(t *testing.T) {
	enc := newTestEncryptonize(t)
	oid, err := enc.Encrypt("bad token", &data.Object{})
	if !errors.Is(err, ErrNotAuthenticated) {
		t.Fatalf("Expected error '%s' but got '%s'", ErrNotAuthenticated, err)
	}
	if oid != uuid.Nil {
		t.Fatal("OID was returned from failed call")
	}
}

// Test that a user without the Encrypt scope cannot encrypt.
func TestEncryptWrongAPIScope(t *testing.T) {
	enc := newTestEncryptonize(t)
	scope := id.ScopeAll ^ id.ScopeEncrypt // All scopes except Encrypt
	_, token := newTestUser(t, &enc, scope)
	oid, err := enc.Encrypt(token, &data.Object{})
	if !errors.Is(err, ErrNotAuthorized) {
		t.Fatalf("Expected error '%s' but got '%s'", ErrNotAuthorized, err)
	}
	if oid != uuid.Nil {
		t.Fatal("OID was returned from failed call")
	}
}

////////////////////////////////////////////////////////
//                       Decrypt                      //
////////////////////////////////////////////////////////

// It is verified that an object is correctly encrypted and decrypted.
func TestDecrypt(t *testing.T) {
	enc := newTestEncryptonize(t)
	_, token := newTestUser(t, &enc, id.ScopeEncrypt, id.ScopeDecrypt)

	plainObject := data.Object{
		Plaintext:      []byte("plaintext"),
		AssociatedData: []byte("associated_data"),
	}

	id, err := enc.Encrypt(token, &plainObject)
	if err != nil {
		t.Fatal(err)
	}

	decrypted, err := enc.Decrypt(token, id)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(plainObject, decrypted) {
		t.Fatal("Decrypted object not equal to original")
	}
}

func TestDecryptUnauthenticated(t *testing.T) {
	enc := newTestEncryptonize(t)
	object, err := enc.Decrypt("bad token", uuid.Must(uuid.NewV4()))
	if !errors.Is(err, ErrNotAuthenticated) {
		t.Fatalf("Expected error '%s' but got '%s'", ErrNotAuthenticated, err)
	}
	if !reflect.DeepEqual(object, data.Object{}) {
		t.Fatal("Data was returned from failed call")
	}
}

func TestDecryptUnauthorizedUser(t *testing.T) {
	enc := newTestEncryptonize(t)
	_, token1 := newTestUser(t, &enc, id.ScopeEncrypt)
	_, token2 := newTestUser(t, &enc, id.ScopeDecrypt)

	plainObject := data.Object{
		Plaintext:      []byte("plaintext"),
		AssociatedData: []byte("associated_data"),
	}

	oid, err := enc.Encrypt(token1, &plainObject)
	if err != nil {
		t.Fatal(err)
	}

	if _, err = enc.Decrypt(token2, oid); err == nil {
		t.Fatal("Unauthorized user was able to decrypt")
	}
}

// Test that a user without the Decrypt scope cannot decrypt.
func TestDecryptWrongAPIScope(t *testing.T) {
	enc := newTestEncryptonize(t)
	scope := id.ScopeAll ^ id.ScopeDecrypt // All scopes except Decrypt
	_, token := newTestUser(t, &enc, scope)
	object, err := enc.Decrypt(token, uuid.Must(uuid.NewV4()))
	if !errors.Is(err, ErrNotAuthorized) {
		t.Fatalf("Expected error '%s' but got '%s'", ErrNotAuthorized, err)
	}
	if !reflect.DeepEqual(object, data.Object{}) {
		t.Fatal("Data was returned from failed call")
	}
}

// Test that a user whose group does not have the Decrypt scope cannot decrypt.
func TestDecryptWrongGroupScope(t *testing.T) {
	enc := newTestEncryptonize(t)
	_, token1 := newTestUser(t, &enc, id.ScopeAll)
	user2, token2 := newTestUser(t, &enc, id.ScopeAll)

	// User2 has all scopes themselves, but get access to the object through a group with a missing
	// scope.
	scope := id.ScopeAll ^ id.ScopeDecrypt // All scopes except Decrypt
	gid := newTestGroup(t, &enc, token1, scope, user2)

	oid, err := enc.Encrypt(token1, &data.Object{})
	if err != nil {
		t.Fatal(err)
	}
	if err := enc.AddGroupsToAccess(token1, oid, gid); err != nil {
		t.Fatal(err)
	}

	object, err := enc.Decrypt(token2, oid)
	if !errors.Is(err, ErrNotAuthorized) {
		t.Fatalf("Expected error '%s' but got '%s'", ErrNotAuthorized, err)
	}
	if !reflect.DeepEqual(object, data.Object{}) {
		t.Fatal("Data was returned from failed call")
	}
}

////////////////////////////////////////////////////////
//                       Update                       //
////////////////////////////////////////////////////////

// It is verified that an object is correctly encrypted, updated, and decrypted.
func TestUpdate(t *testing.T) {
	enc := newTestEncryptonize(t)
	_, token := newTestUser(t, &enc, id.ScopeEncrypt, id.ScopeDecrypt, id.ScopeUpdate)

	plainObject := data.Object{
		Plaintext:      []byte("plaintext"),
		AssociatedData: []byte("associated_data"),
	}

	id, err := enc.Encrypt(token, &plainObject)
	if err != nil {
		t.Fatal(err)
	}

	plainObjectUpdated := data.Object{
		Plaintext:      []byte("plaintext_updated"),
		AssociatedData: []byte("associated_data_updated"),
	}

	err = enc.Update(token, id, &plainObjectUpdated)
	if err != nil {
		t.Fatal(err)
	}

	decrypted, err := enc.Decrypt(token, id)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(plainObjectUpdated, decrypted) {
		t.Fatal("Updated and decrypted object not equal to updated plain object")
	}
}

func TestUpdateUnauthenticated(t *testing.T) {
	enc := newTestEncryptonize(t)
	err := enc.Update("bad token", uuid.Must(uuid.NewV4()), &data.Object{})
	if !errors.Is(err, ErrNotAuthenticated) {
		t.Fatalf("Expected error '%s' but got '%s'", ErrNotAuthenticated, err)
	}
}

// It is verified that an unauthorized user is not able to update.
func TestUpdateUnauthorizedUser(t *testing.T) {
	enc := newTestEncryptonize(t)
	_, token1 := newTestUser(t, &enc, id.ScopeEncrypt)
	_, token2 := newTestUser(t, &enc, id.ScopeUpdate)

	plainObject := data.Object{
		Plaintext:      []byte("plaintext"),
		AssociatedData: []byte("associated_data"),
	}

	id, err := enc.Encrypt(token1, &plainObject)
	if err != nil {
		t.Fatal(err)
	}

	plainObjectUpdated := data.Object{
		Plaintext:      []byte("plaintext_updated"),
		AssociatedData: []byte("associated_data_updated"),
	}

	err = enc.Update(token2, id, &plainObjectUpdated)
	if err == nil {
		t.Fatal("Unauthorized user able to update")
	}
}

// Test that a user without the Update scope cannot update.
func TestUpdateWrongAPIScope(t *testing.T) {
	enc := newTestEncryptonize(t)
	scope := id.ScopeAll ^ id.ScopeUpdate // All scopes except Update
	_, token := newTestUser(t, &enc, scope)
	err := enc.Update(token, uuid.Must(uuid.NewV4()), &data.Object{})
	if !errors.Is(err, ErrNotAuthorized) {
		t.Fatalf("Expected error '%s' but got '%s'", ErrNotAuthorized, err)
	}
}

// Test that a user whose group does not have the Update scope cannot update.
func TestUpdateWrongGroupScope(t *testing.T) {
	enc := newTestEncryptonize(t)
	_, token1 := newTestUser(t, &enc, id.ScopeAll)
	user2, token2 := newTestUser(t, &enc, id.ScopeAll)

	// User2 has all scopes themselves, but get access to the object through a group with a missing
	// scope.
	scope := id.ScopeAll ^ id.ScopeUpdate // All scopes except Update
	gid := newTestGroup(t, &enc, token1, scope, user2)

	oid, err := enc.Encrypt(token1, &data.Object{})
	if err != nil {
		t.Fatal(err)
	}
	if err := enc.AddGroupsToAccess(token1, oid, gid); err != nil {
		t.Fatal(err)
	}

	err = enc.Update(token2, oid, &data.Object{})
	if !errors.Is(err, ErrNotAuthorized) {
		t.Fatalf("Expected error '%s' but got '%s'", ErrNotAuthorized, err)
	}
}

////////////////////////////////////////////////////////
//                       Delete                       //
////////////////////////////////////////////////////////

// It is verified that an object is correctly encrypted and deleted.
func TestDelete(t *testing.T) {
	enc := newTestEncryptonize(t)
	_, token := newTestUser(t, &enc, id.ScopeEncrypt, id.ScopeDecrypt, id.ScopeDelete)

	plainObject := data.Object{
		Plaintext:      []byte("plaintext"),
		AssociatedData: []byte("associated_data"),
	}

	id, err := enc.Encrypt(token, &plainObject)
	if err != nil {
		t.Fatal(err)
	}

	err = enc.Delete(token, id)
	if err != nil {
		t.Fatal(err)
	}
	object, err := enc.Decrypt(token, id)
	if !errors.Is(err, io.ErrNotFound) {
		t.Fatalf("Expected error '%s' but got '%s'", io.ErrNotFound, err)
	}
	if !reflect.DeepEqual(object, data.Object{}) {
		t.Fatal("Data was returned from failed call")
	}

	sealedAccess, err := enc.ioProvider.Get(id, io.DataTypeSealedAccess)
	if !errors.Is(err, io.ErrNotFound) {
		t.Fatalf("Expected error '%s' but got '%s'", io.ErrNotFound, err)
	}
	if sealedAccess != nil {
		t.Fatal("Data was returned from failed call")
	}

	sealedObject, err := enc.ioProvider.Get(id, io.DataTypeSealedObject)
	if !errors.Is(err, io.ErrNotFound) {
		t.Fatalf("Expected error '%s' but got '%s'", io.ErrNotFound, err)
	}
	if sealedObject != nil {
		t.Fatal("Data was returned from failed call")
	}
}

// It is verified that an unauthenticated user is not able to delete.
func TestDeleteUnauthenticated(t *testing.T) {
	enc := newTestEncryptonize(t)

	err := enc.Delete("bad token", uuid.Must(uuid.NewV4()))
	if !errors.Is(err, ErrNotAuthenticated) {
		t.Fatalf("Expected error '%s' but got '%s'", ErrNotAuthenticated, err)
	}
}

// It is verified that an unauthorized user is not able to delete.
func TestDeleteUnauthorizedUser(t *testing.T) {
	enc := newTestEncryptonize(t)
	_, token1 := newTestUser(t, &enc, id.ScopeEncrypt)
	_, token2 := newTestUser(t, &enc, id.ScopeDecrypt)

	plainObject := data.Object{
		Plaintext:      []byte("plaintext"),
		AssociatedData: []byte("associated_data"),
	}

	oid, err := enc.Encrypt(token1, &plainObject)
	if err != nil {
		t.Fatal(err)
	}

	if err = enc.Delete(token2, oid); err == nil {
		t.Fatal("Unauthorized user was able to delete")
	}
}

// Test that a user without the Delete scope cannot delete.
func TestDeleteWrongAPIScope(t *testing.T) {
	enc := newTestEncryptonize(t)
	scope := id.ScopeAll ^ id.ScopeDelete // All scopes except Decrypt
	_, token := newTestUser(t, &enc, scope)

	err := enc.Delete(token, uuid.Must(uuid.NewV4()))
	if !errors.Is(err, ErrNotAuthorized) {
		t.Fatalf("Expected error '%s' but got '%s'", ErrNotAuthorized, err)
	}
}

// Test that a user whose group does not have the Delete scope cannot delete.
func TestDeleteWrongGroupScope(t *testing.T) {
	enc := newTestEncryptonize(t)
	_, token1 := newTestUser(t, &enc, id.ScopeAll)
	user2, token2 := newTestUser(t, &enc, id.ScopeAll)

	// User2 has all scopes themselves, but get access to the object through a group with a missing
	// scope.
	scope := id.ScopeAll ^ id.ScopeDelete // All scopes except Decrypt
	gid := newTestGroup(t, &enc, token1, scope, user2)

	oid, err := enc.Encrypt(token1, &data.Object{})
	if err != nil {
		t.Fatal(err)
	}
	if err := enc.AddGroupsToAccess(token1, oid, gid); err != nil {
		t.Fatal(err)
	}

	err = enc.Delete(token2, oid)
	if !errors.Is(err, ErrNotAuthorized) {
		t.Fatalf("Expected error '%s' but got '%s'", ErrNotAuthorized, err)
	}
}

// Test that an appropriate error is returned when a user tries to delete an object that does not exist.
func TestDeleteNotFound(t *testing.T) {
	enc := newTestEncryptonize(t)
	_, token := newTestUser(t, &enc, id.ScopeDelete)

	err := enc.Delete(token, uuid.Must(uuid.NewV4()))
	if !errors.Is(err, io.ErrNotFound) {
		t.Fatalf("Expected error '%s' but got '%s'", io.ErrNotFound, err)
	}
}

////////////////////////////////////////////////////////
//            CreateToken/GetTokenContents            //
////////////////////////////////////////////////////////

// It is verified that token contents can be derived correctly.
func TestToken(t *testing.T) {
	enc := newTestEncryptonize(t)

	plaintext := []byte("plaintext")

	token, err := enc.CreateToken(plaintext)
	if err != nil {
		t.Fatal(err)
	}

	contents, err := enc.GetTokenContents(&token)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(plaintext, contents) {
		t.Fatal("Token contents not equal to original")
	}
}

// It is verified that contents cannot be derived from an invalid token.
func TestInvalidToken(t *testing.T) {
	enc := newTestEncryptonize(t)

	plaintext := []byte("plaintext")

	token, err := enc.CreateToken(plaintext)
	if err != nil {
		t.Fatal(err)
	}

	// Make token invalid by changing its first 5 ciphertext bytes.
	copy(token.Ciphertext[:5], make([]byte, 5))

	contents, err := enc.GetTokenContents(&token)
	if err == nil {
		t.Fatal("Contents can be derived from invalid token")
	}
	if contents != nil {
		t.Fatal("GetTokenContents failed, but returned contents anyway")
	}
}

////////////////////////////////////////////////////////
//                   GetAccessGroups                  //
////////////////////////////////////////////////////////

func TestGetAccessGroups(t *testing.T) {
	enc := newTestEncryptonize(t)
	uid, token := newTestUser(t, &enc, id.ScopeEncrypt, id.ScopeModifyAccessGroups, id.ScopeGetAccessGroups)

	numIDs := 5
	ids := make([]uuid.UUID, 0, numIDs)
	for i := 0; i < numIDs; i++ {
		ids = append(ids, uuid.Must(uuid.NewV4()))
	}

	plainObject := data.Object{
		Plaintext:      []byte("plaintext"),
		AssociatedData: []byte("associated_data"),
	}

	oid, err := enc.Encrypt(token, &plainObject)
	if err != nil {
		t.Fatal(err)
	}

	err = enc.AddGroupsToAccess(token, oid, ids...)
	if err != nil {
		t.Fatal(err)
	}

	accessGroups, err := enc.GetAccessGroups(token, oid)
	if err != nil {
		t.Fatal(err)
	}

	if len(accessGroups) != numIDs+1 {
		t.Fatal("Wrong number of IDs returned")
	}
	if _, ok := accessGroups[uid]; !ok {
		t.Fatal("Owner not found in access list")
	}
	for _, id := range ids {
		if _, ok := accessGroups[id]; !ok {
			t.Fatal("ID not found in access list")
		}
	}
}

func TestGetAccessGroupsUnauthenticated(t *testing.T) {
	enc := newTestEncryptonize(t)
	groups, err := enc.GetAccessGroups("bad token", uuid.Must(uuid.NewV4()))
	if !errors.Is(err, ErrNotAuthenticated) {
		t.Fatalf("Expected error '%s' but got '%s'", ErrNotAuthenticated, err)
	}
	if len(groups) != 0 {
		t.Fatal("Groups were returned from failed call")
	}
}

// Scenario:
// 1) Two users are created, user1 and user2.
// 2) user1 encrypts an object.
// 3) It is verified that only user1 who is part of the access object is able to call GetAccessGroups.
func TestGetAccessGroupsUnauthorized(t *testing.T) {
	enc := newTestEncryptonize(t)

	_, token1 := newTestUser(t, &enc, id.ScopeEncrypt)
	_, token2 := newTestUser(t, &enc, id.ScopeGetAccessGroups)

	plainObject := data.Object{
		Plaintext:      []byte("plaintext"),
		AssociatedData: []byte("associated_data"),
	}

	id, err := enc.Encrypt(token1, &plainObject)
	if err != nil {
		t.Fatal(err)
	}

	accessGroups, err := enc.GetAccessGroups(token2, id)
	if err == nil {
		t.Fatal("Unauthorized user able to get group IDs contained in access object")
	}
	if accessGroups != nil {
		t.Fatal("GetAccessGroups failed, but returned data anyway")
	}
}

// Test that a user without the GetAccessGroups scope cannot get the access list.
func TestGetAccessGroupsWrongAPIScope(t *testing.T) {
	enc := newTestEncryptonize(t)
	scope := id.ScopeAll ^ id.ScopeGetAccessGroups // All scopes except GetAccessGroups
	_, token := newTestUser(t, &enc, scope)
	groups, err := enc.GetAccessGroups(token, uuid.Must(uuid.NewV4()))
	if !errors.Is(err, ErrNotAuthorized) {
		t.Fatalf("Expected error '%s' but got '%s'", ErrNotAuthorized, err)
	}
	if len(groups) != 0 {
		t.Fatal("Groups were returned from failed call")
	}
}

// Test that a user whose group does not have the GetAccessGroups scope cannot get the access list.
func TestGetAccessGroupsWrongGroupScope(t *testing.T) {
	enc := newTestEncryptonize(t)
	_, token1 := newTestUser(t, &enc, id.ScopeAll)
	user2, token2 := newTestUser(t, &enc, id.ScopeAll)

	// User2 has all scopes themselves, but get access to the object through a group with a missing
	// scope.
	scope := id.ScopeAll ^ id.ScopeGetAccessGroups // All scopes except GetAccessGroups
	gid := newTestGroup(t, &enc, token1, scope, user2)

	oid, err := enc.Encrypt(token1, &data.Object{})
	if err != nil {
		t.Fatal(err)
	}
	if err := enc.AddGroupsToAccess(token1, oid, gid); err != nil {
		t.Fatal(err)
	}

	groups, err := enc.GetAccessGroups(token2, oid)
	if !errors.Is(err, ErrNotAuthorized) {
		t.Fatalf("Expected error '%s' but got '%s'", ErrNotAuthorized, err)
	}
	if len(groups) != 0 {
		t.Fatal("Groups were returned from failed call")
	}
}

////////////////////////////////////////////////////////
//       AddGroupsToAccess/RemoveGroupsFromAccess     //
////////////////////////////////////////////////////////

// It is verified that a user can encrypt an object and add/remove a group to/from the access object.
func TestAddRemoveGroupsFromAccess(t *testing.T) {
	enc := newTestEncryptonize(t)
	_, token := newTestUser(t, &enc, id.ScopeEncrypt, id.ScopeModifyAccessGroups, id.ScopeGetAccessGroups)
	group := newTestGroup(t, &enc, token, id.ScopeNone)

	plainObject := data.Object{
		Plaintext:      []byte("plaintext"),
		AssociatedData: []byte("associated_data"),
	}

	id, err := enc.Encrypt(token, &plainObject)
	if err != nil {
		t.Fatal(err)
	}

	if err = enc.AddGroupsToAccess(token, id, group); err != nil {
		t.Fatal(err)
	}

	accessGroups, err := enc.GetAccessGroups(token, id)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := accessGroups[group]; !ok {
		t.Fatal("Group not correctly added to access object")
	}

	if err = enc.RemoveGroupsFromAccess(token, id, group); err != nil {
		t.Fatal(err)
	}

	accessGroups, err = enc.GetAccessGroups(token, id)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := accessGroups[group]; ok {
		t.Fatal("Group not correctly removed from access object")
	}
}

func TestAddGroupsToAccessUnauthenticated(t *testing.T) {
	enc := newTestEncryptonize(t)
	err := enc.AddGroupsToAccess("bad token", uuid.Must(uuid.NewV4()), uuid.Must(uuid.NewV4()))
	if !errors.Is(err, ErrNotAuthenticated) {
		t.Fatalf("Expected error '%s' but got '%s'", ErrNotAuthenticated, err)
	}
}

func TestRemoveGroupsFromAccessUnauthenticated(t *testing.T) {
	enc := newTestEncryptonize(t)
	err := enc.RemoveGroupsFromAccess("bad token", uuid.Must(uuid.NewV4()), uuid.Must(uuid.NewV4()))
	if !errors.Is(err, ErrNotAuthenticated) {
		t.Fatalf("Expected error '%s' but got '%s'", ErrNotAuthenticated, err)
	}
}

// Test that a user without the ModifyAccessGroups scope cannot add to the access list.
func TestAddGroupsToAccessWrongAPIScope(t *testing.T) {
	enc := newTestEncryptonize(t)
	scope := id.ScopeAll ^ id.ScopeModifyAccessGroups // All scopes except ModifyAccessGroups
	_, token := newTestUser(t, &enc, scope)
	err := enc.AddGroupsToAccess(token, uuid.Must(uuid.NewV4()), uuid.Must(uuid.NewV4()))
	if !errors.Is(err, ErrNotAuthorized) {
		t.Fatalf("Expected error '%s' but got '%s'", ErrNotAuthorized, err)
	}
}

// Test that a user without the ModifyAccessGroups scope cannot remove from the access list.
func TestRemoveGroupsToAccessWrongAPIScope(t *testing.T) {
	enc := newTestEncryptonize(t)
	scope := id.ScopeAll ^ id.ScopeModifyAccessGroups // All scopes except ModifyAccessGroups
	_, token := newTestUser(t, &enc, scope)
	err := enc.RemoveGroupsFromAccess(token, uuid.Must(uuid.NewV4()), uuid.Must(uuid.NewV4()))
	if !errors.Is(err, ErrNotAuthorized) {
		t.Fatalf("Expected error '%s' but got '%s'", ErrNotAuthorized, err)
	}
}

// Test that a user whose group does not have the AddGroupsToAccess scope cannot add to the access list.
func TestAddGroupsToAccessWrongGroupScope(t *testing.T) {
	enc := newTestEncryptonize(t)
	_, token1 := newTestUser(t, &enc, id.ScopeAll)
	user2, token2 := newTestUser(t, &enc, id.ScopeAll)

	// User2 has all scopes themselves, but get access to the object through a group with a missing
	// scope.
	scope := id.ScopeAll ^ id.ScopeModifyAccessGroups // All scopes except ModifyAccessGroups
	gid := newTestGroup(t, &enc, token1, scope, user2)

	oid, err := enc.Encrypt(token1, &data.Object{})
	if err != nil {
		t.Fatal(err)
	}
	if err := enc.AddGroupsToAccess(token1, oid, gid); err != nil {
		t.Fatal(err)
	}

	err = enc.AddGroupsToAccess(token2, oid, uuid.Must(uuid.NewV4()))
	if !errors.Is(err, ErrNotAuthorized) {
		t.Fatalf("Expected error '%s' but got '%s'", ErrNotAuthorized, err)
	}
}

// Test that a user whose group does not have the RemoveGroupsFromAccess scope cannot remove from the access list.
func TestRemoveGroupsFromAccessWrongGroupScope(t *testing.T) {
	enc := newTestEncryptonize(t)
	_, token1 := newTestUser(t, &enc, id.ScopeAll)
	user2, token2 := newTestUser(t, &enc, id.ScopeAll)

	// User2 has all scopes themselves, but get access to the object through a group with a missing
	// scope.
	scope := id.ScopeAll ^ id.ScopeModifyAccessGroups // All scopes except ModifyAccessGroups
	gid := newTestGroup(t, &enc, token1, scope, user2)

	oid, err := enc.Encrypt(token1, &data.Object{})
	if err != nil {
		t.Fatal(err)
	}
	if err := enc.RemoveGroupsFromAccess(token1, oid, gid); err != nil {
		t.Fatal(err)
	}

	err = enc.RemoveGroupsFromAccess(token2, oid, uuid.Must(uuid.NewV4()))
	if !errors.Is(err, ErrNotAuthorized) {
		t.Fatalf("Expected error '%s' but got '%s'", ErrNotAuthorized, err)
	}
}

// It is verified that a user cannot add/remove groups to/from an access object without being part of the access object.
func TestAddRemoveGroupsFromAccessUnauthorized(t *testing.T) {
	enc := newTestEncryptonize(t)
	_, token1 := newTestUser(t, &enc, id.ScopeEncrypt, id.ScopeModifyAccessGroups)
	_, token2 := newTestUser(t, &enc, id.ScopeModifyAccessGroups)
	group := newTestGroup(t, &enc, token1, id.ScopeNone)

	plainObject := data.Object{
		Plaintext:      []byte("plaintext"),
		AssociatedData: []byte("associated_data"),
	}

	id, err := enc.Encrypt(token1, &plainObject)
	if err != nil {
		t.Fatal(err)
	}

	if err = enc.AddGroupsToAccess(token2, id, group); err == nil {
		t.Fatal("Unauthorized user able to add groups to access")
	}

	if err = enc.AddGroupsToAccess(token1, id, group); err != nil {
		t.Fatal(err)
	}

	if err = enc.RemoveGroupsFromAccess(token2, id, group); err == nil {
		t.Fatal("Unauthorized user able to remove groups from access")
	}
}

// It is verified that a user can add/remove groups to/from an access object without being member of the groups,
// as long as the user is part of the access object.
func TestAddRemoveGroupsFromAccessAuthorized(t *testing.T) {
	enc := newTestEncryptonize(t)
	_, token := newTestUser(t, &enc, id.ScopeEncrypt, id.ScopeModifyAccessGroups, id.ScopeGetAccessGroups)
	group := newTestGroup(t, &enc, token, id.ScopeNone)

	plainObject := data.Object{
		Plaintext:      []byte("plaintext"),
		AssociatedData: []byte("associated_data"),
	}

	id, err := enc.Encrypt(token, &plainObject)
	if err != nil {
		t.Fatal(err)
	}

	if err = enc.AddGroupsToAccess(token, id, group); err != nil {
		t.Fatal(err)
	}

	accessGroups, err := enc.GetAccessGroups(token, id)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := accessGroups[group]; !ok {
		t.Fatal("User not able to add groups to access object. User is not member of all groups, but is part of access object.")
	}

	if err = enc.RemoveGroupsFromAccess(token, id, group); err != nil {
		t.Fatal(err)
	}

	accessGroups, err = enc.GetAccessGroups(token, id)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := accessGroups[group]; ok {
		t.Fatal("User not able to remove groups from access object. User is not member of all groups, but is part of access object.")
	}
}

// user1 creates an object, adds user2, and it is verified that user2 is able to decrypt the object.
func TestSharingObjectPart1(t *testing.T) {
	enc := newTestEncryptonize(t)
	_, token1 := newTestUser(t, &enc, id.ScopeEncrypt, id.ScopeModifyAccessGroups)
	id2, token2 := newTestUser(t, &enc, id.ScopeDecrypt)

	plainObject := data.Object{
		Plaintext:      []byte("plaintext"),
		AssociatedData: []byte("associated_data"),
	}

	oid, err := enc.Encrypt(token1, &plainObject)
	if err != nil {
		t.Fatal(err)
	}

	if _, err = enc.Decrypt(token2, oid); err == nil {
		t.Fatal("Unauthorized user was able to decrypt")
	}

	if err = enc.AddGroupsToAccess(token1, oid, id2); err != nil {
		t.Fatal(err)
	}

	if _, err = enc.Decrypt(token2, oid); err != nil {
		t.Fatal(err)
	}
}

// user1 creates an object and adds user2. User2 removes user1, and it is verified that user1 is not able to decrypt the object.
func TestSharingObjectPart2(t *testing.T) {
	enc := newTestEncryptonize(t)
	id1, token1 := newTestUser(t, &enc, id.ScopeEncrypt, id.ScopeModifyAccessGroups)
	id2, token2 := newTestUser(t, &enc, id.ScopeModifyAccessGroups)

	plainObject := data.Object{
		Plaintext:      []byte("plaintext"),
		AssociatedData: []byte("associated_data"),
	}

	oid, err := enc.Encrypt(token1, &plainObject)
	if err != nil {
		t.Fatal(err)
	}
	if err = enc.AddGroupsToAccess(token1, oid, id2); err != nil {
		t.Fatal(err)
	}
	if err = enc.RemoveGroupsFromAccess(token2, oid, id1); err != nil {
		t.Fatal(err)
	}

	if _, err = enc.Decrypt(token1, oid); err == nil {
		t.Fatal("Unauthorized user able to decrypt")
	}
}

// User1 creates an object, adds user2, user2 adds user3, and it is verified that user3 is able to decrypt the object.
func TestSharingObjectPart3(t *testing.T) {
	enc := newTestEncryptonize(t)
	_, token1 := newTestUser(t, &enc, id.ScopeEncrypt, id.ScopeModifyAccessGroups)
	id2, token2 := newTestUser(t, &enc, id.ScopeModifyAccessGroups)
	id3, token3 := newTestUser(t, &enc, id.ScopeDecrypt)

	plainObject := data.Object{
		Plaintext:      []byte("plaintext"),
		AssociatedData: []byte("associated_data"),
	}

	oid, err := enc.Encrypt(token1, &plainObject)
	if err != nil {
		t.Fatal(err)
	}

	if err = enc.AddGroupsToAccess(token1, oid, id2); err != nil {
		t.Fatal(err)
	}
	if err = enc.AddGroupsToAccess(token2, oid, id3); err != nil {
		t.Fatal(err)
	}

	if _, err = enc.Decrypt(token3, oid); err != nil {
		t.Fatal(err)
	}
}

// Scenario:
// 1) Five users are created.
// 2) user1 creates a group and adds all users to it.
// 3) user1 encrypts an object and adds the group to the access object.
// 4) It is verified that all five users are able to decrypt the object.
func TestSharingObjectPart4(t *testing.T) {
	numUsers := 5

	enc := newTestEncryptonize(t)
	uids := make([]uuid.UUID, 0, numUsers)
	tokens := make([]string, 0, numUsers)

	for i := 0; i < numUsers; i++ {
		uid, token := newTestUser(t, &enc, id.ScopeEncrypt, id.ScopeDecrypt, id.ScopeModifyAccessGroups)
		uids = append(uids, uid)
		tokens = append(tokens, token)
	}

	gid := newTestGroup(t, &enc, tokens[0], id.ScopeDecrypt, uids...)

	plainObject := data.Object{
		Plaintext:      []byte("plaintext"),
		AssociatedData: []byte("associated_data"),
	}

	oid, err := enc.Encrypt(tokens[0], &plainObject)
	if err != nil {
		t.Fatal(err)
	}

	if err = enc.AddGroupsToAccess(tokens[0], oid, gid); err != nil {
		t.Fatal(err)
	}

	for _, token := range tokens {
		if _, err = enc.Decrypt(token, oid); err != nil {
			t.Fatal(err)
		}
	}
}

// Scenario:
// 1) A user is created.
// 2) The user encrypts an object.
// 3) The user removes its own group from the access object.
// 4) It is verified that the user is no longer part of the access object even though he created it.
func TestRemoveAccess(t *testing.T) {
	enc := newTestEncryptonize(t)
	_, token := newTestUser(t, &enc, id.ScopeEncrypt, id.ScopeModifyAccessGroups)
	identity, err := enc.idProvider.GetIdentity(token)
	if err != nil {
		t.Fatal(err)
	}

	plainObject := data.Object{
		Plaintext:      []byte("plaintext"),
		AssociatedData: []byte("associated_data"),
	}

	id, err := enc.Encrypt(token, &plainObject)
	if err != nil {
		t.Fatal(err)
	}

	if err = enc.RemoveGroupsFromAccess(token, id, identity.ID); err != nil {
		t.Fatal(err)
	}

	if err = enc.AuthorizeUser(token, id); err == nil {
		t.Fatal("Unauthorized user is authorized anyway")
	}
}

////////////////////////////////////////////////////////
//                    AuthorizeUser                   //
////////////////////////////////////////////////////////

// Scenario:
// 1) Two users are created, user1 and user2.
// 2) user1 encrypts an object.
// 3) It is verified that only user1 is authorized.
func TestAuthorizeUser(t *testing.T) {
	enc := newTestEncryptonize(t)
	_, token1 := newTestUser(t, &enc, id.ScopeEncrypt, id.ScopeGetAccessGroups)
	_, token2 := newTestUser(t, &enc, id.ScopeGetAccessGroups)

	plainObject := data.Object{
		Plaintext:      []byte("plaintext"),
		AssociatedData: []byte("associated_data"),
	}

	id, err := enc.Encrypt(token1, &plainObject)
	if err != nil {
		t.Fatal(err)
	}

	if err = enc.AuthorizeUser(token1, id); err != nil {
		t.Fatal(err)
	}

	if err = enc.AuthorizeUser(token2, id); err == nil {
		t.Fatal("Unauthorized user is authorized anyway")
	}
}

func TestAuthorizeUserUnauthenticated(t *testing.T) {
	enc := newTestEncryptonize(t)
	err := enc.AuthorizeUser("bad token", uuid.Must(uuid.NewV4()))
	if !errors.Is(err, ErrNotAuthenticated) {
		t.Fatalf("Expected error '%s' but got '%s'", ErrNotAuthenticated, err)
	}
}

// Test that a user without the GetAccessGroups scope cannot check if a user is authorized.
func TestAuthorizeUserWrongAPIScope(t *testing.T) {
	enc := newTestEncryptonize(t)
	scope := id.ScopeAll ^ id.ScopeGetAccessGroups // All scopes except GetAccessGroups
	_, token := newTestUser(t, &enc, scope)
	err := enc.AuthorizeUser(token, uuid.Must(uuid.NewV4()))
	if !errors.Is(err, ErrNotAuthorized) {
		t.Fatalf("Expected error '%s' but got '%s'", ErrNotAuthorized, err)
	}
}

// Test that a user whose group does not have the AuthorizeUser scope cannot check if a user is authorized.
func TestAuthorizeUserWrongGroupScope(t *testing.T) {
	enc := newTestEncryptonize(t)
	_, token1 := newTestUser(t, &enc, id.ScopeAll)
	user2, token2 := newTestUser(t, &enc, id.ScopeAll)

	// User2 has all scopes themselves, but get access to the object through a group with a missing
	// scope.
	scope := id.ScopeAll ^ id.ScopeGetAccessGroups // All scopes except GetAccessGroups
	gid := newTestGroup(t, &enc, token1, scope, user2)

	oid, err := enc.Encrypt(token1, &data.Object{})
	if err != nil {
		t.Fatal(err)
	}
	if err := enc.AddGroupsToAccess(token1, oid, gid); err != nil {
		t.Fatal(err)
	}

	err = enc.AuthorizeUser(token2, oid)
	if !errors.Is(err, ErrNotAuthorized) {
		t.Fatalf("Expected error '%s' but got '%s'", ErrNotAuthorized, err)
	}
}

////////////////////////////////////////////////////////
//                 NewIndex/Add/Search                //
////////////////////////////////////////////////////////

func TestAddToIndex(t *testing.T) {
	enc := newTestEncryptonize(t)

	index := enc.NewIndex()

	keywords := [5]string{"keyword1", "keyword2", "keyword3", "keyword4", "keyword5"}
	ids := [5]string{"id1", "id2", "id3", "id4", "id5"}

	for k := 0; k < len(keywords); k++ {
		for i := 0; i < len(ids); i++ {
			if err := enc.Add(keywords[k], ids[i], &index); err != nil {
				t.Fatal(err)
			}
		}
	}

	if index.Size() != len(keywords)*len(ids) {
		t.Fatal("Keyword/ID pairs not correctly added.")
	}
}
func TestSearchInIndex(t *testing.T) {
	enc := newTestEncryptonize(t)

	index := enc.NewIndex()

	keywords := [5]string{"keyword1", "keyword2", "keyword3", "keyword4", "keyword5"}
	ids := [5]string{"id1", "id2", "id3", "id4", "id5"}

	for k := 0; k < len(keywords); k++ {
		for i := 0; i < len(ids); i++ {
			if err := enc.Add(keywords[k], ids[i], &index); err != nil {
				t.Fatal(err)
			}

			IDs, err := enc.Search(keywords[k], &index)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(IDs[:i], ids[:i]) {
				t.Fatal("Search returned wrong decrypted IDs.")
			}
		}
	}
}
