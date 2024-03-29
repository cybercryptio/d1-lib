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

package d1

import (
	"testing"

	"context"
	"errors"
	"fmt"
	"reflect"

	"github.com/gofrs/uuid"

	"github.com/cybercryptio/d1-lib/v2/data"
	"github.com/cybercryptio/d1-lib/v2/id"
	"github.com/cybercryptio/d1-lib/v2/io"
	"github.com/cybercryptio/d1-lib/v2/key"
)

func newTestD1(t *testing.T) D1 {
	ctx := context.Background()
	keyProvider := key.NewStatic(key.Keys{
		KEK: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		AEK: []byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
		TEK: []byte{2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2},
		IEK: []byte{3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3},
	})
	mem := io.NewMem()
	ioProvider := io.NewProxy(&mem)
	idProvider, err := id.NewStandalone(
		id.StandaloneConfig{
			UEK: []byte{4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4},
			GEK: []byte{5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5},
			TEK: []byte{6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6},
		},
		&ioProvider,
	)
	if err != nil {
		t.Fatal(err)
	}

	d1, err := New(ctx, &keyProvider, &ioProvider, &idProvider)
	if err != nil {
		t.Fatal(err)
	}
	return d1
}

func newTestUser(t *testing.T, d1 *D1, scopes ...id.Scope) (string, string) {
	ctx := context.Background()
	idProvider := d1.idProvider.(*id.Standalone)

	id, password, err := idProvider.NewUser(ctx, scopes...)
	if err != nil {
		t.Fatal(err)
	}

	token, _, err := idProvider.LoginUser(ctx, id, password)
	if err != nil {
		t.Fatal(err)
	}

	return id, token
}

func newTestGroup(t *testing.T, d1 *D1, token string, scope id.Scope, uids ...string) string {
	ctx := context.Background()
	idProvider := d1.idProvider.(*id.Standalone)

	gid, err := idProvider.NewGroup(ctx, token, scope)
	if err != nil {
		t.Fatal(err)
	}

	for _, uid := range uids {
		err := idProvider.AddUserToGroups(ctx, token, uid, gid)
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
	ctx := context.Background()
	enc := newTestD1(t)
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
			if _, err := enc.Encrypt(ctx, token, &test.data); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// It is verified that an unauthenticated user is not able to encrypt.
func TestEncryptUnauthenticated(t *testing.T) {
	ctx := context.Background()
	enc := newTestD1(t)
	oid, err := enc.Encrypt(ctx, "bad token", &data.Object{})
	if !errors.Is(err, ErrNotAuthenticated) {
		t.Fatalf("Expected error '%s' but got '%s'", ErrNotAuthenticated, err)
	}
	if oid != uuid.Nil {
		t.Fatal("OID was returned from failed call")
	}
}

// Test that a user without the Encrypt scope cannot encrypt.
func TestEncryptWrongAPIScope(t *testing.T) {
	ctx := context.Background()
	enc := newTestD1(t)
	scope := id.ScopeAll ^ id.ScopeEncrypt // All scopes except Encrypt
	_, token := newTestUser(t, &enc, scope)
	oid, err := enc.Encrypt(ctx, token, &data.Object{})
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
	ctx := context.Background()
	enc := newTestD1(t)
	_, token := newTestUser(t, &enc, id.ScopeEncrypt, id.ScopeDecrypt)

	plainObject := data.Object{
		Plaintext:      []byte("plaintext"),
		AssociatedData: []byte("associated_data"),
	}

	id, err := enc.Encrypt(ctx, token, &plainObject)
	if err != nil {
		t.Fatal(err)
	}

	decrypted, err := enc.Decrypt(ctx, token, id)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(plainObject, decrypted) {
		t.Fatal("Decrypted object not equal to original")
	}
}

// It is verified that an unauthenticated user is not able to decrypt.
func TestDecryptUnauthenticated(t *testing.T) {
	ctx := context.Background()
	enc := newTestD1(t)
	object, err := enc.Decrypt(ctx, "bad token", uuid.Must(uuid.NewV4()))
	if !errors.Is(err, ErrNotAuthenticated) {
		t.Fatalf("Expected error '%s' but got '%s'", ErrNotAuthenticated, err)
	}
	if !reflect.DeepEqual(object, data.Object{}) {
		t.Fatal("Data was returned from failed call")
	}
}

// It is verified that an unauthorized user is not able to decrypt.
func TestDecryptUnauthorizedUser(t *testing.T) {
	ctx := context.Background()
	enc := newTestD1(t)
	_, token1 := newTestUser(t, &enc, id.ScopeEncrypt)
	_, token2 := newTestUser(t, &enc, id.ScopeDecrypt)

	plainObject := data.Object{
		Plaintext:      []byte("plaintext"),
		AssociatedData: []byte("associated_data"),
	}

	oid, err := enc.Encrypt(ctx, token1, &plainObject)
	if err != nil {
		t.Fatal(err)
	}

	if _, err = enc.Decrypt(ctx, token2, oid); err == nil {
		t.Fatal("Unauthorized user was able to decrypt")
	}
}

// Test that a user without the Decrypt scope cannot decrypt.
func TestDecryptWrongAPIScope(t *testing.T) {
	ctx := context.Background()
	enc := newTestD1(t)
	scope := id.ScopeAll ^ id.ScopeDecrypt // All scopes except Decrypt
	_, token := newTestUser(t, &enc, scope)
	object, err := enc.Decrypt(ctx, token, uuid.Must(uuid.NewV4()))
	if !errors.Is(err, ErrNotAuthorized) {
		t.Fatalf("Expected error '%s' but got '%s'", ErrNotAuthorized, err)
	}
	if !reflect.DeepEqual(object, data.Object{}) {
		t.Fatal("Data was returned from failed call")
	}
}

// Test that a user whose group does not have the Decrypt scope cannot decrypt.
func TestDecryptWrongGroupScope(t *testing.T) {
	ctx := context.Background()
	enc := newTestD1(t)
	_, token1 := newTestUser(t, &enc, id.ScopeAll)
	user2, token2 := newTestUser(t, &enc, id.ScopeAll)

	// User2 has all scopes themselves, but get access to the object through a group with a missing
	// scope.
	scope := id.ScopeAll ^ id.ScopeDecrypt // All scopes except Decrypt
	gid := newTestGroup(t, &enc, token1, scope, user2)

	oid, err := enc.Encrypt(ctx, token1, &data.Object{})
	if err != nil {
		t.Fatal(err)
	}
	if err := enc.AddGroupsToAccess(ctx, token1, oid, gid); err != nil {
		t.Fatal(err)
	}

	object, err := enc.Decrypt(ctx, token2, oid)
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
	ctx := context.Background()
	enc := newTestD1(t)
	_, token := newTestUser(t, &enc, id.ScopeEncrypt, id.ScopeDecrypt, id.ScopeUpdate)

	plainObject := data.Object{
		Plaintext:      []byte("plaintext"),
		AssociatedData: []byte("associated_data"),
	}

	id, err := enc.Encrypt(ctx, token, &plainObject)
	if err != nil {
		t.Fatal(err)
	}

	plainObjectUpdated := data.Object{
		Plaintext:      []byte("plaintext_updated"),
		AssociatedData: []byte("associated_data_updated"),
	}

	err = enc.Update(ctx, token, id, &plainObjectUpdated)
	if err != nil {
		t.Fatal(err)
	}

	decrypted, err := enc.Decrypt(ctx, token, id)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(plainObjectUpdated, decrypted) {
		t.Fatal("Updated and decrypted object not equal to updated plain object")
	}
}

// It is verified that an unauthenticated user is not able to update.
func TestUpdateUnauthenticated(t *testing.T) {
	ctx := context.Background()
	enc := newTestD1(t)
	err := enc.Update(ctx, "bad token", uuid.Must(uuid.NewV4()), &data.Object{})
	if !errors.Is(err, ErrNotAuthenticated) {
		t.Fatalf("Expected error '%s' but got '%s'", ErrNotAuthenticated, err)
	}
}

// It is verified that an unauthorized user is not able to update.
func TestUpdateUnauthorizedUser(t *testing.T) {
	ctx := context.Background()
	enc := newTestD1(t)
	_, token1 := newTestUser(t, &enc, id.ScopeEncrypt)
	_, token2 := newTestUser(t, &enc, id.ScopeUpdate)

	plainObject := data.Object{
		Plaintext:      []byte("plaintext"),
		AssociatedData: []byte("associated_data"),
	}

	id, err := enc.Encrypt(ctx, token1, &plainObject)
	if err != nil {
		t.Fatal(err)
	}

	plainObjectUpdated := data.Object{
		Plaintext:      []byte("plaintext_updated"),
		AssociatedData: []byte("associated_data_updated"),
	}

	err = enc.Update(ctx, token2, id, &plainObjectUpdated)
	if err == nil {
		t.Fatal("Unauthorized user able to update")
	}
}

// Test that a user without the Update scope cannot update.
func TestUpdateWrongAPIScope(t *testing.T) {
	ctx := context.Background()
	enc := newTestD1(t)
	scope := id.ScopeAll ^ id.ScopeUpdate // All scopes except Update
	_, token := newTestUser(t, &enc, scope)
	err := enc.Update(ctx, token, uuid.Must(uuid.NewV4()), &data.Object{})
	if !errors.Is(err, ErrNotAuthorized) {
		t.Fatalf("Expected error '%s' but got '%s'", ErrNotAuthorized, err)
	}
}

// Test that a user whose group does not have the Update scope cannot update.
func TestUpdateWrongGroupScope(t *testing.T) {
	ctx := context.Background()
	enc := newTestD1(t)
	_, token1 := newTestUser(t, &enc, id.ScopeAll)
	user2, token2 := newTestUser(t, &enc, id.ScopeAll)

	// User2 has all scopes themselves, but get access to the object through a group with a missing
	// scope.
	scope := id.ScopeAll ^ id.ScopeUpdate // All scopes except Update
	gid := newTestGroup(t, &enc, token1, scope, user2)

	oid, err := enc.Encrypt(ctx, token1, &data.Object{})
	if err != nil {
		t.Fatal(err)
	}
	if err := enc.AddGroupsToAccess(ctx, token1, oid, gid); err != nil {
		t.Fatal(err)
	}

	err = enc.Update(ctx, token2, oid, &data.Object{})
	if !errors.Is(err, ErrNotAuthorized) {
		t.Fatalf("Expected error '%s' but got '%s'", ErrNotAuthorized, err)
	}
}

// Test that an appropriate error is returned when a user tries to update an object that does not exist.
func TestUpdateNotFound(t *testing.T) {
	ctx := context.Background()
	enc := newTestD1(t)
	_, token := newTestUser(t, &enc, id.ScopeUpdate)

	plainObjectUpdated := data.Object{
		Plaintext:      []byte("plaintext_updated"),
		AssociatedData: []byte("associated_data_updated"),
	}

	err := enc.Update(ctx, token, uuid.Must(uuid.NewV4()), &plainObjectUpdated)
	if !errors.Is(err, ErrAccessNotFound) {
		t.Fatalf("Expected error '%s' but got '%s'", ErrAccessNotFound, err)
	}
}

////////////////////////////////////////////////////////
//                       Delete                       //
////////////////////////////////////////////////////////

func checkDataIsDeleted(t *testing.T, ioProvider io.Provider, id []byte, dataTypes ...io.DataType) {
	ctx := context.Background()
	for _, dataType := range dataTypes {
		sealedData, err := ioProvider.Get(ctx, id, dataType)
		if !errors.Is(err, io.ErrNotFound) {
			t.Fatalf("Expected error '%s' but got '%s'", io.ErrNotFound, err)
		}
		if sealedData != nil {
			t.Fatal("Data was returned from failed call")
		}
	}
}

// It is verified that an object is correctly encrypted and deleted.
func TestDelete(t *testing.T) {
	ctx := context.Background()
	enc := newTestD1(t)
	_, token := newTestUser(t, &enc, id.ScopeEncrypt, id.ScopeDecrypt, id.ScopeDelete)

	plainObject := data.Object{
		Plaintext:      []byte("plaintext"),
		AssociatedData: []byte("associated_data"),
	}

	id, err := enc.Encrypt(ctx, token, &plainObject)
	if err != nil {
		t.Fatal(err)
	}

	err = enc.Delete(ctx, token, id)
	if err != nil {
		t.Fatal(err)
	}
	object, err := enc.Decrypt(ctx, token, id)
	if !errors.Is(err, ErrAccessNotFound) {
		t.Fatalf("Expected error '%s' but got '%s'", ErrAccessNotFound, err)
	}
	if !reflect.DeepEqual(object, data.Object{}) {
		t.Fatal("Data was returned from failed call")
	}

	// Double-check with the IO Provider that the sealed data is gone.
	checkDataIsDeleted(t, enc.ioProvider, id.Bytes(),
		io.DataTypeSealedAccess,
		io.DataTypeSealedObject,
	)
}

// It is verified that no errors are returned when deleting a deleted object.
func TestDeleteTwice(t *testing.T) {
	ctx := context.Background()
	enc := newTestD1(t)
	_, token := newTestUser(t, &enc, id.ScopeEncrypt, id.ScopeDecrypt, id.ScopeDelete)

	plainObject := data.Object{
		Plaintext:      []byte("plaintext"),
		AssociatedData: []byte("associated_data"),
	}

	id, err := enc.Encrypt(ctx, token, &plainObject)
	if err != nil {
		t.Fatal(err)
	}

	err = enc.Delete(ctx, token, id)
	if err != nil {
		t.Fatal(err)
	}

	err = enc.Delete(ctx, token, id)
	if err != nil {
		t.Fatal(err)
	}
}

// It is verified that no errors are returned when deleting an object that doesn't exist.
func TestDeleteNonExisting(t *testing.T) {
	ctx := context.Background()
	enc := newTestD1(t)
	_, token := newTestUser(t, &enc, id.ScopeEncrypt, id.ScopeDecrypt, id.ScopeDelete)

	id := uuid.Must(uuid.NewV4())

	err := enc.Delete(ctx, token, id)
	if err != nil {
		t.Fatal(err)
	}
}

// It is verified that data is correctly deleted after retry,
// in cases where an error initially occurs when deleting data of type
// 1) Sealed Access
// 2) Sealed Object
func TestDeleteFailureAndRetry(t *testing.T) {
	ctx := context.Background()
	type testData struct {
		description string
		dataType    io.DataType
		err         error
	}

	tests := []testData{
		{
			description: "DataType=DataTypeSealedAccess",
			dataType:    io.DataTypeSealedAccess,
			err:         errors.New("unable to delete sealed access"),
		},
		{
			description: "DataType=DataTypeSealedObject",
			dataType:    io.DataTypeSealedObject,
			err:         errors.New("unable to delete sealed object"),
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			enc := newTestD1(t)
			ioProxy := enc.ioProvider.(*io.Proxy)

			_, token := newTestUser(t, &enc, id.ScopeEncrypt, id.ScopeDecrypt, id.ScopeDelete)

			plainObject := data.Object{
				Plaintext:      []byte("plaintext"),
				AssociatedData: []byte("associated_data"),
			}

			id, err := enc.Encrypt(ctx, token, &plainObject)
			if err != nil {
				t.Fatal(err)
			}

			// Temporarily inject failures into the delete function.
			delete := ioProxy.DeleteFunc
			ioProxy.DeleteFunc = func(_ context.Context, id []byte, dataType io.DataType) error {
				if dataType == test.dataType {
					return test.err
				}
				return delete(ctx, id, dataType)
			}
			err = enc.Delete(ctx, token, id)
			if !errors.Is(err, test.err) {
				t.Fatalf("Expected error '%s' but got '%s'", test.err, err)
			}

			// Double-check with the IO Provider that the sealed access/object is still there.
			// NOTE: We don't check the other sealed entries, since they may or may not be gone at this point.
			_, err = enc.ioProvider.Get(ctx, id.Bytes(), test.dataType)
			if err != nil {
				t.Fatal(err)
			}

			// Reset the delete function back to the non-failing implementation.
			ioProxy.DeleteFunc = delete
			err = enc.Delete(ctx, token, id)
			if err != nil {
				t.Fatal(err)
			}

			// Double-check with the IO Provider that the sealed data is gone.
			checkDataIsDeleted(t, enc.ioProvider, id.Bytes(),
				io.DataTypeSealedAccess,
				io.DataTypeSealedObject,
			)
		})
	}
}

// It is verified that an unauthenticated user is not able to delete.
func TestDeleteUnauthenticated(t *testing.T) {
	ctx := context.Background()
	enc := newTestD1(t)

	err := enc.Delete(ctx, "bad token", uuid.Must(uuid.NewV4()))
	if !errors.Is(err, ErrNotAuthenticated) {
		t.Fatalf("Expected error '%s' but got '%s'", ErrNotAuthenticated, err)
	}
}

// It is verified that an unauthorized user is not able to delete.
func TestDeleteUnauthorizedUser(t *testing.T) {
	ctx := context.Background()
	enc := newTestD1(t)
	_, token1 := newTestUser(t, &enc, id.ScopeEncrypt)
	_, token2 := newTestUser(t, &enc, id.ScopeDecrypt)

	plainObject := data.Object{
		Plaintext:      []byte("plaintext"),
		AssociatedData: []byte("associated_data"),
	}

	oid, err := enc.Encrypt(ctx, token1, &plainObject)
	if err != nil {
		t.Fatal(err)
	}

	if err = enc.Delete(ctx, token2, oid); err == nil {
		t.Fatal("Unauthorized user was able to delete")
	}
}

// Test that a user without the Delete scope cannot delete.
func TestDeleteWrongAPIScope(t *testing.T) {
	ctx := context.Background()
	enc := newTestD1(t)
	scope := id.ScopeAll ^ id.ScopeDelete // All scopes except Decrypt
	_, token := newTestUser(t, &enc, scope)

	err := enc.Delete(ctx, token, uuid.Must(uuid.NewV4()))
	if !errors.Is(err, ErrNotAuthorized) {
		t.Fatalf("Expected error '%s' but got '%s'", ErrNotAuthorized, err)
	}
}

// Test that a user whose group does not have the Delete scope cannot delete.
func TestDeleteWrongGroupScope(t *testing.T) {
	ctx := context.Background()
	enc := newTestD1(t)
	_, token1 := newTestUser(t, &enc, id.ScopeAll)
	user2, token2 := newTestUser(t, &enc, id.ScopeAll)

	// User2 has all scopes themselves, but get access to the object through a group with a missing
	// scope.
	scope := id.ScopeAll ^ id.ScopeDelete // All scopes except Decrypt
	gid := newTestGroup(t, &enc, token1, scope, user2)

	oid, err := enc.Encrypt(ctx, token1, &data.Object{})
	if err != nil {
		t.Fatal(err)
	}
	if err := enc.AddGroupsToAccess(ctx, token1, oid, gid); err != nil {
		t.Fatal(err)
	}

	err = enc.Delete(ctx, token2, oid)
	if !errors.Is(err, ErrNotAuthorized) {
		t.Fatalf("Expected error '%s' but got '%s'", ErrNotAuthorized, err)
	}
}

////////////////////////////////////////////////////////
//            CreateToken/GetTokenContents            //
////////////////////////////////////////////////////////

// It is verified that token contents can be derived correctly.
func TestToken(t *testing.T) {
	ctx := context.Background()
	enc := newTestD1(t)

	plaintext := []byte("plaintext")

	token, err := enc.CreateToken(ctx, plaintext)
	if err != nil {
		t.Fatal(err)
	}

	contents, err := enc.GetTokenContents(ctx, &token)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(plaintext, contents) {
		t.Fatal("Token contents not equal to original")
	}
}

// It is verified that contents cannot be derived from an invalid token.
func TestInvalidToken(t *testing.T) {
	ctx := context.Background()
	enc := newTestD1(t)

	plaintext := []byte("plaintext")

	token, err := enc.CreateToken(ctx, plaintext)
	if err != nil {
		t.Fatal(err)
	}

	// Make token invalid by changing its first 5 ciphertext bytes.
	copy(token.Ciphertext[:5], make([]byte, 5))

	contents, err := enc.GetTokenContents(ctx, &token)
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
	ctx := context.Background()
	enc := newTestD1(t)
	uid, token := newTestUser(t, &enc, id.ScopeEncrypt, id.ScopeModifyAccessGroups, id.ScopeGetAccessGroups)

	numIDs := 5
	ids := make([]string, 0, numIDs)
	for i := 0; i < numIDs; i++ {
		ids = append(ids, fmt.Sprintf("GroupID%d", i))
	}

	plainObject := data.Object{
		Plaintext:      []byte("plaintext"),
		AssociatedData: []byte("associated_data"),
	}

	oid, err := enc.Encrypt(ctx, token, &plainObject)
	if err != nil {
		t.Fatal(err)
	}

	err = enc.AddGroupsToAccess(ctx, token, oid, ids...)
	if err != nil {
		t.Fatal(err)
	}

	accessGroups, err := enc.GetAccessGroups(ctx, token, oid)
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
	ctx := context.Background()
	enc := newTestD1(t)
	groups, err := enc.GetAccessGroups(ctx, "bad token", uuid.Must(uuid.NewV4()))
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
	ctx := context.Background()
	enc := newTestD1(t)

	_, token1 := newTestUser(t, &enc, id.ScopeEncrypt)
	_, token2 := newTestUser(t, &enc, id.ScopeGetAccessGroups)

	plainObject := data.Object{
		Plaintext:      []byte("plaintext"),
		AssociatedData: []byte("associated_data"),
	}

	id, err := enc.Encrypt(ctx, token1, &plainObject)
	if err != nil {
		t.Fatal(err)
	}

	accessGroups, err := enc.GetAccessGroups(ctx, token2, id)
	if err == nil {
		t.Fatal("Unauthorized user able to get group IDs contained in access object")
	}
	if accessGroups != nil {
		t.Fatal("GetAccessGroups failed, but returned data anyway")
	}
}

// Test that a user without the GetAccessGroups scope cannot get the access list.
func TestGetAccessGroupsWrongAPIScope(t *testing.T) {
	ctx := context.Background()
	enc := newTestD1(t)
	scope := id.ScopeAll ^ id.ScopeGetAccessGroups // All scopes except GetAccessGroups
	_, token := newTestUser(t, &enc, scope)
	groups, err := enc.GetAccessGroups(ctx, token, uuid.Must(uuid.NewV4()))
	if !errors.Is(err, ErrNotAuthorized) {
		t.Fatalf("Expected error '%s' but got '%s'", ErrNotAuthorized, err)
	}
	if len(groups) != 0 {
		t.Fatal("Groups were returned from failed call")
	}
}

// Test that a user whose group does not have the GetAccessGroups scope cannot get the access list.
func TestGetAccessGroupsWrongGroupScope(t *testing.T) {
	ctx := context.Background()
	enc := newTestD1(t)
	_, token1 := newTestUser(t, &enc, id.ScopeAll)
	user2, token2 := newTestUser(t, &enc, id.ScopeAll)

	// User2 has all scopes themselves, but get access to the object through a group with a missing
	// scope.
	scope := id.ScopeAll ^ id.ScopeGetAccessGroups // All scopes except GetAccessGroups
	gid := newTestGroup(t, &enc, token1, scope, user2)

	oid, err := enc.Encrypt(ctx, token1, &data.Object{})
	if err != nil {
		t.Fatal(err)
	}
	if err := enc.AddGroupsToAccess(ctx, token1, oid, gid); err != nil {
		t.Fatal(err)
	}

	groups, err := enc.GetAccessGroups(ctx, token2, oid)
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
	ctx := context.Background()
	enc := newTestD1(t)
	_, token := newTestUser(t, &enc, id.ScopeEncrypt, id.ScopeModifyAccessGroups, id.ScopeGetAccessGroups)
	group := newTestGroup(t, &enc, token, id.ScopeNone)

	plainObject := data.Object{
		Plaintext:      []byte("plaintext"),
		AssociatedData: []byte("associated_data"),
	}

	id, err := enc.Encrypt(ctx, token, &plainObject)
	if err != nil {
		t.Fatal(err)
	}

	if err = enc.AddGroupsToAccess(ctx, token, id, group); err != nil {
		t.Fatal(err)
	}

	accessGroups, err := enc.GetAccessGroups(ctx, token, id)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := accessGroups[group]; !ok {
		t.Fatal("Group not correctly added to access object")
	}

	if err = enc.RemoveGroupsFromAccess(ctx, token, id, group); err != nil {
		t.Fatal(err)
	}

	accessGroups, err = enc.GetAccessGroups(ctx, token, id)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := accessGroups[group]; ok {
		t.Fatal("Group not correctly removed from access object")
	}
}

func TestAddGroupsToAccessUnauthenticated(t *testing.T) {
	ctx := context.Background()
	enc := newTestD1(t)
	err := enc.AddGroupsToAccess(ctx, "bad token", uuid.Must(uuid.NewV4()), "groupID")
	if !errors.Is(err, ErrNotAuthenticated) {
		t.Fatalf("Expected error '%s' but got '%s'", ErrNotAuthenticated, err)
	}
}

func TestRemoveGroupsFromAccessUnauthenticated(t *testing.T) {
	ctx := context.Background()
	enc := newTestD1(t)
	err := enc.RemoveGroupsFromAccess(ctx, "bad token", uuid.Must(uuid.NewV4()), "groupID")
	if !errors.Is(err, ErrNotAuthenticated) {
		t.Fatalf("Expected error '%s' but got '%s'", ErrNotAuthenticated, err)
	}
}

// Test that a user without the ModifyAccessGroups scope cannot add to the access list.
func TestAddGroupsToAccessWrongAPIScope(t *testing.T) {
	ctx := context.Background()
	enc := newTestD1(t)
	scope := id.ScopeAll ^ id.ScopeModifyAccessGroups // All scopes except ModifyAccessGroups
	_, token := newTestUser(t, &enc, scope)
	err := enc.AddGroupsToAccess(ctx, token, uuid.Must(uuid.NewV4()), "groupID")
	if !errors.Is(err, ErrNotAuthorized) {
		t.Fatalf("Expected error '%s' but got '%s'", ErrNotAuthorized, err)
	}
}

// Test that a user without the ModifyAccessGroups scope cannot remove from the access list.
func TestRemoveGroupsToAccessWrongAPIScope(t *testing.T) {
	ctx := context.Background()
	enc := newTestD1(t)
	scope := id.ScopeAll ^ id.ScopeModifyAccessGroups // All scopes except ModifyAccessGroups
	_, token := newTestUser(t, &enc, scope)
	err := enc.RemoveGroupsFromAccess(ctx, token, uuid.Must(uuid.NewV4()), "groupID")
	if !errors.Is(err, ErrNotAuthorized) {
		t.Fatalf("Expected error '%s' but got '%s'", ErrNotAuthorized, err)
	}
}

// Test that a user whose group does not have the AddGroupsToAccess scope cannot add to the access list.
func TestAddGroupsToAccessWrongGroupScope(t *testing.T) {
	ctx := context.Background()
	enc := newTestD1(t)
	_, token1 := newTestUser(t, &enc, id.ScopeAll)
	user2, token2 := newTestUser(t, &enc, id.ScopeAll)

	// User2 has all scopes themselves, but get access to the object through a group with a missing
	// scope.
	scope := id.ScopeAll ^ id.ScopeModifyAccessGroups // All scopes except ModifyAccessGroups
	gid := newTestGroup(t, &enc, token1, scope, user2)

	oid, err := enc.Encrypt(ctx, token1, &data.Object{})
	if err != nil {
		t.Fatal(err)
	}
	if err := enc.AddGroupsToAccess(ctx, token1, oid, gid); err != nil {
		t.Fatal(err)
	}

	err = enc.AddGroupsToAccess(ctx, token2, oid, "groupID")
	if !errors.Is(err, ErrNotAuthorized) {
		t.Fatalf("Expected error '%s' but got '%s'", ErrNotAuthorized, err)
	}
}

// Test that a user whose group does not have the RemoveGroupsFromAccess scope cannot remove from the access list.
func TestRemoveGroupsFromAccessWrongGroupScope(t *testing.T) {
	ctx := context.Background()
	enc := newTestD1(t)
	_, token1 := newTestUser(t, &enc, id.ScopeAll)
	user2, token2 := newTestUser(t, &enc, id.ScopeAll)

	// User2 has all scopes themselves, but get access to the object through a group with a missing
	// scope.
	scope := id.ScopeAll ^ id.ScopeModifyAccessGroups // All scopes except ModifyAccessGroups
	gid := newTestGroup(t, &enc, token1, scope, user2)

	oid, err := enc.Encrypt(ctx, token1, &data.Object{})
	if err != nil {
		t.Fatal(err)
	}
	if err := enc.RemoveGroupsFromAccess(ctx, token1, oid, gid); err != nil {
		t.Fatal(err)
	}

	err = enc.RemoveGroupsFromAccess(ctx, token2, oid, "groupID")
	if !errors.Is(err, ErrNotAuthorized) {
		t.Fatalf("Expected error '%s' but got '%s'", ErrNotAuthorized, err)
	}
}

// It is verified that a user cannot add/remove groups to/from an access object without being part of the access object.
func TestAddRemoveGroupsFromAccessUnauthorized(t *testing.T) {
	ctx := context.Background()
	enc := newTestD1(t)
	_, token1 := newTestUser(t, &enc, id.ScopeEncrypt, id.ScopeModifyAccessGroups)
	_, token2 := newTestUser(t, &enc, id.ScopeModifyAccessGroups)
	group := newTestGroup(t, &enc, token1, id.ScopeNone)

	plainObject := data.Object{
		Plaintext:      []byte("plaintext"),
		AssociatedData: []byte("associated_data"),
	}

	id, err := enc.Encrypt(ctx, token1, &plainObject)
	if err != nil {
		t.Fatal(err)
	}

	if err = enc.AddGroupsToAccess(ctx, token2, id, group); err == nil {
		t.Fatal("Unauthorized user able to add groups to access")
	}

	if err = enc.AddGroupsToAccess(ctx, token1, id, group); err != nil {
		t.Fatal(err)
	}

	if err = enc.RemoveGroupsFromAccess(ctx, token2, id, group); err == nil {
		t.Fatal("Unauthorized user able to remove groups from access")
	}
}

// It is verified that a user can add/remove groups to/from an access object without being member of the groups,
// as long as the user is part of the access object.
func TestAddRemoveGroupsFromAccessAuthorized(t *testing.T) {
	ctx := context.Background()
	enc := newTestD1(t)
	_, token := newTestUser(t, &enc, id.ScopeEncrypt, id.ScopeModifyAccessGroups, id.ScopeGetAccessGroups)
	group := newTestGroup(t, &enc, token, id.ScopeNone)

	plainObject := data.Object{
		Plaintext:      []byte("plaintext"),
		AssociatedData: []byte("associated_data"),
	}

	id, err := enc.Encrypt(ctx, token, &plainObject)
	if err != nil {
		t.Fatal(err)
	}

	if err = enc.AddGroupsToAccess(ctx, token, id, group); err != nil {
		t.Fatal(err)
	}

	accessGroups, err := enc.GetAccessGroups(ctx, token, id)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := accessGroups[group]; !ok {
		t.Fatal("User not able to add groups to access object. User is not member of all groups, but is part of access object.")
	}

	if err = enc.RemoveGroupsFromAccess(ctx, token, id, group); err != nil {
		t.Fatal(err)
	}

	accessGroups, err = enc.GetAccessGroups(ctx, token, id)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := accessGroups[group]; ok {
		t.Fatal("User not able to remove groups from access object. User is not member of all groups, but is part of access object.")
	}
}

// user1 creates an object, adds user2, and it is verified that user2 is able to decrypt the object.
func TestSharingObjectPart1(t *testing.T) {
	ctx := context.Background()
	enc := newTestD1(t)
	_, token1 := newTestUser(t, &enc, id.ScopeEncrypt, id.ScopeModifyAccessGroups)
	id2, token2 := newTestUser(t, &enc, id.ScopeDecrypt)

	plainObject := data.Object{
		Plaintext:      []byte("plaintext"),
		AssociatedData: []byte("associated_data"),
	}

	oid, err := enc.Encrypt(ctx, token1, &plainObject)
	if err != nil {
		t.Fatal(err)
	}

	if _, err = enc.Decrypt(ctx, token2, oid); err == nil {
		t.Fatal("Unauthorized user was able to decrypt")
	}

	if err = enc.AddGroupsToAccess(ctx, token1, oid, id2); err != nil {
		t.Fatal(err)
	}

	if _, err = enc.Decrypt(ctx, token2, oid); err != nil {
		t.Fatal(err)
	}
}

// user1 creates an object and adds user2. User2 removes user1, and it is verified that user1 is not able to decrypt the object.
func TestSharingObjectPart2(t *testing.T) {
	ctx := context.Background()
	enc := newTestD1(t)
	id1, token1 := newTestUser(t, &enc, id.ScopeEncrypt, id.ScopeModifyAccessGroups)
	id2, token2 := newTestUser(t, &enc, id.ScopeModifyAccessGroups)

	plainObject := data.Object{
		Plaintext:      []byte("plaintext"),
		AssociatedData: []byte("associated_data"),
	}

	oid, err := enc.Encrypt(ctx, token1, &plainObject)
	if err != nil {
		t.Fatal(err)
	}
	if err = enc.AddGroupsToAccess(ctx, token1, oid, id2); err != nil {
		t.Fatal(err)
	}
	if err = enc.RemoveGroupsFromAccess(ctx, token2, oid, id1); err != nil {
		t.Fatal(err)
	}

	if _, err = enc.Decrypt(ctx, token1, oid); err == nil {
		t.Fatal("Unauthorized user able to decrypt")
	}
}

// User1 creates an object, adds user2, user2 adds user3, and it is verified that user3 is able to decrypt the object.
func TestSharingObjectPart3(t *testing.T) {
	ctx := context.Background()
	enc := newTestD1(t)
	_, token1 := newTestUser(t, &enc, id.ScopeEncrypt, id.ScopeModifyAccessGroups)
	id2, token2 := newTestUser(t, &enc, id.ScopeModifyAccessGroups)
	id3, token3 := newTestUser(t, &enc, id.ScopeDecrypt)

	plainObject := data.Object{
		Plaintext:      []byte("plaintext"),
		AssociatedData: []byte("associated_data"),
	}

	oid, err := enc.Encrypt(ctx, token1, &plainObject)
	if err != nil {
		t.Fatal(err)
	}

	if err = enc.AddGroupsToAccess(ctx, token1, oid, id2); err != nil {
		t.Fatal(err)
	}
	if err = enc.AddGroupsToAccess(ctx, token2, oid, id3); err != nil {
		t.Fatal(err)
	}

	if _, err = enc.Decrypt(ctx, token3, oid); err != nil {
		t.Fatal(err)
	}
}

// Scenario:
// 1) Five users are created.
// 2) user1 creates a group and adds all users to it.
// 3) user1 encrypts an object and adds the group to the access object.
// 4) It is verified that all five users are able to decrypt the object.
func TestSharingObjectPart4(t *testing.T) {
	ctx := context.Background()
	numUsers := 5

	enc := newTestD1(t)
	uids := make([]string, 0, numUsers)
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

	oid, err := enc.Encrypt(ctx, tokens[0], &plainObject)
	if err != nil {
		t.Fatal(err)
	}

	if err = enc.AddGroupsToAccess(ctx, tokens[0], oid, gid); err != nil {
		t.Fatal(err)
	}

	for _, token := range tokens {
		if _, err = enc.Decrypt(ctx, token, oid); err != nil {
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
	ctx := context.Background()
	enc := newTestD1(t)
	_, token := newTestUser(t, &enc, id.ScopeEncrypt, id.ScopeModifyAccessGroups)
	identity, err := enc.idProvider.GetIdentity(ctx, token)
	if err != nil {
		t.Fatal(err)
	}

	plainObject := data.Object{
		Plaintext:      []byte("plaintext"),
		AssociatedData: []byte("associated_data"),
	}

	id, err := enc.Encrypt(ctx, token, &plainObject)
	if err != nil {
		t.Fatal(err)
	}

	if err = enc.RemoveGroupsFromAccess(ctx, token, id, identity.ID); err != nil {
		t.Fatal(err)
	}

	if err = enc.AuthorizeIdentity(ctx, token, id); err == nil {
		t.Fatal("Unauthorized user is authorized anyway")
	}
}

////////////////////////////////////////////////////////
//                  AuthorizeIdentity                 //
////////////////////////////////////////////////////////

// Scenario:
// 1) Two users are created, user1 and user2.
// 2) user1 encrypts an object.
// 3) It is verified that only user1 is authorized.
func TestAuthorizeUser(t *testing.T) {
	ctx := context.Background()
	enc := newTestD1(t)
	_, token1 := newTestUser(t, &enc, id.ScopeEncrypt, id.ScopeGetAccessGroups)
	_, token2 := newTestUser(t, &enc, id.ScopeGetAccessGroups)

	plainObject := data.Object{
		Plaintext:      []byte("plaintext"),
		AssociatedData: []byte("associated_data"),
	}

	id, err := enc.Encrypt(ctx, token1, &plainObject)
	if err != nil {
		t.Fatal(err)
	}

	if err = enc.AuthorizeIdentity(ctx, token1, id); err != nil {
		t.Fatal(err)
	}

	if err = enc.AuthorizeIdentity(ctx, token2, id); err == nil {
		t.Fatal("Unauthorized user is authorized anyway")
	}
}

func TestAuthorizeUserExtraGroups(t *testing.T) {
	ctx := context.Background()
	enc := newTestD1(t)
	_, token1 := newTestUser(t, &enc, id.ScopeEncrypt, id.ScopeGetAccessGroups)
	user2, token2 := newTestUser(t, &enc, id.ScopeGetAccessGroups)
	_, token3 := newTestUser(t, &enc, id.ScopeGetAccessGroups)

	plainObject := data.Object{
		Plaintext:      []byte("plaintext"),
		AssociatedData: []byte("associated_data"),
	}

	// Add user2 at encryption time
	id, err := enc.Encrypt(ctx, token1, &plainObject, user2)
	if err != nil {
		t.Fatal(err)
	}

	// Both the encrypter and user2 should have access
	if err = enc.AuthorizeIdentity(ctx, token1, id); err != nil {
		t.Fatal(err)
	}
	if err = enc.AuthorizeIdentity(ctx, token2, id); err != nil {
		t.Fatal(err)
	}

	if err = enc.AuthorizeIdentity(ctx, token3, id); err == nil {
		t.Fatal("Unauthorized user is authorized anyway")
	}
}

func TestAuthorizeUserUnauthenticated(t *testing.T) {
	ctx := context.Background()
	enc := newTestD1(t)
	err := enc.AuthorizeIdentity(ctx, "bad token", uuid.Must(uuid.NewV4()))
	if !errors.Is(err, ErrNotAuthenticated) {
		t.Fatalf("Expected error '%s' but got '%s'", ErrNotAuthenticated, err)
	}
}

// Test that a user without the GetAccessGroups scope cannot check if a user is authorized.
func TestAuthorizeUserWrongAPIScope(t *testing.T) {
	ctx := context.Background()
	enc := newTestD1(t)
	scope := id.ScopeAll ^ id.ScopeGetAccessGroups // All scopes except GetAccessGroups
	_, token := newTestUser(t, &enc, scope)
	err := enc.AuthorizeIdentity(ctx, token, uuid.Must(uuid.NewV4()))
	if !errors.Is(err, ErrNotAuthorized) {
		t.Fatalf("Expected error '%s' but got '%s'", ErrNotAuthorized, err)
	}
}

// Test that a user whose group does not have the AuthorizeUser scope cannot check if a user is authorized.
func TestAuthorizeUserWrongGroupScope(t *testing.T) {
	ctx := context.Background()
	enc := newTestD1(t)
	_, token1 := newTestUser(t, &enc, id.ScopeAll)
	user2, token2 := newTestUser(t, &enc, id.ScopeAll)

	// User2 has all scopes themselves, but get access to the object through a group with a missing
	// scope.
	scope := id.ScopeAll ^ id.ScopeGetAccessGroups // All scopes except GetAccessGroups
	gid := newTestGroup(t, &enc, token1, scope, user2)

	oid, err := enc.Encrypt(ctx, token1, &data.Object{})
	if err != nil {
		t.Fatal(err)
	}
	if err := enc.AddGroupsToAccess(ctx, token1, oid, gid); err != nil {
		t.Fatal(err)
	}

	err = enc.AuthorizeIdentity(ctx, token2, oid)
	if !errors.Is(err, ErrNotAuthorized) {
		t.Fatalf("Expected error '%s' but got '%s'", ErrNotAuthorized, err)
	}
}
