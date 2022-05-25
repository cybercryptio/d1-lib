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

	"github.com/cyber-crypt-com/encryptonize-lib/data"
	"github.com/cyber-crypt-com/encryptonize-lib/io"
	"github.com/cyber-crypt-com/encryptonize-lib/key"
)

func newTestEncryptonize(t *testing.T) Encryptonize {
	keyProvider := key.NewStatic(key.Keys{
		KEK: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		AEK: []byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
		TEK: []byte{2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2},
		UEK: []byte{3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3},
		GEK: []byte{4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4},
		IEK: []byte{5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5},
	})
	ioProvider := io.NewMem()
	encryptonize, err := New(&keyProvider, &ioProvider)
	if err != nil {
		t.Fatal(err)
	}
	return encryptonize
}

// It is verified that an object is correctly encrypted and decrypted.
func TestEncryptDecrypt(t *testing.T) {
	enc := newTestEncryptonize(t)

	user, _, _, err := enc.NewUser(nil)
	if err != nil {
		t.Fatal(err)
	}

	plainObject := data.Object{
		Plaintext:      []byte("plaintext"),
		AssociatedData: []byte("associated_data"),
	}

	id, err := enc.Encrypt(&user, &plainObject)
	if err != nil {
		t.Fatal(err)
	}

	decrypted, err := enc.Decrypt(&user, id)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(plainObject, decrypted) {
		t.Fatal("Decrypted object not equal to original")
	}
}

// It is verified than an unauthorized user is not able to encrypt.
func TestEncryptUnauthorizedUser(t *testing.T) {
	enc := newTestEncryptonize(t)

	user, _, _, err := enc.NewUser(nil)
	if err != nil {
		t.Fatal(err)
	}

	// Make user unauthorized by changing its first 5 ciphertext bytes to 0
	copy(user.Ciphertext[:5], make([]byte, 5))

	plainObject := data.Object{
		Plaintext:      []byte("plaintext"),
		AssociatedData: []byte("associated_data"),
	}

	id, err := enc.Encrypt(&user, &plainObject)
	if err == nil {
		t.Fatal("Unauthorized user able to encrypt")
	}
	if !id.IsNil() {
		t.Fatal("Encryption failed, but returned an ID anyway")
	}
}

// It is verified that an unauthorized user is not able to decrypt.
func TestDecryptUnauthorizedUser(t *testing.T) {
	enc := newTestEncryptonize(t)

	user, _, _, err := enc.NewUser(nil)
	if err != nil {
		t.Fatal(err)
	}

	plainObject := data.Object{
		Plaintext:      []byte("plaintext"),
		AssociatedData: []byte("associated_data"),
	}

	id, err := enc.Encrypt(&user, &plainObject)
	if err != nil {
		t.Fatal(err)
	}

	// Make user unauthorized by changing its first 5 ciphertext bytes to 0
	copy(user.Ciphertext[:5], make([]byte, 5))

	decrypted, err := enc.Decrypt(&user, id)
	if err == nil {
		t.Fatal("Unauthorized user able to decrypt")
	}
	if reflect.DeepEqual(decrypted, plainObject) {
		t.Fatal("Decryption failed, but returned plain object anyway")
	}
}

// It is verified that an object is correctly encrypted, updated, and decrypted.
func TestUpdate(t *testing.T) {
	enc := newTestEncryptonize(t)

	user, _, _, err := enc.NewUser(nil)
	if err != nil {
		t.Fatal(err)
	}

	plainObject := data.Object{
		Plaintext:      []byte("plaintext"),
		AssociatedData: []byte("associated_data"),
	}

	id, err := enc.Encrypt(&user, &plainObject)
	if err != nil {
		t.Fatal(err)
	}

	plainObjectUpdated := data.Object{
		Plaintext:      []byte("plaintext_updated"),
		AssociatedData: []byte("associated_data_updated"),
	}

	err = enc.Update(&user, id, &plainObjectUpdated)
	if err != nil {
		t.Fatal(err)
	}

	decrypted, err := enc.Decrypt(&user, id)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(plainObjectUpdated, decrypted) {
		t.Fatal("Updated and decrypted object not equal to updated plain object")
	}
}

// It is verified that an unauthorized user is not able to update.
func TestUpdateUnauthorizedUser(t *testing.T) {
	enc := newTestEncryptonize(t)

	user, _, _, err := enc.NewUser(nil)
	if err != nil {
		t.Fatal(err)
	}

	plainObject := data.Object{
		Plaintext:      []byte("plaintext"),
		AssociatedData: []byte("associated_data"),
	}

	id, err := enc.Encrypt(&user, &plainObject)
	if err != nil {
		t.Fatal(err)
	}

	plainObjectUpdated := data.Object{
		Plaintext:      []byte("plaintext_updated"),
		AssociatedData: []byte("associated_data_updated"),
	}

	// Make user unauthorized by changing its first 5 ciphertext bytes to 0
	copy(user.Ciphertext[:5], make([]byte, 5))

	err = enc.Update(&user, id, &plainObjectUpdated)
	if err == nil {
		t.Fatal("Unauthorized user able to update")
	}
}

// It is verified that plain objects with the following properties can be encrypted:
// 1) Plaintext is empty
// 2) Associated data is empty
// 3) Both are empty
// 4) Both are non-empty
func TestPlainObject(t *testing.T) {
	enc := newTestEncryptonize(t)

	user, _, _, err := enc.NewUser(nil)
	if err != nil {
		t.Fatal(err)
	}

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
			if _, err = enc.Encrypt(&user, &test.data); err != nil {
				t.Fatal(err)
			}
		})
	}
}

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

// Scenario:
// 1) Two users are created, user1 and user2.
// 2) user1 encrypts an object.
// 3) It is verified that only user1 who is part of the access object is able to call GetAccessGroups.
func TestGetAccessGroups(t *testing.T) {
	enc := newTestEncryptonize(t)

	user1, _, _, err := enc.NewUser(nil)
	if err != nil {
		t.Fatal(err)
	}

	user2, _, _, err := enc.NewUser(nil)
	if err != nil {
		t.Fatal(err)
	}

	plainObject := data.Object{
		Plaintext:      []byte("plaintext"),
		AssociatedData: []byte("associated_data"),
	}

	id, err := enc.Encrypt(&user1, &plainObject)
	if err != nil {
		t.Fatal(err)
	}

	_, err = enc.GetAccessGroups(&user1, id)
	if err != nil {
		t.Fatal(err)
	}

	accessGroups, err := enc.GetAccessGroups(&user2, id)
	if err == nil {
		t.Fatal("Unauthorized user able to get group IDs contained in access object")
	}
	if accessGroups != nil {
		t.Fatal("GetAccessGroups failed, but returned data anyway")
	}
}

// It is verified that a user can encrypt an object and add/remove a group to/from the access object.
func TestAddRemoveGroupsFromAccess(t *testing.T) {
	enc := newTestEncryptonize(t)

	user, _, _, err := enc.NewUser(nil)
	if err != nil {
		t.Fatal(err)
	}

	group, err := enc.NewGroup(&user, []byte("group_data"))
	if err != nil {
		t.Fatal(err)
	}

	plainObject := data.Object{
		Plaintext:      []byte("plaintext"),
		AssociatedData: []byte("associated_data"),
	}

	id, err := enc.Encrypt(&user, &plainObject)
	if err != nil {
		t.Fatal(err)
	}

	if err = enc.AddGroupsToAccess(&user, id, &group); err != nil {
		t.Fatal(err)
	}

	accessGroups, err := enc.GetAccessGroups(&user, id)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := accessGroups[group.ID]; !ok {
		t.Fatal("Group not correctly added to access object")
	}

	if err = enc.RemoveGroupsFromAccess(&user, id, &group); err != nil {
		t.Fatal(err)
	}

	accessGroups, err = enc.GetAccessGroups(&user, id)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := accessGroups[group.ID]; ok {
		t.Fatal("Group not correctly removed from access object")
	}
}

// It is verified that a user cannot add/remove groups to/from an access object without being part of the access object.
func TestAddRemoveGroupsFromAccessUnauthorized(t *testing.T) {
	enc := newTestEncryptonize(t)

	user1, _, _, err := enc.NewUser(nil)
	if err != nil {
		t.Fatal(err)
	}

	user2, _, _, err := enc.NewUser(nil)
	if err != nil {
		t.Fatal(err)
	}

	group, err := enc.NewGroup(&user1, []byte("group_data"))
	if err != nil {
		t.Fatal(err)
	}

	plainObject := data.Object{
		Plaintext:      []byte("plaintext"),
		AssociatedData: []byte("associated_data"),
	}

	id, err := enc.Encrypt(&user1, &plainObject)
	if err != nil {
		t.Fatal(err)
	}

	if err = enc.AddGroupsToAccess(&user2, id, &group); err == nil {
		t.Fatal("Unauthorized user able to add groups to access")
	}

	if err = enc.AddGroupsToAccess(&user1, id, &group); err != nil {
		t.Fatal(err)
	}

	if err = enc.RemoveGroupsFromAccess(&user2, id, &group); err == nil {
		t.Fatal("Unauthorized user able to remove groups from access")
	}
}

// It is verified that a user can add/remove groups to/from an access object without being member of the groups,
// as long as the user is part of the access object.
func TestAddRemoveGroupsFromAccessAuthorized(t *testing.T) {
	enc := newTestEncryptonize(t)

	user1, _, _, err := enc.NewUser(nil)
	if err != nil {
		t.Fatal(err)
	}

	_, group2, _, err := enc.NewUser(nil)
	if err != nil {
		t.Fatal(err)
	}

	plainObject := data.Object{
		Plaintext:      []byte("plaintext"),
		AssociatedData: []byte("associated_data"),
	}

	id, err := enc.Encrypt(&user1, &plainObject)
	if err != nil {
		t.Fatal(err)
	}

	if err = enc.AddGroupsToAccess(&user1, id, &group2); err != nil {
		t.Fatal(err)
	}

	accessGroups, err := enc.GetAccessGroups(&user1, id)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := accessGroups[group2.ID]; !ok {
		t.Fatal("User not able to add groups to access object. User is not member of all groups, but is part of access object.")
	}

	if err = enc.RemoveGroupsFromAccess(&user1, id, &group2); err != nil {
		t.Fatal(err)
	}

	accessGroups, err = enc.GetAccessGroups(&user1, id)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := accessGroups[group2.ID]; ok {
		t.Fatal("User not able to remove groups from access object. User is not member of all groups, but is part of access object.")
	}
}

// It is verified that it is not possible to add invalid groups to access.
func TestAddInvalidGroupsToAccess(t *testing.T) {
	enc := newTestEncryptonize(t)

	user, _, _, err := enc.NewUser(nil)
	if err != nil {
		t.Fatal(err)
	}

	group, err := enc.NewGroup(&user, []byte("group_data"))
	if err != nil {
		t.Fatal(err)
	}

	plainObject := data.Object{
		Plaintext:      []byte("plaintext"),
		AssociatedData: []byte("associated_data"),
	}

	id, err := enc.Encrypt(&user, &plainObject)
	if err != nil {
		t.Fatal(err)
	}

	// Make group invalid by changing its ciphertext
	copy(group.Ciphertext[:5], make([]byte, 5))

	if err = enc.AddGroupsToAccess(&user, id, &group); err == nil {
		t.Fatal("User able to add invalid groups to access")
	}
}

// It is verified that it is not possible to remove invalid groups from access.
func TestRemoveInvalidGroupsFromAccess(t *testing.T) {
	enc := newTestEncryptonize(t)

	user, _, _, err := enc.NewUser(nil)
	if err != nil {
		t.Fatal(err)
	}

	group, err := enc.NewGroup(&user, []byte("group_data"))
	if err != nil {
		t.Fatal(err)
	}

	plainObject := data.Object{
		Plaintext:      []byte("plaintext"),
		AssociatedData: []byte("associated_data"),
	}

	id, err := enc.Encrypt(&user, &plainObject)
	if err != nil {
		t.Fatal(err)
	}

	if err = enc.AddGroupsToAccess(&user, id, &group); err != nil {
		t.Fatal(err)
	}

	// Make group invalid by changing its ciphertext
	copy(group.Ciphertext[:5], make([]byte, 5))

	if err = enc.RemoveGroupsFromAccess(&user, id, &group); err == nil {
		t.Fatal("User able to remove invalid groups from access")
	}
}

// Scenario:
// 1) Two users are created, user1 and user2.
// 2) user1 encrypts an object.
// 3) It is verified that only user1 is authorized.
// 4) It is verified that if user1's ciphertext is changed, then user1 is not authorized anymore.
func TestAuthorizeUser(t *testing.T) {
	enc := newTestEncryptonize(t)

	user1, _, _, err := enc.NewUser(nil)
	if err != nil {
		t.Fatal(err)
	}

	user2, _, _, err := enc.NewUser(nil)
	if err != nil {
		t.Fatal(err)
	}

	plainObject := data.Object{
		Plaintext:      []byte("plaintext"),
		AssociatedData: []byte("associated_data"),
	}

	id, err := enc.Encrypt(&user1, &plainObject)
	if err != nil {
		t.Fatal(err)
	}

	if err = enc.AuthorizeUser(&user1, id); err != nil {
		t.Fatal(err)
	}

	if err = enc.AuthorizeUser(&user2, id); err == nil {
		t.Fatal("Unauthorized user is authorized anyway")
	}

	// Make user1 unauthorized by changing its first 5 ciphertext bytes to 0
	copy(user1.Ciphertext[:5], make([]byte, 5))

	if err = enc.AuthorizeUser(&user1, id); err == nil {
		t.Fatal("Unauthorized user is authorized anyway")
	}
}

// Scenario:
// 1) A user is created.
// 2) The user encrypts an object.
// 3) The user removes its own group from the access object.
// 4) It is verified that the user is no longer part of the access object even though he created it.
func TestRemoveAccess(t *testing.T) {
	enc := newTestEncryptonize(t)

	user, group, _, err := enc.NewUser(nil)
	if err != nil {
		t.Fatal(err)
	}

	plainObject := data.Object{
		Plaintext:      []byte("plaintext"),
		AssociatedData: []byte("associated_data"),
	}

	id, err := enc.Encrypt(&user, &plainObject)
	if err != nil {
		t.Fatal(err)
	}

	if err = enc.RemoveUserFromGroups(&user, &user, &group); err != nil {
		t.Fatal(err)
	}

	if err = enc.AuthorizeUser(&user, id); err == nil {
		t.Fatal("Unauthorized user is authorized anyway")
	}
}

// user1 creates an object, adds user2, and it is verified that user2 is able to decrypt the object.
func TestSharingObjectPart1(t *testing.T) {
	enc := newTestEncryptonize(t)

	user1, group, _, err := enc.NewUser(nil)
	if err != nil {
		t.Fatal(err)
	}

	plainObject := data.Object{
		Plaintext:      []byte("plaintext"),
		AssociatedData: []byte("associated_data"),
	}

	id, err := enc.Encrypt(&user1, &plainObject)
	if err != nil {
		t.Fatal(err)
	}

	user2, _, _, err := enc.NewUser(nil)
	if err != nil {
		t.Fatal(err)
	}

	if err = enc.AddUserToGroups(&user1, &user2, &group); err != nil {
		t.Fatal(err)
	}

	if _, err = enc.Decrypt(&user2, id); err != nil {
		t.Fatal(err)
	}
}

// user1 creates an object and adds user2. User2 removes user1, and it is verified that user1 is not able to decrypt the object.
func TestSharingObjectPart2(t *testing.T) {
	enc := newTestEncryptonize(t)

	user1, group, _, err := enc.NewUser(nil)
	if err != nil {
		t.Fatal(err)
	}

	plainObject := data.Object{
		Plaintext:      []byte("plaintext"),
		AssociatedData: []byte("associated_data"),
	}

	id, err := enc.Encrypt(&user1, &plainObject)
	if err != nil {
		t.Fatal(err)
	}

	user2, _, _, err := enc.NewUser(nil)
	if err != nil {
		t.Fatal(err)
	}

	if err = enc.AddUserToGroups(&user1, &user2, &group); err != nil {
		t.Fatal(err)
	}

	if err = enc.RemoveUserFromGroups(&user2, &user1, &group); err != nil {
		t.Fatal(err)
	}

	if _, err = enc.Decrypt(&user1, id); err == nil {
		t.Fatal("Unauthorized user able to decrypt")
	}
}

// User1 creates an object, adds user2, user2 adds user3, and it is verified that user3 is able to decrypt the object.
func TestSharingObjectPart3(t *testing.T) {
	enc := newTestEncryptonize(t)

	user1, group, _, err := enc.NewUser(nil)
	if err != nil {
		t.Fatal(err)
	}

	plainObject := data.Object{
		Plaintext:      []byte("plaintext"),
		AssociatedData: []byte("associated_data"),
	}

	id, err := enc.Encrypt(&user1, &plainObject)
	if err != nil {
		t.Fatal(err)
	}

	user2, _, _, err := enc.NewUser(nil)
	if err != nil {
		t.Fatal(err)
	}

	if err = enc.AddUserToGroups(&user1, &user2, &group); err != nil {
		t.Fatal(err)
	}

	user3, _, _, err := enc.NewUser(nil)
	if err != nil {
		t.Fatal(err)
	}

	if err = enc.AddUserToGroups(&user2, &user3, &group); err != nil {
		t.Fatal(err)
	}

	if _, err = enc.Decrypt(&user3, id); err != nil {
		t.Fatal(err)
	}
}

// Scenario:
// 1) Five users are created.
// 2) user1 creates a group and adds all users to it.
// 3) user1 encrypts an object and adds the group to the access object.
// 4) It is verified that all five users are able to decrypt the object.
func TestSharingObjectPart4(t *testing.T) {
	enc := newTestEncryptonize(t)

	numUsers := 5
	users := make([]data.SealedUser, 0, numUsers)
	for i := 0; i < numUsers; i++ {
		newUser, _, _, err := enc.NewUser(nil)
		if err != nil {
			t.Fatal(err)
		}
		users = append(users, newUser)
	}

	group, err := enc.NewGroup(&users[0], []byte("data"))
	if err != nil {
		t.Fatal(err)
	}

	for i := 1; i < len(users); i++ {
		if err = enc.AddUserToGroups(&users[0], &users[i], &group); err != nil {
			t.Fatal(err)
		}
	}

	plainObject := data.Object{
		Plaintext:      []byte("plaintext"),
		AssociatedData: []byte("associated_data"),
	}

	id, err := enc.Encrypt(&users[0], &plainObject)
	if err != nil {
		t.Fatal(err)
	}

	if err = enc.AddGroupsToAccess(&users[0], id, &group); err != nil {
		t.Fatal(err)
	}

	for i := range users {
		if _, err = enc.Decrypt(&users[i], id); err != nil {
			t.Fatal(err)
		}
	}
}

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
