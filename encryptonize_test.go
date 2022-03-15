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
)

func newTestEncryptonize(t *testing.T) Encryptonize {
	var keys = Keys{
		KEK: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		AEK: []byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
		TEK: []byte{2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2},
		UEK: []byte{3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3},
		GEK: []byte{4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4},
	}
	encryptonize, err := New(keys)
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

	plainObject := Object{
		Plaintext:      []byte("plaintext"),
		AssociatedData: []byte("associated_data"),
	}
	object, access, err := enc.Encrypt(&user, &plainObject)
	if err != nil {
		t.Fatal(err)
	}

	decrypted, err := enc.Decrypt(&user, &object, &access)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(plainObject, decrypted) {
		t.Fatal("Decrypted object not equal to original")
	}
}

// It is verified than only an authorized user is able to encrypt.
func TestEncryptUnauthorizedUser(t *testing.T) {
	enc := newTestEncryptonize(t)

	user, _, _, err := enc.NewUser(nil)
	if err != nil {
		t.Fatal(err)
	}

	// Make user unauthorized by changing its first 5 ciphertext bytes to 0 
	user.Ciphertext[0] = 0
	user.Ciphertext[1] = 0
	user.Ciphertext[2] = 0
	user.Ciphertext[3] = 0
	user.Ciphertext[4] = 0

	plainObject := Object{
		Plaintext:		[]byte("plaintext"),
		AssociatedData:	[]byte("associated_data"),
	}

	_, _, err = enc.Encrypt(&user, &plainObject)
	if err == nil {
		t.Fatal(err)
	}
}

// It is verified than only an authorized user is able to decrypt.
func TestDecryptUnauthorizedUser(t *testing.T) {
	enc := newTestEncryptonize(t)

	user, _, _, err := enc.NewUser(nil)
	if err != nil {
		t.Fatal(err)
	}

	plainObject := Object{
		Plaintext:		[]byte("plaintext"),
		AssociatedData:	[]byte("associated_data"),
	}

	object, access, err := enc.Encrypt(&user, &plainObject)
	if err != nil {
		t.Fatal(err)
	}

	// Make user unauthorized by changing its first 5 ciphertext bytes to 0 
	user.Ciphertext[0] = 0
	user.Ciphertext[1] = 0
	user.Ciphertext[2] = 0
	user.Ciphertext[3] = 0
	user.Ciphertext[4] = 0

	_, err = enc.Decrypt(&user, &object, &access)
	if err == nil {
		t.Fatal(err)
	}
}

// Scenario:  
// 1) Two users are created, user1 and user2.
// 2) user1 encrypts an object.
// 3) It is verified that only user1 who is part of the access object is authorized and able to update the object.
// 4) It is verified that an object is correctly encrypted, updated, and decrypted.
func TestUpdate(t *testing.T) {
	enc := newTestEncryptonize(t)

	user1, _, _, err := enc.NewUser(nil)
	if err != nil {
		t.Fatal(err)
	}

	user2, _, _, err := enc.NewUser(nil)
	if err != nil {
		t.Fatal(err)
	}

	plainObject := Object{
		Plaintext:		[]byte("plaintext"),
		AssociatedData:	[]byte("associated_data"),
	}

	_, access, err := enc.Encrypt(&user1, &plainObject)
	if err != nil {
		t.Fatal(err)
	}

	plainObjectUpdated := Object{
		Plaintext:		[]byte("plaintext_updated"),
		AssociatedData:	[]byte("associated_data_updated"),
	}

	objectUpdated, err := enc.Update(&user2, &plainObjectUpdated, &access)
	if err == nil {
		t.Fatal(err)
	}

	objectUpdated, err = enc.Update(&user1, &plainObjectUpdated, &access)
	if err != nil {
		t.Fatal(err)
	}

	decrypted, err := enc.Decrypt(&user1, &objectUpdated, &access)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(plainObjectUpdated, decrypted) {
		t.Fatal("Decrypted object not equal to original")
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

	plainObject := Object{
		Plaintext:		nil,
		AssociatedData:	[]byte("associated_data"),
	}

	_, _, err = enc.Encrypt(&user, &plainObject)
	if err != nil {
		t.Fatal(err)
	}

	plainObject = Object{
		Plaintext:		[]byte("plaintext"),
		AssociatedData:	nil,
	}

	_, _, err = enc.Encrypt(&user, &plainObject)
	if err != nil {
		t.Fatal(err)
	}

	plainObject = Object{
		Plaintext:		nil,
		AssociatedData:	nil,
	}

	_, _, err = enc.Encrypt(&user, &plainObject)
	if err != nil {
		t.Fatal(err)
	}

	plainObject = Object{
		Plaintext:		[]byte("plaintext"),
		AssociatedData:	[]byte("associated_data"),
	}

	_, _, err = enc.Encrypt(&user, &plainObject)
	if err != nil {
		t.Fatal(err)
	}
}

// Scenario:
// 1) A token is created.
// 2) It is verified that the token contents is correctly derived.
// 3) It is verified that if the token ciphertext is changed, then contents cannot be derived anymore. 
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

	// Change the first 5 token ciphertext bytes to 0 and verify that contents cannot be derived.
	token.Ciphertext[0] = 0
	token.Ciphertext[1] = 0
	token.Ciphertext[2] = 0
	token.Ciphertext[3] = 0
	token.Ciphertext[4] = 0

	contents, err = enc.GetTokenContents(&token)
	if err == nil {
		t.Fatal(err)
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

	plainObject := Object{
		Plaintext:      []byte("plaintext"),
		AssociatedData: []byte("associated_data"),
	}

	_, access, err := enc.Encrypt(&user1, &plainObject)
	if err != nil {
		t.Fatal(err)
	}

	_, err = enc.GetAccessGroups(&user1, &access)
	if err != nil {
		t.Fatal(err)
	}

	_, err = enc.GetAccessGroups(&user2, &access)
	if err == nil {
		t.Fatal(err)
	}
}

// Scenario:
// 1) Two users are created, user1 and user2.
// 2) user1 encrypts an object.
// 3) It is verified that the group with same ID as user1 can be added and removed from the access object.
// 4) It is verified that only user1 who is part of the access object is able to add and remove the group.
func TestAddRemoveGroupsFromAccess(t *testing.T) {
	enc := newTestEncryptonize(t)

	user1, group, _, err := enc.NewUser(nil)
	if err != nil {
		t.Fatal(err)
	}

	user2, _, _, err := enc.NewUser(nil)
	if err != nil {
		t.Fatal(err)
	}

	plainObject := Object{
		Plaintext:      []byte("plaintext"),
		AssociatedData: []byte("associated_data"),
	}

	_, access, err := enc.Encrypt(&user1, &plainObject)
	if err != nil {
		t.Fatal(err)
	}

	err = enc.AddGroupsToAccess(&user2, &access, &group)
	if err == nil {
		t.Fatal(err)
	}

	err = enc.AddGroupsToAccess(&user1, &access, &group)
	if err != nil {
		t.Fatal(err)
	}

	accessGroups, err := enc.GetAccessGroups(&user1, &access)

	if _, ok := accessGroups[group.ID]; !ok {
		t.Fatal("Group not correctly added to access")
	}

	err = enc.RemoveGroupsFromAccess(&user2, &access, &group)
	if err == nil {
		t.Fatal(err)
	}

	err = enc.RemoveGroupsFromAccess(&user1, &access, &group)
	if err != nil {
		t.Fatal(err)
	}

	accessGroups, err = enc.GetAccessGroups(&user1, &access)

	if _, ok := accessGroups[group.ID]; ok {
		t.Fatal("Group not correctly removed from access")
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

	plainObject := Object{
		Plaintext:		[]byte("plaintext"),
		AssociatedData:	[]byte("associated_data"),
	}

	_, access, err := enc.Encrypt(&user1, &plainObject)
	if err != nil {
		t.Fatal(err)
	}

	err = enc.AuthorizeUser(&user1, &access)
	if err != nil {
		t.Fatal(err)
	}

	err = enc.AuthorizeUser(&user2, &access)
	if err == nil {
		t.Fatal(err)
	}

	// Make user1 unauthorized by changing its first 5 ciphertext bytes to 0 
	user1.Ciphertext[0] = 0
	user1.Ciphertext[1] = 0
	user1.Ciphertext[2] = 0
	user1.Ciphertext[3] = 0
	user1.Ciphertext[4] = 0

	err = enc.AuthorizeUser(&user1, &access)
	if err == nil {
		t.Fatal(err)
	}
}

// Scenario: 
// 1) user1 is created.
// 2) user1 creates two additional groups, group1 and group2.
// 3) group2 is broken by changing some of its ciphertext.
// 4) It is verified that user2 can be created and added to its own group and group1 simultaneously.
// 5) It is verified that a third user cannot be created and added to its own group and group2 simultaneously (because of step 3) ).
func TestNewUser(t *testing.T) {
	enc := newTestEncryptonize(t)

	user1, _, _, err := enc.NewUser(nil)
	if err != nil {
		t.Fatal(err)
	}

	group1, err := enc.NewGroup(&user1, []byte("group_data_1"))
	if err != nil {
		t.Fatal(err)
	}

	group2, err := enc.NewGroup(&user1, []byte("group_data_2"))
	if err != nil {
		t.Fatal(err)
	}

	group2.Ciphertext[0] = 0
	group2.Ciphertext[1] = 0
	group2.Ciphertext[2] = 0
	group2.Ciphertext[3] = 0
	group2.Ciphertext[4] = 0

	user2, _, _, err := enc.NewUser([]byte("data"), &group1)
	if err != nil {
		t.Fatal(err)
	}

	userGroups, err := enc.GetUserGroups(&user2)
	if err != nil {
		t.Fatal(err)
	}

	if _, ok := userGroups[user2.ID]; !ok {
		t.Fatal("User not correctly added to its own group")
	}

	if _, ok := userGroups[group1.ID]; !ok {
		t.Fatal("User not correctly added to group")
	}

	_, _, _, err = enc.NewUser([]byte("data"), &group2)
	if err == nil {
		t.Fatal(err)
	}
}

// It is verified that both empty and non-empty group data is accepted. Group data can be provided through either NewUser or NewGroup.
func TestGroupData(t *testing.T) {
	enc := newTestEncryptonize(t)

	user1, _, _, err := enc.NewUser(nil)
	if err != nil {
		t.Fatal(err)
	}

	user2, _, _, err := enc.NewUser([]byte("group_data"))
	if err != nil {
		t.Fatal(err)
	}

	_, err = enc.NewGroup(&user1, nil)
	if err != nil {
		t.Fatal(err)
	}

	_, err = enc.NewGroup(&user2, []byte("data"))
	if err != nil {
		t.Fatal(err)
	}
}

// Scenario: 
// 1) Two users are created, user1 and user2.
// 2) It is verified that only user1 is authenticated with user1's password.
// 3) It is verified that a user is not authenticated with a mistyped password.
func TestAuthenticateUser(t *testing.T) {
	enc := newTestEncryptonize(t)

	user1, _, pwd1, err := enc.NewUser(nil)
	if err != nil {
		t.Fatal(err)
	}

	user2, _, _, err := enc.NewUser(nil)
	if err != nil {
		t.Fatal(err)
	}

	err = enc.AuthenticateUser(&user1, pwd1)
	if err != nil {
		t.Fatal(err)
	}

	err = enc.AuthenticateUser(&user2, pwd1)
	if err == nil {
		t.Fatal("User authenticated with wrong password")
	}

	pwd1Short := pwd1[:len(pwd1)-1]
	pwd1Long := pwd1 + "0"

	err = enc.AuthenticateUser(&user1, pwd1Short)
	if err == nil {
		t.Fatal("User authenticated with wrong password")
	}

	err = enc.AuthenticateUser(&user1, pwd1Long)
	if err == nil {
		t.Fatal("User authenticated with wrong password")
	}
}

// Scenario: 
// 1) Three users are created, user1, user2, and user3.
// 2) user1 creates a group.
// 3) It is verified that user1 is able to add and remove user2 from the group.
// 4) It is verified that user3 who is not a member of the group is not able to add and remove user2 from the group.
func TestAddRemoveUserFromGroups(t *testing.T) {
	enc := newTestEncryptonize(t)

	user1, _, _, err := enc.NewUser(nil)
	if err != nil {
		t.Fatal(err)
	}

	user2, _, _, err := enc.NewUser(nil)
	if err != nil {
		t.Fatal(err)
	}

	user3, _, _, err := enc.NewUser(nil)
	if err != nil {
		t.Fatal(err)
	}

	group, err := enc.NewGroup(&user1, []byte("data"))
	if err != nil {
		t.Fatal(err)
	}

	err = enc.AddUserToGroups(&user3, &user2, &group)
	if err == nil {
		t.Fatal(err)
	}

	err = enc.AddUserToGroups(&user1, &user2, &group)
	if err != nil {
		t.Fatal(err)
	}

	userGroups, err := enc.GetUserGroups(&user2)

	if _, ok := userGroups[group.ID]; !ok {
		t.Fatal("User not correctly added to group")
	}

	err = enc.RemoveUserFromGroups(&user3, &user2, &group)
	if err == nil {
		t.Fatal(err)
	}
	
	err = enc.RemoveUserFromGroups(&user1, &user2, &group)
	if err != nil {
		t.Fatal(err)
	}

	userGroups, err = enc.GetUserGroups(&user2)

	if _, ok := userGroups[group.ID]; ok {
		t.Fatal("User not correctly removed from group")
	}
}

// Scenario: 
// 1) Two users are created, user1 and user2.
// 2) user1 creates a group.
// 3) It is verified that only user1 who is a member of the group is able to call GetGroupData.
func TestGetGroupData(t *testing.T) {
	enc := newTestEncryptonize(t)

	user1, _, _, err := enc.NewUser(nil)
	if err != nil {
		t.Fatal(err)
	}

	user2, _, _, err := enc.NewUser(nil)
	if err != nil {
		t.Fatal(err)
	}

	group, err := enc.NewGroup(&user1, nil)
	if err != nil {
		t.Fatal(err)
	}

	_, err = enc.GetGroupData(&user1, &group)
	if err != nil {
		t.Fatal(err)
	}

	_, err = enc.GetGroupData(&user2, &group)
	if err == nil {
		t.Fatal(err)
	}
}

// Scenario:
// 1) A user is created.
// 2) The user creates a group.
// 3) It is verified that if the user is removed from the group, then no one can add new members to the group and hence the group is lost.
func TestRemoveAllUsers(t *testing.T) {
	enc := newTestEncryptonize(t)

	user1, group, _, err := enc.NewUser(nil)
	if err != nil {
		t.Fatal(err)
	}

	err = enc.RemoveUserFromGroups(&user1, &user1, &group)
	if err != nil {
		t.Fatal(err)
	}

	userGroups, err := enc.GetUserGroups(&user1)

	if _, ok := userGroups[group.ID]; ok {
		t.Fatal("User not correctly removed from group")
	}

	user2, _, _, err := enc.NewUser(nil)
	if err != nil {
		t.Fatal(err)
	}

	// user1 cannot add user2 to the group
	err = enc.AddUserToGroups(&user1, &user2, &group)
	if err == nil {
		t.Fatal(err)
	}
}

// Scenario:
// 1) Two users are created, user1 and user2.
// 2) user1 creates two groups.
// 3) It is verified that user1 can add user2 to both groups simultaneously.
// 4) It is verified that user1 can remove user2 from both groups simultaneously.
func TestMultipleGroups(t *testing.T) {
	enc := newTestEncryptonize(t)

	user1, _, _, err := enc.NewUser(nil)
	if err != nil {
		t.Fatal(err)
	}

	user2, _, _, err := enc.NewUser(nil)
	if err != nil {
		t.Fatal(err)
	}

	group1, err := enc.NewGroup(&user1, []byte("group_data_1"))
	if err != nil {
		t.Fatal(err)
	}

	group2, err := enc.NewGroup(&user1, []byte("group_data_2"))
	if err != nil {
		t.Fatal(err)
	}

	err = enc.AddUserToGroups(&user1, &user2, &group1, &group2)
	if err != nil {
		t.Fatal(err)
	}

	userGroups, err := enc.GetUserGroups(&user2)

	if _, ok := userGroups[group1.ID]; !ok {
		t.Fatal("User not correctly added to group")
	}

	if _, ok := userGroups[group2.ID]; !ok {
		t.Fatal("User not correctly added to group")
	}

	err = enc.RemoveUserFromGroups(&user1, &user2, &group1, &group2)
	if err != nil {
		t.Fatal(err)
	}

	userGroups, err = enc.GetUserGroups(&user2)

	if _, ok := userGroups[group1.ID]; ok {
		t.Fatal("User not correctly removed from group")
	}

	if _, ok := userGroups[group2.ID]; ok {
		t.Fatal("User not correctly removed from group")
	}
}

// Scenario:
// 1) A user is created.
// 2) The user encrypts an object.
// 3) The user adds its own group to the access object.
// 4) The user removes its own group from the access object.
// 4) It is verified that the user is no longer part of the access object even though it was created by the user itself.
func TestRemoveAccess(t *testing.T) {
	enc := newTestEncryptonize(t)

	user, group, _, err := enc.NewUser(nil)
	if err != nil {
		t.Fatal(err)
	}

	plainObject := Object{
		Plaintext:      []byte("plaintext"),
		AssociatedData: []byte("associated_data"),
	}

	_, access, err := enc.Encrypt(&user, &plainObject)
	if err != nil {
		t.Fatal(err)
	}

	err = enc.AddGroupsToAccess(&user, &access, &group)
	if err != nil {
		t.Fatal(err)
	}

	err = enc.RemoveUserFromGroups(&user, &user, &group)
	if err != nil {
		t.Fatal(err)
	}

	userGroups, err := enc.GetUserGroups(&user)

	if _, ok := userGroups[group.ID]; ok {
		t.Fatal("User not correctly removed from group")
	}

	err = enc.AuthorizeUser(&user, &access)
	if err == nil {
		t.Fatal(err)
	}
}
