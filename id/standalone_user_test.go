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

package id

import (
	"fmt"
	"testing"

	"reflect"

	"github.com/cybercryptio/d1-lib/crypto"
)

var groupIDs = []string{
	"groupID1",
	"groupID2",
	"groupID3",
	"groupID4",
}

func TestGetGroupIDs(t *testing.T) {
	user, _, err := newUser(ScopeEncrypt)
	if err != nil {
		t.Fatal(err)
	}
	groupID := "groupID"
	user.addGroups(groupID)

	userGroups := user.getGroups()
	if _, ok := userGroups[groupID]; len(userGroups) == 0 || !ok {
		t.Error("Expected GetGroups to return a group ID")
	}
}

func TestGetZeroGroupIDs(t *testing.T) {
	user, _, err := newUser(ScopeEncrypt)
	if err != nil {
		t.Fatal(err)
	}

	userGroups := user.getGroups()
	if len(userGroups) != 0 {
		t.Error("GetGroups should have returned empty array")
	}
}

func TestUserContainsGroup(t *testing.T) {
	user, _, err := newUser(ScopeEncrypt)
	if err != nil {
		t.Fatal(err)
	}
	user.addGroups(groupIDs...)

	if !user.containsGroups(groupIDs...) {
		t.Error("ContainsGroup returned false")
	}

	if user.containsGroups("non-existent user ID") {
		t.Error("ContainsGroup returned true")
	}
}

func TestUserAdd(t *testing.T) {
	user, _, err := newUser(ScopeEncrypt)
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 256; i++ {
		g := fmt.Sprintf("groupID%d", i)
		user.addGroups(g)
		if !user.containsGroups(g) {
			t.Error("AddGroup failed")
		}
	}
}

func TestUserAddDuplicate(t *testing.T) {
	user, _, err := newUser(ScopeEncrypt)
	if err != nil {
		t.Fatal(err)
	}
	g := "groupID"
	user.addGroups(g)
	user.addGroups(g)
	if !user.containsGroups(g) {
		t.Error("calling AddGroup twice with same ID failed")
	}
}

func TestUserRemoveGroup(t *testing.T) {
	user, _, err := newUser(ScopeEncrypt)
	if err != nil {
		t.Fatal(err)
	}
	user.addGroups(groupIDs...)

	for _, g := range groupIDs {
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

	user, _, err := newUser(ScopeEncrypt)
	if err != nil {
		t.Fatal(err)
	}
	user.addGroups(groupIDs...)

	id := "userID"
	sealed, err := user.seal(id, &cryptor)
	if err != nil {
		t.Fatal(err)
	}
	if sealed.UID != id {
		t.Fatalf("Wrong ID: %s != %s", sealed.UID, id)
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

	user, _, err := newUser(ScopeEncrypt)
	if err != nil {
		t.Fatal(err)
	}
	user.addGroups(groupIDs...)

	id := "userID"
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

	user, _, err := newUser(ScopeEncrypt)
	if err != nil {
		t.Fatal(err)
	}
	user.addGroups(groupIDs...)

	id := "userID"
	sealed, err := user.seal(id, &cryptor)
	if err != nil {
		t.Fatal(err)
	}

	if !sealed.verify(&cryptor) {
		t.Fatal("Verification failed")
	}
	sealed.UID = "wrongID"
	if sealed.verify(&cryptor) {
		t.Fatal("Verification should have failed")
	}
}

func TestUserAuth(t *testing.T) {
	user, pwd, err := newUser(ScopeEncrypt)
	if err != nil {
		t.Fatal(err)
	}

	if err := user.authenticate(pwd); err != nil {
		t.Fatal(err)
	}
}

func TestUserAuthWrongPwd(t *testing.T) {
	user, _, err := newUser(ScopeEncrypt)
	if err != nil {
		t.Fatal(err)
	}

	if err := user.authenticate("wrong password"); err == nil {
		t.Fatal("User authentication with a wrong password should fail")
	}
}

func TestChangePwd(t *testing.T) {
	user, pwd, err := newUser(ScopeEncrypt)
	if err != nil {
		t.Fatal(err)
	}

	newPwd, err := user.changePassword(pwd)
	if err != nil {
		t.Fatal(err)
	}

	if err := user.authenticate(newPwd); err != nil {
		t.Fatal(err)
	}
}

func TestChangePwdWrongPwd(t *testing.T) {
	user, _, err := newUser(ScopeEncrypt)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := user.changePassword("wrong password"); err == nil {
		t.Fatal("User must provide his correct password in order to change it")
	}
}

func TestChangePwdAuthWithOldPwd(t *testing.T) {
	user, pwd, err := newUser(ScopeEncrypt)
	if err != nil {
		t.Fatal(err)
	}

	_, err = user.changePassword(pwd)
	if err != nil {
		t.Fatal(err)
	}

	if err := user.authenticate(pwd); err == nil {
		t.Fatal("User authentication with old password after password change should fail")
	}
}
