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
	"testing"

	"reflect"

	"github.com/gofrs/uuid"

	"github.com/cybercryptio/d1-lib/io"
)

func newTestStandalone(t *testing.T) *Standalone {
	ioProvider := io.NewMem()
	standalone, err := NewStandalone(
		StandaloneConfig{
			UEK: []byte{4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4},
			GEK: []byte{5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5},
			TEK: []byte{6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6},
		},
		&ioProvider,
	)
	if err != nil {
		t.Fatal(err)
	}

	return &standalone
}

func manipulateUser(t *testing.T, uid uuid.UUID, standalone *Standalone) {
	userBytes, err := standalone.ioProvider.Get(uid.Bytes(), DataTypeSealedUser)
	if err != nil {
		t.Fatal(err)
	}

	copy(userBytes[:5], make([]byte, 5))
	if err := standalone.ioProvider.Update(uid.Bytes(), DataTypeSealedUser, userBytes); err != nil {
		t.Fatal(err)
	}
}

////////////////////////////////////////////////////////
//                     GetIdentity                    //
////////////////////////////////////////////////////////

// It is verified that GetUserGroups returns all the groups that the user is a member of.
func TestGetIdentity(t *testing.T) {
	standalone := newTestStandalone(t)

	user, pwd, err := standalone.NewUser(ScopeEncrypt)
	if err != nil {
		t.Fatal(err)
	}

	token, _, err := standalone.LoginUser(user, pwd)
	if err != nil {
		t.Fatal(err)
	}

	gid1, err := standalone.NewGroup(token, ScopeEncrypt)
	if err != nil {
		t.Fatal(err)
	}
	gid2, err := standalone.NewGroup(token, ScopeEncrypt)
	if err != nil {
		t.Fatal(err)
	}

	identity, err := standalone.GetIdentity(token)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := identity.GetIDs()[gid1]; !ok {
		t.Fatal("GetUserGroups does not return all groups that the user is member of")
	}
	if _, ok := identity.GetIDs()[gid2]; !ok {
		t.Fatal("GetUserGroups does not return all groups that the user is member of")
	}
}

// It is verified that it is not possible to get user groups from invalid user.
func TestGetIdentityInvalidUser(t *testing.T) {
	standalone := newTestStandalone(t)

	user, pwd, err := standalone.NewUser(ScopeEncrypt)
	if err != nil {
		t.Fatal(err)
	}

	token, _, err := standalone.LoginUser(user, pwd)
	if err != nil {
		t.Fatal(err)
	}

	manipulateUser(t, user, standalone)

	identity, err := standalone.GetIdentity(token)
	if err == nil {
		t.Fatal("Identity fetched for invalid user")
	}
	if !reflect.DeepEqual(identity, Identity{}) {
		t.Fatal("GetIdentity returned a non-empty identity")
	}
}

func TestGetIdentityInvalidToken(t *testing.T) {
	standalone := newTestStandalone(t)

	// Token which isn't base64
	identity, err := standalone.GetIdentity("not valid base64")
	if err == nil {
		t.Fatal("Identity fetched for invalid token")
	}
	if !reflect.DeepEqual(identity, Identity{}) {
		t.Fatal("GetIdentity returned a non-empty identity")
	}

	// Token which is base64 but is not a real token
	identity, err = standalone.GetIdentity("bm90IGEgdmFsaWQgdG9rZW4")
	if err == nil {
		t.Fatal("Identity fetched for invalid token")
	}
	if !reflect.DeepEqual(identity, Identity{}) {
		t.Fatal("GetIdentity returned a non-empty identity")
	}

	// Token which has been altered
	user, pwd, err := standalone.NewUser(ScopeEncrypt)
	if err != nil {
		t.Fatal(err)
	}
	token, _, err := standalone.LoginUser(user, pwd)
	if err != nil {
		t.Fatal(err)
	}
	tokenBytes := []byte(token)
	if tokenBytes[len(tokenBytes)/2] == 'A' {
		tokenBytes[len(tokenBytes)/2] = 'B'
	} else {
		tokenBytes[len(tokenBytes)/2] = 'A'
	}
	token = string(tokenBytes)

	identity, err = standalone.GetIdentity(token)
	if err == nil {
		t.Fatal("Identity fetched for invalid token")
	}
	if !reflect.DeepEqual(identity, Identity{}) {
		t.Fatal("GetIdentity returned a non-empty identity")
	}
}

////////////////////////////////////////////////////////
//                      LoginUser                     //
////////////////////////////////////////////////////////

// Scenario:
// 1) Two users are created, user1 and user2.
// 2) It is verified that only user1 is authenticated with user1's password.
// 3) It is verified that a user is not authenticated with a mistyped password.
func TestLoginUser(t *testing.T) {
	standalone := newTestStandalone(t)

	user1, pwd1, err := standalone.NewUser(ScopeEncrypt)
	if err != nil {
		t.Fatal(err)
	}

	user2, _, err := standalone.NewUser(ScopeEncrypt)
	if err != nil {
		t.Fatal(err)
	}

	if _, _, err = standalone.LoginUser(user1, pwd1); err != nil {
		t.Fatal(err)
	}

	if _, _, err = standalone.LoginUser(user2, pwd1); err == nil {
		t.Fatal("User authenticated with wrong password")
	}

	pwd1Short := pwd1[:len(pwd1)-1]
	pwd1Long := pwd1 + "0"

	if _, _, err = standalone.LoginUser(user1, pwd1Short); err == nil {
		t.Fatal("User authenticated with wrong password")
	}

	if _, _, err = standalone.LoginUser(user1, pwd1Long); err == nil {
		t.Fatal("User authenticated with wrong password")
	}
}

func TestLoginManipulatedUser(t *testing.T) {
	standalone := newTestStandalone(t)

	user, pwd, err := standalone.NewUser(ScopeEncrypt)
	if err != nil {
		t.Fatal(err)
	}

	manipulateUser(t, user, standalone)

	if _, _, err = standalone.LoginUser(user, pwd); err == nil {
		t.Fatal("Invalid user able to log in")
	}
}

////////////////////////////////////////////////////////
//                 ChangeUserPassword                 //
////////////////////////////////////////////////////////

// Verify that after a password change, the new user can be authenticated with the new password and
// can no longer be authenticated with the old one.
func TestChangeUserPassword(t *testing.T) {
	standalone := newTestStandalone(t)

	user, pwd, err := standalone.NewUser(ScopeEncrypt)
	if err != nil {
		t.Fatal(err)
	}

	newPwd, err := standalone.ChangeUserPassword(user, pwd)
	if err != nil {
		t.Fatal(err)
	}

	if _, _, err := standalone.LoginUser(user, newPwd); err != nil {
		t.Fatal(err)
	}

	if _, _, err := standalone.LoginUser(user, pwd); err == nil {
		t.Fatal("User should not be able to authenticate with his old password after it was changed")
	}
}

////////////////////////////////////////////////////////
//        AddUserToGroups/RemoveUserFromGroups        //
////////////////////////////////////////////////////////

// It is verified that a user can add/remove another user to/from groups that he is member of himself.
func TestAddRemoveUserFromGroupsAuthorized(t *testing.T) {
	standalone := newTestStandalone(t)

	user1, pwd1, err := standalone.NewUser(ScopeEncrypt)
	if err != nil {
		t.Fatal(err)
	}
	token1, _, err := standalone.LoginUser(user1, pwd1)
	if err != nil {
		t.Fatal(err)
	}

	user2, pwd2, err := standalone.NewUser(ScopeEncrypt)
	if err != nil {
		t.Fatal(err)
	}
	token2, _, err := standalone.LoginUser(user2, pwd2)
	if err != nil {
		t.Fatal(err)
	}

	gid1, err := standalone.NewGroup(token1, ScopeEncrypt)
	if err != nil {
		t.Fatal(err)
	}
	gid2, err := standalone.NewGroup(token1, ScopeEncrypt)
	if err != nil {
		t.Fatal(err)
	}

	if err = standalone.AddUserToGroups(token1, user2, gid1, gid2); err != nil {
		t.Fatal(err)
	}

	identity, err := standalone.GetIdentity(token2)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := identity.GetIDs()[gid1]; !ok {
		t.Fatal("User not correctly added to group")
	}
	if _, ok := identity.GetIDs()[gid2]; !ok {
		t.Fatal("User not correctly added to group")
	}

	if err = standalone.RemoveUserFromGroups(token2, user2, gid1, gid2); err != nil {
		t.Fatal(err)
	}

	identity, err = standalone.GetIdentity(token2)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := identity.GetIDs()[gid1]; ok {
		t.Fatal("User not correctly removed from group")
	}
	if _, ok := identity.GetIDs()[gid2]; ok {
		t.Fatal("User not correctly removed from group")
	}
}

// It is verified that a user cannot add/remove another user to/from groups that he is not member of himself.
func TestAddRemoveUserFromGroupsUnauthorized(t *testing.T) {
	standalone := newTestStandalone(t)

	user1, pwd1, err := standalone.NewUser(ScopeEncrypt)
	if err != nil {
		t.Fatal(err)
	}
	token1, _, err := standalone.LoginUser(user1, pwd1)
	if err != nil {
		t.Fatal(err)
	}

	user2, pwd2, err := standalone.NewUser(ScopeEncrypt)
	if err != nil {
		t.Fatal(err)
	}
	token2, _, err := standalone.LoginUser(user2, pwd2)
	if err != nil {
		t.Fatal(err)
	}

	gid, err := standalone.NewGroup(token1, ScopeEncrypt)
	if err != nil {
		t.Fatal(err)
	}

	if err = standalone.RemoveUserFromGroups(token2, user1, gid); err == nil {
		t.Fatal("User able to remove another user from groups without being member itself")
	}
	if err = standalone.AddUserToGroups(token2, user2, gid); err == nil {
		t.Fatal("User able to add another user to groups without being member itself")
	}
}

// It is verified that it is not possible to add an invalid user to a group
func TestAddInvalidUserToGroups(t *testing.T) {
	standalone := newTestStandalone(t)

	user1, pwd1, err := standalone.NewUser(ScopeEncrypt)
	if err != nil {
		t.Fatal(err)
	}
	token1, _, err := standalone.LoginUser(user1, pwd1)
	if err != nil {
		t.Fatal(err)
	}

	user2, _, err := standalone.NewUser(ScopeEncrypt)
	if err != nil {
		t.Fatal(err)
	}

	gid, err := standalone.NewGroup(token1, ScopeEncrypt)
	if err != nil {
		t.Fatal(err)
	}

	manipulateUser(t, user2, standalone)

	if err = standalone.AddUserToGroups(token1, user2, gid); err == nil {
		t.Fatal("User able to add an invalid user to group")
	}
}

// It is verified that it is not possible to remove an invalid user from a group
func TestRemoveInvalidUserFromGroups(t *testing.T) {
	standalone := newTestStandalone(t)

	user1, pwd1, err := standalone.NewUser(ScopeEncrypt)
	if err != nil {
		t.Fatal(err)
	}
	token1, _, err := standalone.LoginUser(user1, pwd1)
	if err != nil {
		t.Fatal(err)
	}

	user2, _, err := standalone.NewUser(ScopeEncrypt)
	if err != nil {
		t.Fatal(err)
	}

	gid, err := standalone.NewGroup(token1, ScopeEncrypt)
	if err != nil {
		t.Fatal(err)
	}

	if err = standalone.AddUserToGroups(token1, user2, gid); err != nil {
		t.Fatal(err)
	}

	manipulateUser(t, user2, standalone)

	if err = standalone.RemoveUserFromGroups(token1, user2, gid); err == nil {
		t.Fatal("User able to remove an invalid user from group")
	}
}

// Scenario:
// 1) A user is created.
// 2) The user creates a group.
// 3) It is verified that if the user is removed from the group, then no one can add new members to the group and hence the group is lost.
func TestRemoveAllUsers(t *testing.T) {
	standalone := newTestStandalone(t)

	user1, pwd1, err := standalone.NewUser(ScopeEncrypt)
	if err != nil {
		t.Fatal(err)
	}
	token1, _, err := standalone.LoginUser(user1, pwd1)
	if err != nil {
		t.Fatal(err)
	}

	// User 1 creates a new group and removes themselves form it
	gid, err := standalone.NewGroup(token1, ScopeEncrypt)
	if err != nil {
		t.Fatal(err)
	}
	if err = standalone.RemoveUserFromGroups(token1, user1, gid); err != nil {
		t.Fatal(err)
	}

	user2, _, err := standalone.NewUser(ScopeEncrypt)
	if err != nil {
		t.Fatal(err)
	}

	// user1 cannot add user2 to the group
	if err = standalone.AddUserToGroups(token1, user2, gid); err == nil {
		t.Fatal("User able to add another user to groups without being member itself")
	}
}

////////////////////////////////////////////////////////
//                      NewGroup                      //
////////////////////////////////////////////////////////

// It is verified that an invalid user cannot create a new group.
func TestNewGroupInvalidUser(t *testing.T) {
	standalone := newTestStandalone(t)

	user1, pwd1, err := standalone.NewUser(ScopeEncrypt)
	if err != nil {
		t.Fatal(err)
	}
	token1, _, err := standalone.LoginUser(user1, pwd1)
	if err != nil {
		t.Fatal(err)
	}

	manipulateUser(t, user1, standalone)

	gid, err := standalone.NewGroup(token1, ScopeEncrypt)
	if err == nil {
		t.Fatal("Invalid user able to create a new group")
	}
	if gid != uuid.Nil {
		t.Fatal("NewGroup failed, but returned group ID anyway")
	}
}
