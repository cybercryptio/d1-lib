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

package d1_test

import (
	"context"
	"fmt"
	"log"

	"github.com/gofrs/uuid"

	d1lib "github.com/cybercryptio/d1-lib/v2"
	"github.com/cybercryptio/d1-lib/v2/data"
)

// The UserData struct models the data of a user. It contains both private data that should be kept confidential and public data that can be shared
// with other users, being protected cryptographically.
type UserData struct {
	private PrivateUserData
	public  PublicUserData
}

type PrivateUserData struct {
	token string
	data  data.Object
}

type PublicUserData struct {
	uid string
	gid string
	oid uuid.UUID
}

// createUserData instantiates a user with its private and public data.
func createUserData(ctx context.Context, d1 d1lib.D1) UserData {
	uid, gid, token := NewUser(ctx)

	privateUserObject := data.Object{
		Plaintext:      []byte("Plaintext"),
		AssociatedData: []byte("AssociatedData"),
	}

	oid, err := d1.Encrypt(ctx, token, &privateUserObject)
	if err != nil {
		log.Fatalf("Error encrypting object: %v", err)
	}

	err = d1.AddGroupsToAccess(ctx, token, oid, gid)
	if err != nil {
		log.Fatalf("Error adding group to access list: %v", err)
	}

	return UserData{
		PrivateUserData{token, privateUserObject},
		PublicUserData{uid, gid, oid},
	}
}

// This example demonstrates how to use the D1 library to enforce discretionary access control for binary data.
func Example_accessControl() {
	ctx := context.Background()

	// Instantiate the D1 library with the given keys.
	d1, err := d1lib.New(ctx, &keyProvider, &ioProvider, &idProvider)
	if err != nil {
		log.Fatalf("Error instantiating D1: %v", err)
	}

	// Create three users with their data.
	alice := createUserData(ctx, d1)
	bob := createUserData(ctx, d1)
	charlie := createUserData(ctx, d1)

	// charlie wants to share her data with bob.
	err = d1.AddGroupsToAccess(ctx, charlie.private.token, charlie.public.oid, bob.public.uid)
	if err != nil {
		log.Fatalf("Error adding group to access: %v", err)
	}

	// bob can now decrypt charlie's encrypted data.
	charliesDecryptedData, err := d1.Decrypt(ctx, bob.private.token, charlie.public.oid)
	if err != nil {
		log.Fatalf("Error decrypting object: %v", err)
	}
	fmt.Printf("%s %s\n", charliesDecryptedData.Plaintext, charliesDecryptedData.AssociatedData)

	// alice wants to form a group with charlie so that all of his previously encrypted data can be decrypted by charlie.
	err = idProvider.AddUserToGroups(ctx, alice.private.token, charlie.public.uid, alice.public.gid)
	if err != nil {
		log.Fatalf("Error adding user to group: %v", err)
	}

	// charlie can now decrypt all of alice's previously encrypted data.
	alicesDecryptedData, err := d1.Decrypt(ctx, charlie.private.token, alice.public.oid)
	if err != nil {
		log.Fatalf("Error decrypting object: %v", err)
	}
	fmt.Printf("%s %s\n", alicesDecryptedData.Plaintext, alicesDecryptedData.AssociatedData)

	// Output:
	// Plaintext AssociatedData
	// Plaintext AssociatedData
}
