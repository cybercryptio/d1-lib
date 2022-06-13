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

package encryptonize_test

import (
	"fmt"
	"log"

	"github.com/cybercryptio/d1-lib"
	"github.com/cybercryptio/d1-lib/data"
	"github.com/gofrs/uuid"
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
	uid uuid.UUID
	gid uuid.UUID
	oid uuid.UUID
}

// createUserData instantiates a user with its private and public data.
func createUserData(ectnz encryptonize.Encryptonize) UserData {
	uid, gid, token := NewUser()

	privateUserObject := data.Object{
		Plaintext:      []byte("Plaintext"),
		AssociatedData: []byte("AssociatedData"),
	}

	oid, err := ectnz.Encrypt(token, &privateUserObject)
	if err != nil {
		log.Fatalf("Error encrypting object: %v", err)
	}

	err = ectnz.AddGroupsToAccess(token, oid, gid)
	if err != nil {
		log.Fatalf("Error adding group to access list: %v", err)
	}

	return UserData{
		PrivateUserData{token, privateUserObject},
		PublicUserData{uid, gid, oid},
	}
}

// This example demonstrates how to use the Encryptonize® library to enforce discretionary access control for binary data.
func Example_accessControl() {
	// Instantiate the Encryptonize® library with the given keys.
	ectnz, err := encryptonize.New(&keyProvider, &ioProvider, &idProvider)
	if err != nil {
		log.Fatalf("Error instantiating Encryptonize: %v", err)
	}

	// Create three users with their data.
	alice := createUserData(ectnz)
	bob := createUserData(ectnz)
	charlie := createUserData(ectnz)

	// charlie wants to share her data with bob.
	err = ectnz.AddGroupsToAccess(charlie.private.token, charlie.public.oid, bob.public.uid)
	if err != nil {
		log.Fatalf("Error adding group to access: %v", err)
	}

	// bob can now decrypt charlie's encrypted data.
	charliesDecryptedData, err := ectnz.Decrypt(bob.private.token, charlie.public.oid)
	if err != nil {
		log.Fatalf("Error decrypting object: %v", err)
	}
	fmt.Printf("%s %s\n", charliesDecryptedData.Plaintext, charliesDecryptedData.AssociatedData)

	// alice wants to form a group with charlie so that all of his previously encrypted data can be decrypted by charlie.
	err = idProvider.AddUserToGroups(alice.private.token, charlie.public.uid, alice.public.gid)
	if err != nil {
		log.Fatalf("Error adding user to group: %v", err)
	}

	// charlie can now decrypt all of alice's previously encrypted data.
	alicesDecryptedData, err := ectnz.Decrypt(charlie.private.token, alice.public.oid)
	if err != nil {
		log.Fatalf("Error decrypting object: %v", err)
	}
	fmt.Printf("%s %s\n", alicesDecryptedData.Plaintext, alicesDecryptedData.AssociatedData)

	// Output:
	// Plaintext AssociatedData
	// Plaintext AssociatedData
}
