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

	"github.com/cyber-crypt-com/encryptonize-lib"
)

// The UserData struct models the data of a user. It contains both private data that should be kept confidential and public data that can be shared
// with other users, being protected cryptographically.
type UserData struct {
	private PrivateUserData
	public  PublicUserData
}

type PrivateUserData struct {
	user     encryptonize.SealedUser
	password string
	data     encryptonize.Object
}

type PublicUserData struct {
	group               encryptonize.SealedGroup
	encryptedData       encryptonize.SealedObject
	encryptedDataAccess encryptonize.SealedAccess
}

// createUser instantiates a user with its private and public data.
func createUser(ectnz encryptonize.Encryptonize) UserData {
	user, group, password, err := ectnz.NewUser(nil)
	if err != nil {
		log.Fatalf("Error creating Encryptonize user: %v", err)
	}

	privateUserObject := encryptonize.Object{
		Plaintext:      []byte("Plaintext"),
		AssociatedData: []byte("AssociatedData"),
	}

	encryptedUserObject, encryptedObjectAccess, err := ectnz.Encrypt(&user, &privateUserObject)
	if err != nil {
		log.Fatalf("Error encrypting object: %v", err)
	}

	return UserData{
		PrivateUserData{user, password, privateUserObject},
		PublicUserData{group, encryptedUserObject, encryptedObjectAccess},
	}
}

// This example demonstrates how to use the Encryptonize® library to enforce discretionary access control for binary data.
func Example_accessControl() {
	// Instantiate the Encryptonize® library with the given keys.
	ectnz, err := encryptonize.New(keys)
	if err != nil {
		log.Fatalf("Error instantiating Encryptonize: %v", err)
	}

	// Create three users with their data.
	user1 := createUser(ectnz)
	user2 := createUser(ectnz)
	user3 := createUser(ectnz)

	// user3 wants to share her data with user2.
	err = ectnz.AddGroupsToAccess(&user3.private.user, &user3.public.encryptedDataAccess, &user2.public.group)
	if err != nil {
		log.Fatalf("Error adding group to access: %v", err)
	}

	// user2 can now decrypt user3's encrypted data.
	user3sDecryptedData, err := ectnz.Decrypt(&user2.private.user, &user3.public.encryptedData, &user3.public.encryptedDataAccess)
	if err != nil {
		log.Fatalf("Error decrypting object: %v", err)
	}
	fmt.Printf("%s %s\n", user3sDecryptedData.Plaintext, user3sDecryptedData.AssociatedData)

	// user1 wants to form a group with user3 so that all of his previously encrypted data can be decrypted by user3.
	err = ectnz.AddUserToGroups(&user1.private.user, &user3.private.user, &user1.public.group)
	if err != nil {
		log.Fatalf("Error adding user to group: %v", err)
	}

	// user3 can now decrypt all of user1's previously encrypted data.
	user1sDecryptedData, err := ectnz.Decrypt(&user3.private.user, &user1.public.encryptedData, &user1.public.encryptedDataAccess)
	if err != nil {
		log.Fatalf("Error decrypting object: %v", err)
	}
	fmt.Printf("%s %s\n", user1sDecryptedData.Plaintext, user1sDecryptedData.AssociatedData)

	// Output:
	// Plaintext AssociatedData
	// Plaintext AssociatedData
}
