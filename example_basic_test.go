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
	"fmt"
	"log"

	d1lib "github.com/cybercryptio/d1-lib"
	"github.com/cybercryptio/d1-lib/data"
	"github.com/cybercryptio/d1-lib/id"
	"github.com/cybercryptio/d1-lib/io"
	"github.com/cybercryptio/d1-lib/key"
)

// These are insecure keys used only for demonstration purposes.
var keyProvider = key.NewStatic(key.Keys{
	KEK: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	AEK: []byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
	TEK: []byte{2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2},
	IEK: []byte{3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3},
})

// Store encrypted data in memory.
var ioProvider = io.NewMem()

var idProvider, _ = id.NewStandalone(
	id.StandaloneConfig{
		UEK: []byte{4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4},
		GEK: []byte{5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5},
		TEK: []byte{6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6},
	},
	&ioProvider,
)

func NewUser() (string, string, string) {
	uid, password, err := (&idProvider).NewUser(id.ScopeAll)
	if err != nil {
		log.Fatalf("Error creating user: %v", err)
	}

	token, _, err := (&idProvider).LoginUser(uid, password)
	if err != nil {
		log.Fatalf("Error logging in user: %v", err)
	}

	gid, err := idProvider.NewGroup(token, id.ScopeAll)
	if err != nil {
		log.Fatalf("Error creating group: %v", err)
	}

	err = idProvider.AddUserToGroups(token, uid, gid)
	if err != nil {
		log.Fatalf("Error adding user to group: %v", err)
	}

	return uid, gid, token
}

// This is a basic example demonstrating how to use the D1 library to encrypt and decrypt binary data.
func Example_basicEncryptDecrypt() {
	// Instantiate the D1 library with the given keys.
	d1, err := d1lib.New(&keyProvider, &ioProvider, &idProvider)
	if err != nil {
		log.Fatalf("Error instantiating D1: %v", err)
	}

	// Create a basic user.
	_, _, token := NewUser()

	// A simple binary object with associated data.
	binaryObject := data.Object{
		Plaintext:      []byte("Plaintext"),
		AssociatedData: []byte("AssociatedData"),
	}

	// Encrypt the object and get the resulting object ID. By default, only the default group of the
	// user who encrypted the object is allowed to decrypt the object.
	oid, err := d1.Encrypt(token, &binaryObject)
	if err != nil {
		log.Fatalf("Error encrypting object: %v", err)
	}

	// Decrypt the object using the given user as the authorizer.
	decryptedObject, err := d1.Decrypt(token, oid)
	if err != nil {
		log.Fatalf("Error decrypting object: %v", err)
	}

	fmt.Printf("Decrypted object plaintext: %s\nDecrypted object associated data: %s\n", decryptedObject.Plaintext, decryptedObject.AssociatedData)

	// Output:
	// Decrypted object plaintext: Plaintext
	// Decrypted object associated data: AssociatedData
}
