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
	"github.com/cybercryptio/d1-lib/io"
	"github.com/cybercryptio/d1-lib/key"
)

// These are insecure keys used only for demonstration purposes.
var keyProvider = key.NewStatic(key.Keys{
	KEK: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	AEK: []byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
	TEK: []byte{2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2},
	UEK: []byte{3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3},
	GEK: []byte{4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4},
	IEK: []byte{5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5},
})

// Store encrypted data in memory.
var ioProvider = io.NewMem()

// This is a basic example demonstrating how to use the Encryptonize® library to encrypt and decrypt binary data.
func Example_basicEncryptDecrypt() {
	// Instantiate the Encryptonize® library with the given keys.
	ectnz, err := encryptonize.New(&keyProvider, &ioProvider)
	if err != nil {
		log.Fatalf("Error instantiating Encryptonize: %v", err)
	}

	// Create a basic user.
	user, _, _, err := ectnz.NewUser(nil)
	if err != nil {
		log.Fatalf("Error creating Encryptonize user: %v", err)
	}

	// A simple binary object with associated data.
	binaryObject := data.Object{
		Plaintext:      []byte("Plaintext"),
		AssociatedData: []byte("AssociatedData"),
	}

	// Encrypt the object and get the resulting object ID. By default, only the default group of the
	// user who encrypted the object is allowed to decrypt the object.
	oid, err := ectnz.Encrypt(&user, &binaryObject)
	if err != nil {
		log.Fatalf("Error encrypting object: %v", err)
	}

	// Decrypt the object using the given user as the authorizer.
	decryptedObject, err := ectnz.Decrypt(&user, oid)
	if err != nil {
		log.Fatalf("Error decrypting object: %v", err)
	}

	fmt.Printf("Decrypted object plaintext: %s\nDecrypted object associated data: %s\n", decryptedObject.Plaintext, decryptedObject.AssociatedData)

	// Output:
	// Decrypted object plaintext: Plaintext
	// Decrypted object associated data: AssociatedData
}
