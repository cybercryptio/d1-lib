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

func ExampleEncryptonize_CreateToken() {
	// Instantiate the Encryptonize® library with the given keys.
	ectnz, err := encryptonize.New(&keyProvider, &ioProvider)
	if err != nil {
		log.Fatalf("Error instantiating Encryptonize: %v", err)
	}

	// Create a token with encrypted contents and default expiry time.
	token, err := ectnz.CreateToken([]byte("token contents"))
	if err != nil {
		log.Fatalf("Error creating token: %v", err)
	}

	// Validate the token and fetch its decrypted contents. This call will fail if the token has expired or has been tampered with.
	tokenContents, err := ectnz.GetTokenContents(&token)
	if err != nil {
		log.Fatalf("Invalid token: %v", err)
	}
	fmt.Printf("%s", tokenContents)

	// Output: token contents
}
