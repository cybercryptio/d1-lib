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

package encryptonize_test

import (
	"fmt"
	"log"

	"github.com/cybercryptio/d1-lib"
)

func ExampleEncryptonize_CreateToken() {
	// Instantiate the Encryptonize® library with the given keys.
	ectnz, err := encryptonize.New(&keyProvider, &ioProvider, &idProvider)
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
