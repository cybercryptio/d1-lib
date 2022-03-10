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
