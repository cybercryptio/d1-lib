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

package crypto

import (
	"bytes"
	"testing"
)

func TestRandom(t *testing.T) {
	rand := &NativeRandom{}

	bytes1, err := rand.GetBytes(128)
	if err != nil {
		t.Fatal(err)
	}
	bytes2, err := rand.GetBytes(128)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(bytes1, bytes2) {
		t.Fatal("Expected random bytes")
	}
}
