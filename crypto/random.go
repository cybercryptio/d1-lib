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
	"crypto/rand"
	"errors"
)

// NativeRandom implements RandomInterface.
type NativeRandom struct {
}

func (r *NativeRandom) GetBytes(n uint) ([]byte, error) {
	bytes := make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		return nil, err
	}
	return bytes, nil
}

// MockRandom is a mock implementation of RandomInterface for testing.
type MockRandom struct {
	bytes []byte
}

func (r *MockRandom) GetBytes(n uint) ([]byte, error) {
	if int(n) > len(r.bytes) {
		return nil, errors.New("No more random bytes")
	}
	var out []byte
	out, r.bytes = r.bytes[:n], r.bytes[n:]
	return out, nil
}
