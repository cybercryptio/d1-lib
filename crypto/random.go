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
	Bytes []byte
}

func (r *MockRandom) GetBytes(n uint) ([]byte, error) {
	if int(n) > len(r.Bytes) {
		return nil, errors.New("No more random bytes")
	}
	var out []byte
	out, r.Bytes = r.Bytes[:n], r.Bytes[n:]
	return out, nil
}
