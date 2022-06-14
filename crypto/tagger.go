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
	"bytes"
	"encoding/gob"
)

const TagLength = 32
const TaggerKeyLength = 32

// Tagger implements the TaggerInterface
type Tagger struct {
	Key []byte
}

// NewKMAC256Tagger creates a Tagger which uses KMAC256.
func NewKMAC256Tagger(key []byte) (Tagger, error) {
	if len(key) != TaggerKeyLength {
		return Tagger{}, ErrInvalidKeyLength
	}

	return Tagger{Key: key}, nil
}

func (t *Tagger) Tag(data interface{}) ([]byte, error) {
	var dataBuffer bytes.Buffer
	enc := gob.NewEncoder(&dataBuffer)
	if err := enc.Encode(data); err != nil {
		return nil, err
	}

	mac := NewKMAC256(t.Key, TagLength, dataBuffer.Bytes())
	macSum := mac.Sum(nil)

	return macSum, nil
}
