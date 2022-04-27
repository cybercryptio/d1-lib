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
	"encoding/gob"
)

const tagSize = 32

// Tagger implements the TaggerInterface
type Tagger struct {
	Key []byte
}

// NewKMAC256Tagger creates a Tagger which uses KMAC256.
func NewKMAC256Tagger(key []byte) (Tagger, error) {
	return Tagger{Key: key}, nil
}

func (t *Tagger) Tag(data interface{}) ([]byte, error) {
	var dataBuffer bytes.Buffer
	enc := gob.NewEncoder(&dataBuffer)
	if err := enc.Encode(data); err != nil {
		return nil, err
	}

	mac := NewKMAC256(t.Key, tagSize, dataBuffer.Bytes())
	macSum := mac.Sum(nil)

	return macSum, nil
}
