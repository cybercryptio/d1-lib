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

// Macor implements the MacorInterface
type Macor struct {
}

// NewKMAC256Macor creates a Macor which uses KMAC256.
func NewKMAC256Macor() (Macor, error) {
	return Macor{}, nil
}

func (m *Macor) MAC(key []byte, tagSize int, customizationString interface{}) ([]byte, error) {
	var customizationStringBuffer bytes.Buffer
	enc := gob.NewEncoder(&customizationStringBuffer)
	if err := enc.Encode(customizationString); err != nil {
		return nil, err
	}

	mac := NewKMAC256(key, tagSize, customizationStringBuffer.Bytes())
	macSum := mac.Sum(nil)

	return macSum, nil
}
