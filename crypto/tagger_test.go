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

func TestTagger(t *testing.T) {
	rand := &NativeRandom{}
	key, err := rand.GetBytes(32)
	if err != nil {
		t.Fatalf("Random failed: %v", err)
	}

	tagger, err := NewKMAC256Tagger(key)
	if err != nil {
		t.Fatalf("NewKMAC256Tagger failed: %v", err)
	}

	data1, err := rand.GetBytes(uint(1))
	if err != nil {
		t.Fatalf("Random failed: %v", err)
	}

	data2, err := rand.GetBytes(uint(2))
	if err != nil {
		t.Fatalf("Random failed: %v", err)
	}

	mac1, err := tagger.Tag(data1)
	if err != nil {
		t.Fatalf("Tag failed: %v", err)
	}

	mac2, err := tagger.Tag(data2)
	if err != nil {
		t.Fatalf("Tag failed: %v", err)
	}

	mac3, err := tagger.Tag(data1)
	if err != nil {
		t.Fatalf("Tag failed: %v", err)
	}
	if bytes.Equal(mac1, mac2) {
		t.Fatal("Tagger returns identical output from instances with different data")
	}
	if !bytes.Equal(mac1, mac3) {
		t.Fatal("Tagger returns different output from instances with identical input")
	}
}
