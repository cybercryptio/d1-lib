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

	data1, err := rand.GetBytes(1)
	if err != nil {
		t.Fatalf("Random failed: %v", err)
	}

	data2, err := rand.GetBytes(2)
	if err != nil {
		t.Fatalf("Random failed: %v", err)
	}

	tag1, err := tagger.Tag(data1)
	if err != nil {
		t.Fatalf("Tag failed: %v", err)
	}

	tag2, err := tagger.Tag(data2)
	if err != nil {
		t.Fatalf("Tag failed: %v", err)
	}

	tag3, err := tagger.Tag(data1)
	if err != nil {
		t.Fatalf("Tag failed: %v", err)
	}
	if bytes.Equal(tag1, tag2) {
		t.Fatal("Tagger returns identical output from instances with different data")
	}
	if !bytes.Equal(tag1, tag3) {
		t.Fatal("Tagger returns different output from instances with identical data")
	}
}

func TestTaggerInvalidKeyLength(t *testing.T) {
	rand := &NativeRandom{}
	key, err := rand.GetBytes(31)
	if err != nil {
		t.Fatalf("Random failed: %v", err)
	}

	if _, err = NewKMAC256Tagger(key); err == nil {
		t.Fatal("Invalid key length accepted")
	}
}
