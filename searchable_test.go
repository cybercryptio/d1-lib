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
	"reflect"
	"testing"

	"github.com/cyber-crypt-com/encryptonize-lib/crypto"
)

func TestNewSearchable(t *testing.T) {
	searchable := NewSearchable()
	if len(searchable.mapping) != 0 {
		t.Fatal("Index non-empty at initialization.")
	}
}

func TestAdd(t *testing.T) {
	searchable := NewSearchable()

	rand := &crypto.NativeRandom{}
	masterKey, _ := rand.GetBytes(32)

	keyword := "first keyword"
	id := "first id"

	if err := searchable.Add(masterKey, keyword, id); err != nil {
		t.Fatal(err)
	}
	if len(searchable.mapping) != 1 {
		t.Fatal("Keyword/id pair not correctly added to mapping")
	}
}

func TestAddMultiple(t *testing.T) {
	searchable := NewSearchable()

	rand := &crypto.NativeRandom{}
	masterKey, err := rand.GetBytes(32)
	if err != nil {
		t.Fatalf("Random failed: %v", err)
	}

	keywords := [2]string{"first keyword", "second keyword"}
	ids := [2]string{"first id", "second id"}

	for i := 0; i < len(keywords); i++ {
		for j := 0; j < len(ids); j++ {
			err = searchable.Add(masterKey, keywords[i], ids[j])
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	if len(searchable.mapping) != len(keywords)*len(ids) {
		t.Fatal("Multiple keyword/id pairs not correctly added to mapping")
	}
}

func TestSearch(t *testing.T) {
	searchable := NewSearchable()

	rand := &crypto.NativeRandom{}
	masterKey, err := rand.GetBytes(32)
	if err != nil {
		t.Fatalf("Random failed: %v", err)
	}

	keyword := "first keyword"
	ids := []string{"id1", "id2", "id3", "id4", "id5"}

	for i := 0; i < len(ids); i++ {
		err = searchable.Add(masterKey, keyword, ids[i])
		if err != nil {
			t.Fatal(err)
		}

		IDs, err := searchable.Search(masterKey, keyword)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(IDs[:i], ids[:i]) {
			t.Fatal("Search returned wrong decrypted IDs.")
		}
	}
}

func TestSearchWrongMasterkey(t *testing.T) {
	searchable := NewSearchable()

	rand := &crypto.NativeRandom{}
	masterKey1, err := rand.GetBytes(32)
	if err != nil {
		t.Fatalf("Random failed: %v", err)
	}
	masterKey2, err := rand.GetBytes(32)
	if err != nil {
		t.Fatalf("Random failed: %v", err)
	}

	keyword := "first keyword"
	id := "first id"

	err = searchable.Add(masterKey1, keyword, id)
	if err != nil {
		t.Fatal(err)
	}

	IDs, err := searchable.Search(masterKey2, keyword)
	if err != nil {
		t.Fatal(err)
	}
	if len(IDs) != 0 {
		t.Fatal("Search returned decrypted IDs when given wrong masterkey")
	}
}

func TestSearchWrongKeyword(t *testing.T) {
	searchable := NewSearchable()

	rand := &crypto.NativeRandom{}
	masterKey, err := rand.GetBytes(32)
	if err != nil {
		t.Fatalf("Random failed: %v", err)
	}

	keyword := "first keyword"
	id := "first id"

	err = searchable.Add(masterKey, keyword, id)
	if err != nil {
		t.Fatal(err)
	}

	keywordShort := "first keywor"
	keywordLong := "first keywordd"

	IDs, err := searchable.Search(masterKey, keywordShort)
	if err != nil {
		t.Fatal(err)
	}
	if len(IDs) != 0 {
		t.Fatal("Search returned decrypted IDs when given wrong keyword")
	}

	IDs, err = searchable.Search(masterKey, keywordLong)
	if err != nil {
		t.Fatal(err)
	}
	if len(IDs) != 0 {
		t.Fatal("Search returned decrypted IDs when given wrong keyword")
	}
}

func TestCount(t *testing.T) {
	searchable := NewSearchable()

	rand := &crypto.NativeRandom{}
	masterKey, err := rand.GetBytes(32)
	if err != nil {
		t.Fatalf("Random failed: %v", err)
	}

	keywords := [3]string{"keyword1", "keyword2", "keyword3"}
	ids := [5]string{"id1", "id2", "id3", "id4", "id5"}

	for i := 0; i < len(keywords); i++ {
		count, err := searchable.count(masterKey, keywords[i])
		if err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatal("Count returned wrong count.")
		}
	}

	for i := 0; i < len(keywords); i++ {
		for j := 0; j < len(ids); j++ {
			err = searchable.Add(masterKey, keywords[i], ids[j])
			if err != nil {
				t.Fatal(err)
			}

			count, err := searchable.count(masterKey, keywords[i])
			if err != nil {
				t.Fatal(err)
			}
			if count != uint64(j+1) {
				t.Fatal("Count returned wrong count.")
			}
		}
	}
}

func TestCountWrongMasterkey(t *testing.T) {
	searchable := NewSearchable()

	rand := &crypto.NativeRandom{}
	masterKey1, err := rand.GetBytes(32)
	if err != nil {
		t.Fatalf("Random failed: %v", err)
	}
	masterKey2, err := rand.GetBytes(32)
	if err != nil {
		t.Fatalf("Random failed: %v", err)
	}

	keyword := "first keyword"
	id := "first id"

	err = searchable.Add(masterKey1, keyword, id)
	if err != nil {
		t.Fatal(err)
	}

	count, err := searchable.count(masterKey2, keyword)
	if err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("Count returned wrong count when given wrong masterkey.")
	}
}

func TestCountWrongKeyword(t *testing.T) {
	searchable := NewSearchable()

	rand := &crypto.NativeRandom{}
	masterKey, err := rand.GetBytes(32)
	if err != nil {
		t.Fatalf("Random failed: %v", err)
	}

	keyword := "first keyword"
	id := "first id"

	err = searchable.Add(masterKey, keyword, id)
	if err != nil {
		t.Fatal(err)
	}

	keywordShort := "first keywor"
	keywordLong := "first keywordd"

	count, err := searchable.count(masterKey, keywordShort)
	if err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("Count returned wrong count when given wrong keyword.")
	}

	count, err = searchable.count(masterKey, keywordLong)
	if err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("Count returned wrong count when given wrong keyword.")
	}
}
