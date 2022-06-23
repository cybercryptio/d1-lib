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

package index

import (
	"reflect"
	"testing"

	"github.com/gofrs/uuid"

	"github.com/cybercryptio/d1-lib/crypto"
	"github.com/cybercryptio/d1-lib/id"
	"github.com/cybercryptio/d1-lib/io"
	"github.com/cybercryptio/d1-lib/key"
)

func newTestSecureIndex(t *testing.T) SecureIndex {
	keyProvider := key.NewStatic(key.Keys{
		KEK: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		AEK: []byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
		TEK: []byte{2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2},
		IEK: []byte{3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3},
	})
	ioProvider := io.NewMem()
	idProvider, err := id.NewStandalone(
		id.StandaloneConfig{
			UEK: []byte{4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4},
			GEK: []byte{5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5},
			TEK: []byte{6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6},
		},
		&ioProvider,
	)
	if err != nil {
		t.Fatal(err)
	}

	secureIndex, err := NewSecureIndex(&keyProvider, &ioProvider, &idProvider)
	if err != nil {
		t.Fatal(err)
	}
	return secureIndex
}

func newTestUser(t *testing.T, secureIndex *SecureIndex, scopes ...id.Scope) (uuid.UUID, string) {
	idProvider := secureIndex.idProvider.(*id.Standalone)

	id, password, err := idProvider.NewUser(scopes...)
	if err != nil {
		t.Fatal(err)
	}

	token, _, err := idProvider.LoginUser(id, password)
	if err != nil {
		t.Fatal(err)
	}

	return id, token
}

func TestAdd(t *testing.T) {
	index := newTestSecureIndex(t)
	_, token := newTestUser(t, &index, id.ScopeIndex)

	keyword := "first keyword"
	docID := "first id"

	if err := index.Add(index.indexKey, token, keyword, docID); err != nil {
		t.Fatal(err)
	}
	size, err := index.Size(token)
	if err != nil {
		t.Fatal(err)
	}
	if size != 1 {
		t.Fatal("Keyword/id pair not correctly added to mapping")
	}
}

func TestAddMultiple(t *testing.T) {
	index := newTestSecureIndex(t)
	_, token := newTestUser(t, &index, id.ScopeIndex)

	rand := &crypto.NativeRandom{}
	masterKey, _ := rand.GetBytes(32)

	keywords := [2]string{"first keyword", "second keyword"}
	ids := [2]string{"first id", "second id"}

	for i := 0; i < len(keywords); i++ {
		for j := 0; j < len(ids); j++ {
			if err := index.Add(masterKey, token, keywords[i], ids[j]); err != nil {
				t.Fatal(err)
			}
		}
	}
	size, err := index.Size(token)
	if err != nil {
		t.Fatal(err)
	}
	if size != len(keywords)*len(ids) {
		t.Fatal("Multiple keyword/id pairs not correctly added to mapping")
	}
}

func TestAddInvalidMasterkey(t *testing.T) {
	index := newTestSecureIndex(t)
	_, token := newTestUser(t, &index, id.ScopeIndex)

	rand := &crypto.NativeRandom{}
	masterKeyShort, _ := rand.GetBytes(31)
	masterKeyLong, _ := rand.GetBytes(33)

	keyword := "first keyword"
	id := "first id"

	if err := index.Add(masterKeyShort, token, keyword, id); err == nil {
		t.Fatal(ErrInvalidMasterKeyLength)
	}
	if err := index.Add(masterKeyLong, token, keyword, id); err == nil {
		t.Fatal(ErrInvalidMasterKeyLength)
	}
}

func TestSearch(t *testing.T) {
	index := newTestSecureIndex(t)
	_, token := newTestUser(t, &index, id.ScopeIndex)

	rand := &crypto.NativeRandom{}
	masterKey, _ := rand.GetBytes(32)

	keyword := "first keyword"
	ids := []string{"id1", "id2", "id3", "id4", "id5"}

	for i := 0; i < len(ids); i++ {
		if err := index.Add(masterKey, token, keyword, ids[i]); err != nil {
			t.Fatal(err)
		}

		IDs, err := index.Search(masterKey, token, keyword)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(IDs[:i], ids[:i]) {
			t.Fatal("Search returned wrong decrypted IDs.")
		}
	}
}

func TestSearchWrongMasterkey(t *testing.T) {
	index := newTestSecureIndex(t)
	_, token := newTestUser(t, &index, id.ScopeIndex)

	rand := &crypto.NativeRandom{}
	masterKey1, _ := rand.GetBytes(32)
	masterKey2, _ := rand.GetBytes(32)

	keyword := "first keyword"
	id := "first id"

	if err := index.Add(masterKey1, token, keyword, id); err != nil {
		t.Fatal(err)
	}

	IDs, err := index.Search(masterKey2, token, keyword)
	if err != nil {
		t.Fatal(err)
	}
	if len(IDs) != 0 {
		t.Fatal("Search returned decrypted IDs when given wrong masterkey")
	}
}

func TestSearchWrongKeyword(t *testing.T) {
	index := newTestSecureIndex(t)
	_, token := newTestUser(t, &index, id.ScopeIndex)

	rand := &crypto.NativeRandom{}
	masterKey, _ := rand.GetBytes(32)

	keyword := "first keyword"
	id := "first id"

	if err := index.Add(masterKey, token, keyword, id); err != nil {
		t.Fatal(err)
	}

	keywordShort := "first keywor"
	keywordLong := "first keywordd"

	IDs, err := index.Search(masterKey, token, keywordShort)
	if err != nil {
		t.Fatal(err)
	}
	if len(IDs) != 0 {
		t.Fatal("Search returned decrypted IDs when given wrong keyword")
	}

	IDs, err = index.Search(masterKey, token, keywordLong)
	if err != nil {
		t.Fatal(err)
	}
	if len(IDs) != 0 {
		t.Fatal("Search returned decrypted IDs when given wrong keyword")
	}
}

func TestCount(t *testing.T) {
	index := newTestSecureIndex(t)
	_, token := newTestUser(t, &index, id.ScopeIndex)

	rand := &crypto.NativeRandom{}
	masterKey, _ := rand.GetBytes(32)

	keywords := [3]string{"keyword1", "keyword2", "keyword3"}
	ids := [5]string{"id1", "id2", "id3", "id4", "id5"}

	for i := 0; i < len(keywords); i++ {
		count, err := index.count(masterKey, keywords[i])
		if err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatal("Count returned wrong count.")
		}
	}

	for i := 0; i < len(keywords); i++ {
		for j := 0; j < len(ids); j++ {
			if err := index.Add(masterKey, token, keywords[i], ids[j]); err != nil {
				t.Fatal(err)
			}

			count, err := index.count(masterKey, keywords[i])
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
	index := newTestSecureIndex(t)
	_, token := newTestUser(t, &index, id.ScopeIndex)

	rand := &crypto.NativeRandom{}
	masterKey1, _ := rand.GetBytes(32)
	masterKey2, _ := rand.GetBytes(32)

	keyword := "first keyword"
	id := "first id"

	if err := index.Add(masterKey1, token, keyword, id); err != nil {
		t.Fatal(err)
	}

	count, err := index.count(masterKey2, keyword)
	if err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("Count returned wrong count when given wrong masterkey.")
	}
}

func TestCountWrongKeyword(t *testing.T) {
	index := newTestSecureIndex(t)
	_, token := newTestUser(t, &index, id.ScopeIndex)

	rand := &crypto.NativeRandom{}
	masterKey, _ := rand.GetBytes(32)

	keyword := "first keyword"
	id := "first id"

	if err := index.Add(masterKey, token, keyword, id); err != nil {
		t.Fatal(err)
	}

	keywordShort := "first keywor"
	keywordLong := "first keywordd"

	count, err := index.count(masterKey, keywordShort)
	if err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("Count returned wrong count when given wrong keyword.")
	}

	count, err = index.count(masterKey, keywordLong)
	if err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("Count returned wrong count when given wrong keyword.")
	}
}

func TestDelete(t *testing.T) {
	index := newTestSecureIndex(t)
	_, token := newTestUser(t, &index, id.ScopeIndex)

	rand := &crypto.NativeRandom{}
	masterKey, _ := rand.GetBytes(32)

	keyword := "first keyword"
	id := "first id"

	if err := index.Add(masterKey, token, keyword, id); err != nil {
		t.Fatal(err)
	}

	if err := index.Delete(masterKey, token, keyword, id); err != nil {
		t.Fatal(err)
	}

	IDs, err := index.Search(masterKey, token, keyword)
	if err != nil {
		t.Fatal(err)
	}
	if len(IDs) != 0 {
		t.Fatal("Search returned decrypted ID for which the keyword/ID pair has been deleted.")
	}
}

func TestDeleteAdd(t *testing.T) {
	index := newTestSecureIndex(t)
	_, token := newTestUser(t, &index, id.ScopeIndex)

	rand := &crypto.NativeRandom{}
	masterKey, _ := rand.GetBytes(32)

	keyword := "first keyword"
	id := "first id"

	if err := index.Add(masterKey, token, keyword, id); err != nil {
		t.Fatal(err)
	}

	if err := index.Delete(masterKey, token, keyword, id); err != nil {
		t.Fatal(err)
	}

	if err := index.Add(masterKey, token, keyword, id); err != nil {
		t.Fatal(err)
	}

	IDs, err := index.Search(masterKey, token, keyword)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(IDs[0], id) {
		t.Fatal("Keyword/ID pair not correctly added after it has been deleted.")
	}
}

func TestDeleteAddDelete(t *testing.T) {
	index := newTestSecureIndex(t)
	_, token := newTestUser(t, &index, id.ScopeIndex)

	rand := &crypto.NativeRandom{}
	masterKey, _ := rand.GetBytes(32)

	keyword := "first keyword"
	id := "first id"

	if err := index.Add(masterKey, token, keyword, id); err != nil {
		t.Fatal(err)
	}

	if err := index.Delete(masterKey, token, keyword, id); err != nil {
		t.Fatal(err)
	}

	if err := index.Add(masterKey, token, keyword, id); err != nil {
		t.Fatal(err)
	}

	if err := index.Delete(masterKey, token, keyword, id); err != nil {
		t.Fatal(err)
	}

	IDs, err := index.Search(masterKey, token, keyword)
	if err != nil {
		t.Fatal(err)
	}
	if len(IDs) != 0 {
		t.Fatal("Keyword/ID pair not correctly deleted after it has been deleted and then added.")
	}
}

func TestCountAfterDelete(t *testing.T) {
	index := newTestSecureIndex(t)
	_, token := newTestUser(t, &index, id.ScopeIndex)

	rand := &crypto.NativeRandom{}
	masterKey, _ := rand.GetBytes(32)

	keywords := [3]string{"keyword1", "keyword2", "keyword3"}
	ids := [5]string{"id1", "id2", "id3", "id4", "id5"}

	for i := 0; i < len(keywords); i++ {
		for j := 0; j < len(ids); j++ {
			if err := index.Add(masterKey, token, keywords[i], ids[j]); err != nil {
				t.Fatal(err)
			}

			if err := index.Delete(masterKey, token, keywords[i], ids[j]); err != nil {
				t.Fatal(err)
			}

			count, err := index.count(masterKey, keywords[i])
			if err != nil {
				t.Fatal(err)
			}
			if count != uint64(j+1) {
				t.Fatal("Count returned wrong count after deletion. Deleted keyword/ID pairs should still be counted.")
			}
		}
	}
}

func TestDeleteMultiple(t *testing.T) {
	index := newTestSecureIndex(t)
	_, token := newTestUser(t, &index, id.ScopeIndex)

	rand := &crypto.NativeRandom{}
	masterKey, _ := rand.GetBytes(32)

	keywords := [2]string{"keyword1", "keyword2"}
	ids := [2]string{"id1", "id2"}

	for i := 0; i < len(keywords); i++ {
		for j := 0; j < len(ids); j++ {
			if err := index.Add(masterKey, token, keywords[i], ids[j]); err != nil {
				t.Fatal(err)
			}
		}
	}

	if err := index.Delete(masterKey, token, keywords[0], ids[1]); err != nil {
		t.Fatal(err)
	}
	if err := index.Delete(masterKey, token, keywords[1], ids[0]); err != nil {
		t.Fatal(err)
	}

	for i := 0; i < len(keywords); i++ {
		IDs, err := index.Search(masterKey, token, keywords[i])
		if err != nil {
			t.Fatal(err)
		}
		if len(IDs) != 1 {
			t.Fatal("Keyword/ID pair not correctly deleted.")
		}
	}
}
