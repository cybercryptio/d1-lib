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
	"testing"

	"context"
	"reflect"

	"github.com/cybercryptio/d1-lib/v2/id"
	"github.com/cybercryptio/d1-lib/v2/io"
	"github.com/cybercryptio/d1-lib/v2/key"
)

func newTestSecureIndex(t *testing.T) SecureIndex {
	ctx := context.Background()
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

	secureIndex, err := NewSecureIndex(ctx, &keyProvider, &ioProvider, &idProvider)
	if err != nil {
		t.Fatal(err)
	}
	return secureIndex
}

func newTestUser(t *testing.T, secureIndex *SecureIndex, scopes ...id.Scope) (string, string) {
	ctx := context.Background()
	idProvider := secureIndex.idProvider.(*id.Standalone)

	id, password, err := idProvider.NewUser(ctx, scopes...)
	if err != nil {
		t.Fatal(err)
	}

	token, _, err := idProvider.LoginUser(ctx, id, password)
	if err != nil {
		t.Fatal(err)
	}

	return id, token
}

func TestAdd(t *testing.T) {
	ctx := context.Background()
	index := newTestSecureIndex(t)
	_, token := newTestUser(t, &index, id.ScopeIndex)

	keyword := "first keyword"
	identifier := "first id"

	if err := index.Add(ctx, token, keyword, identifier); err != nil {
		t.Fatal(err)
	}
}

func TestAddSeveral(t *testing.T) {
	ctx := context.Background()
	index := newTestSecureIndex(t)
	_, token := newTestUser(t, &index, id.ScopeIndex)

	keywords := [2]string{"first keyword", "second keyword"}
	identifiers := [4]string{"first id", "second id", "third id", "fourth id"}

	for i := 0; i < len(keywords); i++ {
		for j := 0; j < len(identifiers); j++ {
			if err := index.Add(ctx, token, keywords[i], identifiers[j]); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestSearch(t *testing.T) {
	ctx := context.Background()
	index := newTestSecureIndex(t)
	_, token := newTestUser(t, &index, id.ScopeIndex)

	keyword := "first keyword"
	identifiers := []string{"id1", "id2", "id3", "id4", "id5"}

	for i := 0; i < len(identifiers); i++ {
		if err := index.Add(ctx, token, keyword, identifiers[i]); err != nil {
			t.Fatal(err)
		}

		IDs, err := index.Search(ctx, token, keyword)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(IDs[:i], identifiers[:i]) {
			t.Fatal("Search returned wrong decrypted Identifiers.")
		}
	}
}

func TestSearchWrongKeyword(t *testing.T) {
	ctx := context.Background()
	index := newTestSecureIndex(t)
	_, token := newTestUser(t, &index, id.ScopeIndex)

	keyword := "first keyword"
	identifier := "first id"

	if err := index.Add(ctx, token, keyword, identifier); err != nil {
		t.Fatal(err)
	}

	keywordShort := "first keywor"
	keywordLong := "first keywordd"

	IDs, err := index.Search(ctx, token, keywordShort)
	if err != nil {
		t.Fatal(err)
	}
	if len(IDs) != 0 {
		t.Fatal("Search returned decrypted Identifiers when given wrong keyword.")
	}

	IDs, err = index.Search(ctx, token, keywordLong)
	if err != nil {
		t.Fatal(err)
	}
	if len(IDs) != 0 {
		t.Fatal("Search returned decrypted Identifiers when given wrong keyword.")
	}
}

func TestDelete(t *testing.T) {
	ctx := context.Background()
	index := newTestSecureIndex(t)
	_, token := newTestUser(t, &index, id.ScopeIndex)

	keyword := "first keyword"
	identifier := "first id"

	if err := index.Add(ctx, token, keyword, identifier); err != nil {
		t.Fatal(err)
	}

	if err := index.Delete(ctx, token, keyword, identifier); err != nil {
		t.Fatal(err)
	}

	IDs, err := index.Search(ctx, token, keyword)
	if err != nil {
		t.Fatal(err)
	}
	if len(IDs) != 0 {
		t.Fatal("Search returned decrypted Identifier after the keyword/identifier pair has been deleted.")
	}
}

func TestDeleteAdd(t *testing.T) {
	ctx := context.Background()
	index := newTestSecureIndex(t)
	_, token := newTestUser(t, &index, id.ScopeIndex)

	keyword := "first keyword"
	identifier := "first id"

	if err := index.Add(ctx, token, keyword, identifier); err != nil {
		t.Fatal(err)
	}

	if err := index.Delete(ctx, token, keyword, identifier); err != nil {
		t.Fatal(err)
	}

	if err := index.Add(ctx, token, keyword, identifier); err != nil {
		t.Fatal(err)
	}

	IDs, err := index.Search(ctx, token, keyword)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(IDs[0], identifier) {
		t.Fatal("Keyword/identifier pair not correctly added after it has been deleted.")
	}
}

func TestAddTwiceDelete(t *testing.T) {
	ctx := context.Background()
	index := newTestSecureIndex(t)
	_, token := newTestUser(t, &index, id.ScopeIndex)

	keyword := "first keyword"
	identifier := "first id"

	if err := index.Add(ctx, token, keyword, identifier); err != nil {
		t.Fatal(err)
	}
	if err := index.Add(ctx, token, keyword, identifier); err != nil {
		t.Fatal(err)
	}
	if err := index.Delete(ctx, token, keyword, identifier); err != nil {
		t.Fatal(err)
	}

	IDs, err := index.Search(ctx, token, keyword)
	if err != nil {
		t.Fatal(err)
	}
	if len(IDs) != 0 {
		t.Fatal("Keyword/identifier pair not correctly deleted after added twice. Delete should delete all instances of the given pair.")
	}
}

func TestDeleteAddDelete(t *testing.T) {
	ctx := context.Background()
	index := newTestSecureIndex(t)
	_, token := newTestUser(t, &index, id.ScopeIndex)

	keyword := "first keyword"
	identifier := "first id"

	if err := index.Add(ctx, token, keyword, identifier); err != nil {
		t.Fatal(err)
	}

	if err := index.Delete(ctx, token, keyword, identifier); err != nil {
		t.Fatal(err)
	}

	if err := index.Add(ctx, token, keyword, identifier); err != nil {
		t.Fatal(err)
	}

	if err := index.Delete(ctx, token, keyword, identifier); err != nil {
		t.Fatal(err)
	}

	IDs, err := index.Search(ctx, token, keyword)
	if err != nil {
		t.Fatal(err)
	}
	if len(IDs) != 0 {
		t.Fatal("Keyword/identifier pair not correctly deleted after it has been deleted and then added.")
	}
}

func TestDeleteFirst(t *testing.T) {
	ctx := context.Background()
	index := newTestSecureIndex(t)
	_, token := newTestUser(t, &index, id.ScopeIndex)

	keyword := "keyword"
	identifiers := [5]string{"id1", "id2", "id3", "id4", "id5"}

	for i := 0; i < len(identifiers); i++ {
		if err := index.Add(ctx, token, keyword, identifiers[i]); err != nil {
			t.Fatal(err)
		}
	}

	if err := index.Delete(ctx, token, keyword, identifiers[0]); err != nil {
		t.Fatal(err)
	}

	IDs, err := index.Search(ctx, token, keyword)
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < len(IDs); i++ {
		if IDs[i] != identifiers[i+1] {
			t.Fatal("First Identifier not correctly deleted.")
		}
	}
	if len(IDs) != len(identifiers)-1 {
		t.Fatal("First Identifier not correctly deleted.")
	}
}

func TestDeleteLast(t *testing.T) {
	ctx := context.Background()
	index := newTestSecureIndex(t)
	_, token := newTestUser(t, &index, id.ScopeIndex)

	keyword := "keyword"
	identifiers := [5]string{"id1", "id2", "id3", "id4", "id5"}

	for i := 0; i < len(identifiers); i++ {
		if err := index.Add(ctx, token, keyword, identifiers[i]); err != nil {
			t.Fatal(err)
		}
	}

	if err := index.Delete(ctx, token, keyword, identifiers[len(identifiers)-1]); err != nil {
		t.Fatal(err)
	}

	IDs, err := index.Search(ctx, token, keyword)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < len(IDs); i++ {
		if IDs[i] != identifiers[i] {
			t.Fatal("Last Identifier not correctly deleted.")
		}
	}
	if len(IDs) != len(identifiers)-1 {
		t.Fatal("Last Identifier not correctly deleted.")
	}
}

func TestDeleteFromMiddle(t *testing.T) {
	ctx := context.Background()
	index := newTestSecureIndex(t)
	_, token := newTestUser(t, &index, id.ScopeIndex)

	keyword := "keyword"
	identifiers := [5]string{"id1", "id2", "id3", "id4", "id5"}

	for i := 0; i < len(identifiers); i++ {
		if err := index.Add(ctx, token, keyword, identifiers[i]); err != nil {
			t.Fatal(err)
		}
	}

	if err := index.Delete(ctx, token, keyword, identifiers[2]); err != nil {
		t.Fatal(err)
	}

	IDs, err := index.Search(ctx, token, keyword)
	if err != nil {
		t.Fatal(err)
	}

	identifiersOneLess := identifiers[:2]
	identifiersOneLess = append(identifiersOneLess, identifiers[3:]...)

	for i := 0; i < len(IDs); i++ {
		if IDs[i] != identifiersOneLess[i] {
			t.Fatal("Middle Identifier not correctly deleted.")
		}
	}
	if len(IDs) != len(identifiers)-1 {
		t.Fatal("Middle Identifier not correctly deleted.")
	}
}

func TestDeleteSeveral(t *testing.T) {
	ctx := context.Background()
	index := newTestSecureIndex(t)
	_, token := newTestUser(t, &index, id.ScopeIndex)

	keyword := "keyword"
	identifiers := [5]string{"id1", "id2", "id3", "id4", "id5"}

	for i := 0; i < len(identifiers); i++ {
		if err := index.Add(ctx, token, keyword, identifiers[i]); err != nil {
			t.Fatal(err)
		}
	}

	if err := index.Delete(ctx, token, keyword, identifiers[0]); err != nil {
		t.Fatal(err)
	}
	if err := index.Delete(ctx, token, keyword, identifiers[1]); err != nil {
		t.Fatal(err)
	}
	if err := index.Delete(ctx, token, keyword, identifiers[4]); err != nil {
		t.Fatal(err)
	}

	IDs, err := index.Search(ctx, token, keyword)
	if err != nil {
		t.Fatal(err)
	}
	if IDs[0] != identifiers[2] {
		t.Fatal("Identifier not correctly deleted.")
	}
	if IDs[1] != identifiers[3] {
		t.Fatal("Identifier not correctly deleted.")
	}
	if len(IDs) != 2 {
		t.Fatal("Last Identifier not correctly deleted.")
	}
}

func TestGetLastNode(t *testing.T) {
	ctx := context.Background()
	index := newTestSecureIndex(t)
	_, token := newTestUser(t, &index, id.ScopeIndex)

	keyword := "keyword"
	identifiers := [5]string{"id1", "id2", "id3", "id4", "id5"}

	tagger, cryptor, err := index.getTaggerAndCryptor(keyword)
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < len(identifiers); i++ {
		if err := index.Add(ctx, token, keyword, identifiers[i]); err != nil {
			t.Fatal(err)
		}

		lastNode, err := index.getLastNode(ctx, tagger, cryptor)
		if err != nil {
			t.Fatal(err)
		}
		if lastNode.Identifier != identifiers[i] {
			t.Fatal("getLastNode returned wrong last Node.")
		}
		if lastNode.NextCounter != uint64(i+1) {
			t.Fatal("getLastNode returned wrong last Node.")
		}
	}
}

func TestGetLastNodeBeforeAdd(t *testing.T) {
	ctx := context.Background()
	index := newTestSecureIndex(t)

	keyword := "keyword"
	tagger, cryptor, err := index.getTaggerAndCryptor(keyword)
	if err != nil {
		t.Fatal(err)
	}

	lastNode, err := index.getLastNode(ctx, tagger, cryptor)
	if err != nil {
		t.Fatal(err)
	}
	if lastNode.Identifier != "" {
		t.Fatal("getLastNode returned non-empty Node, but no keyword/identifier pairs have been added.")
	}
	if lastNode.NextCounter != 0 {
		t.Fatal("getLastNode returned non-empty Node, but no keyword/identifier pairs have been added.")
	}
}

func TestGetLastNodeWrongKeyword(t *testing.T) {
	ctx := context.Background()
	index := newTestSecureIndex(t)
	_, token := newTestUser(t, &index, id.ScopeIndex)

	keyword := "first keyword"
	identifier := "first id"

	if err := index.Add(ctx, token, keyword, identifier); err != nil {
		t.Fatal(err)
	}

	keywordShort := "first keywor"
	tagger, cryptor, err := index.getTaggerAndCryptor(keywordShort)
	if err != nil {
		t.Fatal(err)
	}

	lastNode, err := index.getLastNode(ctx, tagger, cryptor)
	if err != nil {
		t.Fatal(err)
	}
	if lastNode.Identifier != "" {
		t.Fatal("getLastNode returned non-empty Node when given wrong keyword.")
	}
	if lastNode.NextCounter != 0 {
		t.Fatal("getLastNode returned non-empty Node when given wrong keyword.")
	}

	keywordLong := "first keywordd"
	tagger, cryptor, err = index.getTaggerAndCryptor(keywordLong)
	if err != nil {
		t.Fatal(err)
	}

	lastNode, err = index.getLastNode(ctx, tagger, cryptor)
	if err != nil {
		t.Fatal(err)
	}
	if lastNode.Identifier != "" {
		t.Fatal("getLastNode returned non-empty Node when given wrong keyword.")
	}
	if lastNode.NextCounter != 0 {
		t.Fatal("getLastNode returned non-empty Node when given wrong keyword.")
	}
}
