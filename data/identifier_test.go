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

package data

import (
	"testing"

	"reflect"

	"github.com/cybercryptio/d1-lib/crypto"
)

func TestNextLabel(t *testing.T) {
	key := make([]byte, 32)
	tagger, err := crypto.NewKMAC256Tagger(key)
	if err != nil {
		t.Fatal(err)
	}

	identifier1 := Identifier{Identifier: "first id", NextCounter: 1}
	identifier2 := Identifier{Identifier: "second id", NextCounter: 1}
	identifier3 := Identifier{Identifier: "third id", NextCounter: 2}

	nextLabel1, err := identifier1.NextLabel(&tagger)
	if err != nil {
		t.Fatal(err)
	}
	nextLabel2, err := identifier2.NextLabel(&tagger)
	if err != nil {
		t.Fatal(err)
	}
	nextLabel3, err := identifier3.NextLabel(&tagger)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(nextLabel1, nextLabel2) {
		t.Fatal("NextLabel should return the same next label when given the same NextCounter.")
	}
	if reflect.DeepEqual(nextLabel1, nextLabel3) {
		t.Fatal("NextLabel should return different next labels when given different NextCounter's.")
	}
}

func TestNextLabelDifferentTaggers(t *testing.T) {
	rand := &crypto.NativeRandom{}
	key1, _ := rand.GetBytes(32)
	key2, _ := rand.GetBytes(32)

	tagger1, err := crypto.NewKMAC256Tagger(key1)
	if err != nil {
		t.Fatal(err)
	}
	tagger2, err := crypto.NewKMAC256Tagger(key2)
	if err != nil {
		t.Fatal(err)
	}

	identifier1 := Identifier{Identifier: "first id", NextCounter: 1}
	identifier2 := Identifier{Identifier: "first id", NextCounter: 1}

	nextLabel1, err := identifier1.NextLabel(&tagger1)
	if err != nil {
		t.Fatal(err)
	}
	nextLabel2, err := identifier2.NextLabel(&tagger2)
	if err != nil {
		t.Fatal(err)
	}
	if reflect.DeepEqual(nextLabel1, nextLabel2) {
		t.Fatal("NextLabel should return different next labels when given different tagger's.")
	}
}

func TestIdentifierSeal(t *testing.T) {
	key := make([]byte, 32)
	cryptor, err := crypto.NewAESCryptor(key)
	if err != nil {
		t.Fatal(err)
	}

	identifier := Identifier{Identifier: "first id", NextCounter: 1}

	rand := &crypto.NativeRandom{}
	label, _ := rand.GetBytes(32)

	sealed, err := identifier.Seal(label, &cryptor)
	if err != nil {
		t.Fatal(err)
	}

	unsealed, err := sealed.Unseal(label, &cryptor)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(identifier, unsealed) {
		t.Fatal("Unsealed object not equal to original")
	}
}

func TestIdentifierVerifyCiphertext(t *testing.T) {
	key := make([]byte, 32)
	cryptor, err := crypto.NewAESCryptor(key)
	if err != nil {
		t.Fatal(err)
	}

	identifier := Identifier{Identifier: "first id", NextCounter: 1}

	rand := &crypto.NativeRandom{}
	label, _ := rand.GetBytes(32)

	sealed, err := identifier.Seal(label, &cryptor)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := sealed.Unseal(label, &cryptor); err != nil {
		t.Fatal("Verification failed")
	}
	sealed.Ciphertext[0] = sealed.Ciphertext[0] ^ 1
	if _, err := sealed.Unseal(label, &cryptor); err == nil {
		t.Fatal("Verification should have failed")
	}
}
