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
	"encoding/binary"
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

	for i := 0; i < 10; i++ {
		identifier := Identifier{Identifier: "id", NextCounter: uint64(i)}

		nextLabel, err := identifier.NextLabel(&tagger)
		if err != nil {
			t.Fatal(err)
		}

		// Convert counter = i to byte array and compute expected next label.
		buf := make([]byte, binary.MaxVarintLen64)
		n := binary.PutUvarint(buf, uint64(i))
		expectedNextLabel, err := tagger.Tag(buf[:n])
		if err != nil {
			t.Fatal(err)
		}

		if !reflect.DeepEqual(nextLabel, expectedNextLabel) {
			t.Fatal("NextLabel did not compute correct next label.")
		}
	}
}

func TestNextLabelWithCounterGaps(t *testing.T) {
	key := make([]byte, 32)
	tagger, err := crypto.NewKMAC256Tagger(key)
	if err != nil {
		t.Fatal(err)
	}

	NextCounters := [5]uint64{1, 3, 7, 11, 20}

	for i := range NextCounters {
		identifier := Identifier{Identifier: "id", NextCounter: NextCounters[i]}

		nextLabel, err := identifier.NextLabel(&tagger)
		if err != nil {
			t.Fatal(err)
		}

		// Convert counter = i to byte array and compute expected next label.
		buf := make([]byte, binary.MaxVarintLen64)
		n := binary.PutUvarint(buf, NextCounters[i])
		expectedNextLabel, err := tagger.Tag(buf[:n])
		if err != nil {
			t.Fatal(err)
		}

		if !reflect.DeepEqual(nextLabel, expectedNextLabel) {
			t.Fatal("NextLabel did not compute correct next label when there are gaps in counter values.")
		}
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
