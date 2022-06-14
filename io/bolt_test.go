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

package io

import (
	"testing"

	"bytes"
	"errors"

	"github.com/gofrs/uuid"
)

// Test that putting and subsequently getting data returns the right bytes for all data types.
func TestBoltPutAndGet(t *testing.T) {
	bolt, err := NewBolt(t.TempDir() + "test.db")
	if err != nil {
		t.Fatal(err)
	}

	data := []byte("mock data")
	id := uuid.Must(uuid.NewV4())

	for dt := DataType(0); dt < DataTypeEnd; dt++ {
		testData := append(data, dt.Bytes()...)
		err := bolt.Put(id, dt, testData)
		if err != nil {
			t.Fatal(err)
		}

		fetched, err := bolt.Get(id, dt)
		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(testData, fetched) {
			t.Fatalf("returned data (%+v) not equal to original (%+v)", fetched, data)
		}
	}
}

// Test that putting existing data returns the right error.
func TestBoltPutAlreadyExists(t *testing.T) {
	bolt, err := NewBolt(t.TempDir() + "test.db")
	if err != nil {
		t.Fatal(err)
	}

	data := []byte("mock data")
	id := uuid.Must(uuid.NewV4())

	for dt := DataType(0); dt < DataTypeEnd; dt++ {
		testData := append(data, dt.Bytes()...)
		err := bolt.Put(id, dt, testData)
		if err != nil {
			t.Fatal(err)
		}

		err = bolt.Put(id, dt, testData)
		if !errors.Is(err, ErrAlreadyExists) {
			t.Fatalf("Expected %v but got %v", ErrAlreadyExists, err)
		}
	}
}

// Test that getting non-existing data returns the right error.
func TestBoltNotFound(t *testing.T) {
	bolt, err := NewBolt(t.TempDir() + "test.db")
	if err != nil {
		t.Fatal(err)
	}

	id := uuid.Must(uuid.NewV4())

	data, err := bolt.Get(id, DataTypeSealedObject)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Expected %v but got %v", ErrNotFound, err)
	}
	if data != nil {
		t.Fatalf("Expected data to be nil but got %v", data)
	}
}

// Test that using an invalid file path fails.
func TestBoltInvalidPath(t *testing.T) {
	_, err := NewBolt("/../../../not/a/valid/path")
	if err == nil {
		t.Fatal("Expected NewBolt to fail on invalid path")
	}
}

// Test that data can be updated correctly.
func TestBoltUpdate(t *testing.T) {
	bolt, err := NewBolt(t.TempDir() + "test.db")
	if err != nil {
		t.Fatal(err)
	}

	data := []byte("mock data")
	updated := []byte("updated mock data")
	id := uuid.Must(uuid.NewV4())

	for dt := DataType(0); dt < DataTypeEnd; dt++ {
		err := bolt.Put(id, dt, append(data, dt.Bytes()...))
		if err != nil {
			t.Fatal(err)
		}

		testUpdated := append(updated, dt.Bytes()...)
		err = bolt.Update(id, dt, testUpdated)
		if err != nil {
			t.Fatal(err)
		}

		fetched, err := bolt.Get(id, dt)
		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(testUpdated, fetched) {
			t.Fatalf("returned data (%+v) not equal to original (%+v)", fetched, data)
		}
	}
}

// Test that updating data that doesn't exist errors correctly.
func TestBoltUpdateNotFound(t *testing.T) {
	bolt, err := NewBolt(t.TempDir() + "test.db")
	if err != nil {
		t.Fatal(err)
	}

	id := uuid.Must(uuid.NewV4())

	err = bolt.Update(id, DataTypeSealedObject, []byte("mock data"))
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Expected %v but got %v", ErrNotFound, err)
	}
}

// Test that deleting data actually removes it.
func TestBoltDelete(t *testing.T) {
	bolt, err := NewBolt(t.TempDir() + "test.db")
	if err != nil {
		t.Fatal(err)
	}

	data := []byte("mock data")
	id := uuid.Must(uuid.NewV4())

	for dt := DataType(0); dt < DataTypeEnd; dt++ {
		err := bolt.Put(id, dt, append(data, dt.Bytes()...))
		if err != nil {
			t.Fatal(err)
		}

		err = bolt.Delete(id, dt)
		if err != nil {
			t.Fatal(err)
		}

		data, err := bolt.Get(id, dt)
		if !errors.Is(err, ErrNotFound) {
			t.Fatalf("Expected %v but got %v", ErrNotFound, err)
		}
		if data != nil {
			t.Fatalf("Expected data to be nil but got %v", data)
		}
	}
}

// Test that deleting non-existing data doesn't error.
func TestBoltDeleteNotFound(t *testing.T) {
	bolt, err := NewBolt(t.TempDir() + "test.db")
	if err != nil {
		t.Fatal(err)
	}

	id := uuid.Must(uuid.NewV4())

	err = bolt.Delete(id, DataTypeSealedObject)
	if err != nil {
		t.Fatal(err)
	}
}
