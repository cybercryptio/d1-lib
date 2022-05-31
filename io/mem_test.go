package io

import (
	"testing"

	"bytes"
	"errors"

	"github.com/gofrs/uuid"
)

// Test that putting and subsequently getting data returns the right bytes for all data types.
func TestMemPutAndGet(t *testing.T) {
	mem := NewMem()

	data := []byte("mock data")
	id := uuid.Must(uuid.NewV4())

	for dt := DataType(0); dt < DataTypeEnd; dt++ {
		testData := append(data, dt.Bytes()...)
		err := mem.Put(id, dt, testData)
		if err != nil {
			t.Fatal(err)
		}

		fetched, err := mem.Get(id, dt)
		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(testData, fetched) {
			t.Fatalf("returned data (%+v) not equal to original (%+v)", fetched, data)
		}
	}
}

// Test that getting non-existing data returns the right error.
func TestMemNotFound(t *testing.T) {
	mem := NewMem()

	id := uuid.Must(uuid.NewV4())

	data, err := mem.Get(id, DataTypeSealedObject)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Expected %v but got %v", ErrNotFound, err)
	}
	if data != nil {
		t.Fatalf("Expected data to be nil but got %v", data)
	}
}

// Test that data can be updated correctly.
func TestMemUpdate(t *testing.T) {
	mem := NewMem()

	data := []byte("mock data")
	updated := []byte("updated mock data")
	id := uuid.Must(uuid.NewV4())

	for dt := DataType(0); dt < DataTypeEnd; dt++ {
		err := mem.Put(id, dt, append(data, dt.Bytes()...))
		if err != nil {
			t.Fatal(err)
		}

		testUpdated := append(updated, dt.Bytes()...)
		err = mem.Update(id, dt, testUpdated)
		if err != nil {
			t.Fatal(err)
		}

		fetched, err := mem.Get(id, dt)
		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(testUpdated, fetched) {
			t.Fatalf("returned data (%+v) not equal to original (%+v)", fetched, data)
		}
	}
}

// Test that updating data that doesn't exist errors correctly.
func TestMemUpdateNotFound(t *testing.T) {
	mem := NewMem()

	id := uuid.Must(uuid.NewV4())

	err := mem.Update(id, DataTypeSealedObject, []byte("mock data"))
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Expected %v but got %v", ErrNotFound, err)
	}
}

// Test that deleting data actually removes it.
func TestMemDelete(t *testing.T) {
	mem := NewMem()

	data := []byte("mock data")
	id := uuid.Must(uuid.NewV4())

	for dt := DataType(0); dt < DataTypeEnd; dt++ {
		err := mem.Put(id, dt, append(data, dt.Bytes()...))
		if err != nil {
			t.Fatal(err)
		}

		err = mem.Delete(id, dt)
		if err != nil {
			t.Fatal(err)
		}

		data, err := mem.Get(id, dt)
		if !errors.Is(err, ErrNotFound) {
			t.Fatalf("Expected %v but got %v", ErrNotFound, err)
		}
		if data != nil {
			t.Fatalf("Expected data to be nil but got %v", data)
		}
	}
}

// Test that deleting non-existing data doesn't error.
func TestMemDeleteNotFound(t *testing.T) {
	mem := NewMem()

	id := uuid.Must(uuid.NewV4())

	err := mem.Delete(id, DataTypeSealedObject)
	if err != nil {
		t.Fatal(err)
	}
}
