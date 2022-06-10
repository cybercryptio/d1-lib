// Package io contains the definition of the IO Provider, as well as various implementations of
// the concept.
package io

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/gofrs/uuid"
)

// Error returned if data is not found during a "Get" or "Update" call.
var ErrNotFound = errors.New("not found")

// Error returned if data is found during a "Put" call.
var ErrAlreadyExists = errors.New("already exists")

// Types of data supported by an IO Provider.
type DataType uint16

const (
	DataTypeSealedObject DataType = iota
	DataTypeSealedAccess
	DataTypeEnd
)

// Bytes returns a byte representation of a DataType..
func (d DataType) Bytes() []byte {
	b := make([]byte, binary.MaxVarintLen16)
	binary.LittleEndian.PutUint16(b, uint16(d))
	return b
}

// String returns a string representation of a DataType.
func (d DataType) String() string {
	return fmt.Sprintf("%d", d)
}

// Provider is the interface an IO Provider must implement to handle data from Encryptonize.
type Provider interface {
	// Put sends bytes to the IO Provider. The data is identified by an ID and a data type.
	Put(id uuid.UUID, dataType DataType, data []byte) error

	// Get fetches data from the IO Provider. The data is identified by an ID and a data type.
	Get(id uuid.UUID, dataType DataType) ([]byte, error)

	// Update is similar to Put but updates data previously sent to the IO Provider. Should error if
	// the data does not exist in the IO Provider.
	Update(id uuid.UUID, dataType DataType, data []byte) error

	// Delete removes data previously sent to the IO Provider.
	Delete(id uuid.UUID, dataType DataType) error
}
