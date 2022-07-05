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

// Package io contains the definition of the IO Provider, as well as various implementations of
// the concept.
package io

import (
	"encoding/binary"
	"errors"
	"fmt"
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
	DataTypeSealedIdentifier
	DataTypeEnd
)

// Bytes returns a byte representation of a DataType.
func (d DataType) Bytes() []byte {
	b := make([]byte, binary.MaxVarintLen16)
	binary.LittleEndian.PutUint16(b, uint16(d))
	return b
}

// String returns a string representation of a DataType.
func (d DataType) String() string {
	return fmt.Sprintf("%d", d)
}

// Provider is the interface an IO Provider must implement to handle data from D1.
type Provider interface {
	// Put sends bytes to the IO Provider. The data is identified by an ID and a data type.
	// Should error if the data already exists in the IO Provider.
	Put(id []byte, dataType DataType, data []byte) error

	// Get fetches data from the IO Provider. The data is identified by an ID and a data type.
	Get(id []byte, dataType DataType) ([]byte, error)

	// Update is similar to Put but updates data previously sent to the IO Provider.
	// Should error if the data does not exist in the IO Provider.
	Update(id []byte, dataType DataType, data []byte) error

	// Delete removes data previously sent to the IO Provider.
	Delete(id []byte, dataType DataType) error
}
