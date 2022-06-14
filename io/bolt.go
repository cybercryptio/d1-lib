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
	"time"

	"github.com/gofrs/uuid"
	bolt "go.etcd.io/bbolt"
)

// Mem implements an IO Provider backed by the key/value database bolt..
type Bolt struct {
	store *bolt.DB
}

// NewBolt creates a new IO Provider that stores its data in the specified file.
func NewBolt(path string) (Bolt, error) {
	store, err := bolt.Open(path, 0600, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		return Bolt{}, err
	}

	// Create one bucket per data type
	err = store.Update(func(tx *bolt.Tx) error {
		for t := DataType(0); t < DataTypeEnd; t++ {
			_, err := tx.CreateBucketIfNotExists(t.Bytes())
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return Bolt{}, err
	}

	return Bolt{store}, nil
}

func (b *Bolt) Put(id uuid.UUID, dataType DataType, data []byte) error {
	return b.store.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(dataType.Bytes())
		if b.Get(id.Bytes()) != nil {
			return ErrAlreadyExists
		}
		return b.Put(id.Bytes(), data)
	})
}

func (b *Bolt) Get(id uuid.UUID, dataType DataType) ([]byte, error) {
	var out []byte
	err := b.store.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(dataType.Bytes())
		out = append(out, b.Get(id.Bytes())...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if out == nil {
		return nil, ErrNotFound
	}
	return out, nil
}

func (b *Bolt) Update(id uuid.UUID, dataType DataType, data []byte) error {
	return b.store.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(dataType.Bytes())
		if b.Get(id.Bytes()) == nil {
			return ErrNotFound
		}
		return b.Put(id.Bytes(), data)
	})
}

func (b *Bolt) Delete(id uuid.UUID, dataType DataType) error {
	return b.store.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(dataType.Bytes())
		return b.Delete(id.Bytes())
	})
}
