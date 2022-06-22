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
	store        *bolt.DB
	objectBucket []byte
}

// NewBolt creates a new IO Provider that stores its data in the specified file.
func NewBolt(path string) (Bolt, error) {
	store, err := bolt.Open(path, 0600, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		return Bolt{}, err
	}

	objectBucket := []byte("object")

	// Create one bucket per data type
	err = store.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(objectBucket)
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return Bolt{}, err
	}

	return Bolt{store, objectBucket}, nil
}

func (b *Bolt) Put(id uuid.UUID, dataType DataType, data []byte) error {
	key := append(id.Bytes(), dataType.Bytes()...)
	return b.store.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(b.objectBucket)
		if b.Get(key) != nil {
			return ErrAlreadyExists
		}
		return b.Put(key, data)
	})
}

func (b *Bolt) Get(id uuid.UUID, dataType DataType) ([]byte, error) {
	key := append(id.Bytes(), dataType.Bytes()...)
	var out []byte
	err := b.store.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(b.objectBucket)
		out = append(out, b.Get(key)...)
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
	key := append(id.Bytes(), dataType.Bytes()...)
	return b.store.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(b.objectBucket)
		if b.Get(key) == nil {
			return ErrNotFound
		}
		return b.Put(key, data)
	})
}

func (b *Bolt) Delete(id uuid.UUID, dataType DataType) error {
	key := append(id.Bytes(), dataType.Bytes()...)
	return b.store.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(b.objectBucket)
		return b.Delete(key)
	})
}
