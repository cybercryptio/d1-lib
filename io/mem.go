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
	"context"
	"fmt"
	"sync"
)

// Mem implements an in-memory version of an IO Provider.
type Mem struct {
	data sync.Map
}

// NewMem creates a new in-memory IO Provider.
func NewMem() Mem {
	return Mem{sync.Map{}}
}

func newKey(id []byte, dataType DataType) string {
	key := fmt.Sprintf("%x:%s", id, dataType.String())
	return key
}

func (m *Mem) Put(_ context.Context, id []byte, dataType DataType, data []byte) error {
	key := newKey(id, dataType)
	if _, ok := m.data.Load(key); ok {
		return ErrAlreadyExists
	}
	m.data.Store(key, data)
	return nil
}

func (m *Mem) Get(_ context.Context, id []byte, dataType DataType) ([]byte, error) {
	key := newKey(id, dataType)
	out, ok := m.data.Load(key)
	if !ok {
		return nil, ErrNotFound
	}
	data := out.([]byte)
	return data, nil
}

func (m *Mem) Update(_ context.Context, id []byte, dataType DataType, data []byte) error {
	key := newKey(id, dataType)
	if _, ok := m.data.Load(key); !ok {
		return ErrNotFound
	}
	m.data.Store(key, data)
	return nil
}

func (m *Mem) Delete(_ context.Context, id []byte, dataType DataType) error {
	key := newKey(id, dataType)
	m.data.Delete(key)
	return nil
}
