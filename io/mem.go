package io

import (
	"fmt"
	"sync"

	"github.com/gofrs/uuid"
)

// Mem implements an in-memory version of an IO Provider.
type Mem struct {
	data sync.Map
}

// NewMem creates a new in-memory IO Provider.
func NewMem() Mem {
	return Mem{sync.Map{}}
}

func newKey(id uuid.UUID, dataType DataType) string {
	key := fmt.Sprintf("%s:%s", id.String(), dataType.String())
	return key
}

func (m *Mem) Put(id uuid.UUID, dataType DataType, data []byte) error {
	key := newKey(id, dataType)
	_, ok := m.data.Load(key)
	if ok {
		return ErrAlreadyExists
	}
	m.data.Store(key, data)
	return nil
}

func (m *Mem) Get(id uuid.UUID, dataType DataType) ([]byte, error) {
	key := newKey(id, dataType)
	out, ok := m.data.Load(key)
	if !ok {
		return nil, ErrNotFound
	}
	data := out.([]byte)
	return data, nil
}

func (m *Mem) Update(id uuid.UUID, dataType DataType, data []byte) error {
	key := newKey(id, dataType)
	_, ok := m.data.Load(key)
	if !ok {
		return ErrNotFound
	}
	m.data.Store(key, data)
	return nil
}

func (m *Mem) Delete(id uuid.UUID, dataType DataType) error {
	key := newKey(id, dataType)
	m.data.Delete(key)
	return nil
}
