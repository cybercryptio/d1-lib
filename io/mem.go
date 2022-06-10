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

func (m *Mem) Put(id uuid.UUID, dataType DataType, data []byte) error {
	_, ok := m.data.Load(fmt.Sprintf("%s:%s", id.String(), dataType.String()))
	if ok {
		return ErrAlreadyExists
	}
	m.data.Store(fmt.Sprintf("%s:%s", id.String(), dataType.String()), data)
	return nil
}

func (m *Mem) Get(id uuid.UUID, dataType DataType) ([]byte, error) {
	out, ok := m.data.Load(fmt.Sprintf("%s:%s", id.String(), dataType.String()))
	if !ok {
		return nil, ErrNotFound
	}
	return out.([]byte), nil
}

func (m *Mem) Update(id uuid.UUID, dataType DataType, data []byte) error {
	_, ok := m.data.Load(fmt.Sprintf("%s:%s", id.String(), dataType.String()))
	if !ok {
		return ErrNotFound
	}
	m.data.Store(fmt.Sprintf("%s:%s", id.String(), dataType.String()), data)
	return nil
}

func (m *Mem) Delete(id uuid.UUID, dataType DataType) error {
	m.data.Delete(fmt.Sprintf("%s:%s", id.String(), dataType.String()))
	return nil
}
