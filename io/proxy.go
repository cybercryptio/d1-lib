// Copyright 2020-2022 CYBERCRYPT

package io

// Proxy is an IO Provider that wraps other IO Providers
// By default, it forwards calls directly to the implementation,
// but allows you to customize the behavior as you see fit by
// changing the individual functions as you see fit.
type Proxy struct {
	Implementation Provider
	PutFunc        func(id []byte, dataType DataType, data []byte) error
	GetFunc        func(id []byte, dataType DataType) ([]byte, error)
	UpdateFunc     func(id []byte, dataType DataType, data []byte) error
	DeleteFunc     func(id []byte, dataType DataType) error
}

func (o *Proxy) Put(id []byte, dataType DataType, data []byte) error {
	return o.PutFunc(id, dataType, data)
}

func (o *Proxy) Get(id []byte, dataType DataType) ([]byte, error) {
	return o.GetFunc(id, dataType)
}

func (o *Proxy) Update(id []byte, dataType DataType, data []byte) error {
	return o.UpdateFunc(id, dataType, data)
}

func (o *Proxy) Delete(id []byte, dataType DataType) error {
	return o.DeleteFunc(id, dataType)
}

// NewProxy returns a basic implementation of Proxy that can be used as a basis
// for tests.
func NewProxy(implementation Provider) Proxy {
	return Proxy{
		Implementation: implementation,
		PutFunc:        implementation.Put,
		GetFunc:        implementation.Get,
		UpdateFunc:     implementation.Update,
		DeleteFunc:     implementation.Delete,
	}
}
