// Copyright 2020-2022 CYBERCRYPT

package io

import (
	"context"
)

// Proxy is an IO Provider that wraps other IO Providers
// By default, it forwards calls directly to the implementation,
// but allows you to customize the behavior as you see fit by
// changing the individual functions as you see fit.
type Proxy struct {
	Implementation Provider
	PutFunc        func(ctx context.Context, id []byte, dataType DataType, data []byte) error
	GetFunc        func(ctx context.Context, id []byte, dataType DataType) ([]byte, error)
	UpdateFunc     func(ctx context.Context, id []byte, dataType DataType, data []byte) error
	DeleteFunc     func(ctx context.Context, id []byte, dataType DataType) error
}

func (o *Proxy) Put(ctx context.Context, id []byte, dataType DataType, data []byte) error {
	return o.PutFunc(ctx, id, dataType, data)
}

func (o *Proxy) Get(ctx context.Context, id []byte, dataType DataType) ([]byte, error) {
	return o.GetFunc(ctx, id, dataType)
}

func (o *Proxy) Update(ctx context.Context, id []byte, dataType DataType, data []byte) error {
	return o.UpdateFunc(ctx, id, dataType, data)
}

func (o *Proxy) Delete(ctx context.Context, id []byte, dataType DataType) error {
	return o.DeleteFunc(ctx, id, dataType)
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
