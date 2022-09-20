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

package log

import (
	"context"

	"github.com/rs/zerolog"
)

// CopyCtxLogger creates a new context with a copy of any logger found in the context. This is
// useful when we don't want to pollute the caller's log context.
func CopyCtxLogger(ctx context.Context) context.Context {
	l := *zerolog.Ctx(ctx)
	return l.WithContext(ctx)
}

// Ctx returns any logger contained in the context, or a disable logger if none is present.
func Ctx(ctx context.Context) *zerolog.Logger {
	return zerolog.Ctx(ctx)
}

// WithMethod adds a method field to the context's logger.
func WithMethod(ctx context.Context, method string) {
	Ctx(ctx).UpdateContext(func(c zerolog.Context) zerolog.Context {
		return c.Str("method", method)
	})
}

// WithUserID adds a user ID field to the context's logger.
func WithUserID(ctx context.Context, id string) {
	Ctx(ctx).UpdateContext(func(c zerolog.Context) zerolog.Context {
		return c.Str("uid", id)
	})
}

// WithObjectID adds an object ID field to the context's logger.
func WithObjectID(ctx context.Context, id string) {
	Ctx(ctx).UpdateContext(func(c zerolog.Context) zerolog.Context {
		return c.Str("oid", id)
	})
}
