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
	"github.com/gofrs/uuid"
	"github.com/rs/zerolog"
)

// WithMethod adds a method field to the log.
func WithMethod(l *zerolog.Logger, method string) {
	l.UpdateContext(func(c zerolog.Context) zerolog.Context {
		return c.Str("method", method)
	})
}

// WithMethod adds an bject ID field to the log.
func WithOID(l *zerolog.Logger, oid uuid.UUID) {
	l.UpdateContext(func(c zerolog.Context) zerolog.Context {
		return c.Stringer("oid", oid)
	})
}

// WithMethod adds a user ID field to the log.
func WithUID(l *zerolog.Logger, uid string) {
	l.UpdateContext(func(c zerolog.Context) zerolog.Context {
		return c.Str("uid", uid)
	})
}
