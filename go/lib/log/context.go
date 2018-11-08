// Copyright 2018 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package log

import (
	"context"
)

type loggerContextKey string

const loggerKey loggerContextKey = "logger"

// CtxWith returns a new context, based on ctx, that embeds argument
// logger. The logger can be recovered using GetLogger. Attaching a logger to a
// context which already contains one will overwrite the existing value.
func CtxWith(ctx context.Context, logger Logger) context.Context {
	return context.WithValue(ctx, loggerKey, logger)
}

// FromCtx returns the logger embedded in ctx if one exists, or the root
// logger otherwise. FromCtx is guaranteed to never return nil.
func FromCtx(ctx context.Context) Logger {
	if logger := ctx.Value(loggerKey); logger != nil {
		return logger.(Logger)
	}
	// Logger not found in ctx, make sure we never return a nil root
	if Root() == nil {
		panic("unable to find non-nil logger")
	}
	return Root()
}
