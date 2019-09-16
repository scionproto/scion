// Copyright 2019 Anapaya Systems
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

package metrics

import (
	"context"
)

type triggerContextKey string

const triggerKey triggerContextKey = "trigger"

// CtxWith returns a new context, based on ctx, that embeds argument trigger.
func CtxWith(ctx context.Context, trigger string) context.Context {
	return context.WithValue(ctx, triggerKey, trigger)
}

// FromCtx returns the trigger embedded in ctx if one exists, or the empty
// string otherwise.
func FromCtx(ctx context.Context) string {
	if ctx == nil {
		return App
	}
	if trigger := ctx.Value(triggerKey); trigger != nil {
		return trigger.(string)
	}
	return App
}
