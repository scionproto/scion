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

package tracing

import (
	"context"

	"github.com/opentracing/opentracing-go"
	"github.com/uber/jaeger-client-go"

	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/util"
)

// CtxWith creates a new span and attaches it to the context, it also sets the
// debug id of the logger and the span id and attaches the logger to the context.
func CtxWith(parentCtx context.Context, parentLogger log.Logger, operationName string,
	opts ...opentracing.StartSpanOption) (context.Context, opentracing.Span) {

	debugId := util.GetDebugID()
	span, ctx := opentracing.StartSpanFromContext(parentCtx, operationName, opts...)
	if spanCtx, ok := span.Context().(jaeger.SpanContext); ok {
		ctx = log.CtxWith(ctx, parentLogger.New("debug_id", debugId, "trace_id", spanCtx.TraceID()))
		span.SetTag("LogDebugId", debugId)
	} else {
		ctx = log.CtxWith(ctx, parentLogger.New("debug_id", util.GetDebugID()))
	}
	return ctx, span
}
