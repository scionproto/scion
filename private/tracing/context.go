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
	"bytes"
	"context"

	"github.com/opentracing/opentracing-go"
	"github.com/uber/jaeger-client-go"

	"github.com/scionproto/scion/pkg/log"
)

// CtxWith creates a new span and attaches it to the context, it also sets the
// debug id of the logger and the span id and attaches the logger to the context.
func CtxWith(parentCtx context.Context, operationName string,
	opts ...opentracing.StartSpanOption) (opentracing.Span, context.Context) {

	span, ctx := opentracing.StartSpanFromContext(parentCtx, operationName, opts...)
	if spanCtx, ok := span.Context().(jaeger.SpanContext); ok {
		id := spanCtx.TraceID()
		ctx, _ = log.WithLabels(ctx, "debug_id", id.String()[:8], "trace_id", id)
		return span, ctx
	}
	ctx, _ = log.WithLabels(ctx, "debug_id", log.NewDebugID())
	return span, ctx
}

// LoggerWith attaches the trace ID if the context contains a span.
func LoggerWith(ctx context.Context, logger log.Logger) log.Logger {
	if logger == nil {
		return nil
	}
	span := opentracing.SpanFromContext(ctx)
	if span == nil {
		return logger
	}
	spanCtx, ok := span.Context().(jaeger.SpanContext)
	if !ok {
		return logger
	}
	return logger.New("trace_id", spanCtx.TraceID())
}

// IDFromCtx reads the tracing ID from the context.
func IDFromCtx(ctx context.Context) []byte {
	span := opentracing.SpanFromContext(ctx)
	if span == nil {
		return nil
	}
	var tracingBin bytes.Buffer
	err := opentracing.GlobalTracer().Inject(span.Context(), opentracing.Binary, &tracingBin)
	if err != nil {
		// According to the opentracing documentation, this error should never happen:
		// "All opentracing.Tracer implementations MUST support all BuiltinFormats."
		panic(err)
	}
	return tracingBin.Bytes()
}

// StartSpanFromCtx wraps opentracing.StartSpanFromContext for convenience.
func StartSpanFromCtx(ctx context.Context, operationName string,
	opts ...opentracing.StartSpanOption) (opentracing.Span, context.Context) {

	return opentracing.StartSpanFromContext(ctx, operationName, opts...)
}
