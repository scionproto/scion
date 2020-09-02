// Copyright 2020 Anapaya Systems
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

package grpc

import (
	"context"

	opentracing "github.com/opentracing/opentracing-go"
	jaeger "github.com/uber/jaeger-client-go"
	"google.golang.org/grpc"

	"github.com/scionproto/scion/go/lib/log"
)

func LogIDClientInterceptor() grpc.UnaryClientInterceptor {
	return func(
		ctx context.Context,
		method string,
		req, resp interface{},
		cc *grpc.ClientConn,
		invoker grpc.UnaryInvoker,
		opts ...grpc.CallOption,
	) error {

		logger := loggerFromSpan(opentracing.SpanFromContext(ctx))
		logger.Debug("Outgoing RPC", "method", method)
		ctx = log.CtxWith(ctx, logger)
		return invoker(ctx, method, req, resp, cc, opts...)
	}
}

func LogIDServerInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {

		logger := loggerFromSpan(opentracing.SpanFromContext(ctx))
		logger.Debug("Serving RPC", "method", info.FullMethod)
		ctx = log.CtxWith(ctx, logger)
		return handler(ctx, req)
	}
}

func loggerFromSpan(span opentracing.Span) log.Logger {
	if span == nil {
		return log.New("debug_id", log.NewDebugID())
	}
	spanCtx, ok := span.Context().(jaeger.SpanContext)
	if !ok {
		return log.New("debug_id", log.NewDebugID())
	}
	id := spanCtx.TraceID()
	return log.New("debug_id", log.NewDebugID(), "trace_id", id)
}
