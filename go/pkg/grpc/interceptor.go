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

	grpc_retry "github.com/grpc-ecosystem/go-grpc-middleware/retry"
	"github.com/grpc-ecosystem/grpc-opentracing/go/otgrpc"
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
		logger.Debug("Outgoing RPC", "method", method, "target", cc.Target())
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

func openTracingInterceptorWithTarget() grpc.UnaryClientInterceptor {
	// Need to declare a new function here because the span decorator binds to one of the
	// args of the previous interceptor.
	return func(
		ctx context.Context,
		method string,
		req, reply interface{},
		cc *grpc.ClientConn,
		invoker grpc.UnaryInvoker,
		opts ...grpc.CallOption,
	) error {

		spanDecorator := func(
			span opentracing.Span,
			method string,
			req, resp interface{},
			grpcError error,
		) {
			if span != nil {
				span.SetTag("target", cc.Target())
			}
		}

		return otgrpc.OpenTracingClientInterceptor(
			opentracing.GlobalTracer(),
			otgrpc.SpanDecorator(spanDecorator),
		)(ctx, method, req, reply, cc, invoker, opts...)
	}
}

// UnaryClientInterceptor constructs the default unary RPC client-side interceptor for
// SCION control-plane applications.
func UnaryClientInterceptor() grpc.DialOption {
	return grpc.WithChainUnaryInterceptor(
		grpc_retry.UnaryClientInterceptor(),
		openTracingInterceptorWithTarget(),
		LogIDClientInterceptor(),
	)
}

// UnaryServerInterceptor constructs the default unary RPC server-side interceptor for
// SCION control-plane applications.
func UnaryServerInterceptor() grpc.ServerOption {
	return grpc.ChainUnaryInterceptor(
		otgrpc.OpenTracingServerInterceptor(opentracing.GlobalTracer()),
		LogIDServerInterceptor(),
	)
}
