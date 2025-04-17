// Code generated by protoc-gen-connect-go. DO NOT EDIT.
//
// Source: proto/gateway/v1/prefix.proto

package gatewayconnect

import (
	connect "connectrpc.com/connect"
	context "context"
	errors "errors"
	gateway "github.com/scionproto/scion/pkg/proto/gateway"
	http "net/http"
	strings "strings"
)

// This is a compile-time assertion to ensure that this generated file and the connect package are
// compatible. If you get a compiler error that this constant is not defined, this code was
// generated with a version of connect newer than the one compiled into your binary. You can fix the
// problem by either regenerating this code with an older version of connect or updating the connect
// version compiled into your binary.
const _ = connect.IsAtLeastVersion1_13_0

const (
	// IPPrefixesServiceName is the fully-qualified name of the IPPrefixesService service.
	IPPrefixesServiceName = "proto.gateway.v1.IPPrefixesService"
)

// These constants are the fully-qualified names of the RPCs defined in this package. They're
// exposed at runtime as Spec.Procedure and as the final two segments of the HTTP route.
//
// Note that these are different from the fully-qualified method names used by
// google.golang.org/protobuf/reflect/protoreflect. To convert from these constants to
// reflection-formatted method names, remove the leading slash and convert the remaining slash to a
// period.
const (
	// IPPrefixesServicePrefixesProcedure is the fully-qualified name of the IPPrefixesService's
	// Prefixes RPC.
	IPPrefixesServicePrefixesProcedure = "/proto.gateway.v1.IPPrefixesService/Prefixes"
)

// IPPrefixesServiceClient is a client for the proto.gateway.v1.IPPrefixesService service.
type IPPrefixesServiceClient interface {
	Prefixes(context.Context, *connect.Request[gateway.PrefixesRequest]) (*connect.Response[gateway.PrefixesResponse], error)
}

// NewIPPrefixesServiceClient constructs a client for the proto.gateway.v1.IPPrefixesService
// service. By default, it uses the Connect protocol with the binary Protobuf Codec, asks for
// gzipped responses, and sends uncompressed requests. To use the gRPC or gRPC-Web protocols, supply
// the connect.WithGRPC() or connect.WithGRPCWeb() options.
//
// The URL supplied here should be the base URL for the Connect or gRPC server (for example,
// http://api.acme.com or https://acme.com/grpc).
func NewIPPrefixesServiceClient(httpClient connect.HTTPClient, baseURL string, opts ...connect.ClientOption) IPPrefixesServiceClient {
	baseURL = strings.TrimRight(baseURL, "/")
	iPPrefixesServiceMethods := gateway.File_proto_gateway_v1_prefix_proto.Services().ByName("IPPrefixesService").Methods()
	return &iPPrefixesServiceClient{
		prefixes: connect.NewClient[gateway.PrefixesRequest, gateway.PrefixesResponse](
			httpClient,
			baseURL+IPPrefixesServicePrefixesProcedure,
			connect.WithSchema(iPPrefixesServiceMethods.ByName("Prefixes")),
			connect.WithClientOptions(opts...),
		),
	}
}

// iPPrefixesServiceClient implements IPPrefixesServiceClient.
type iPPrefixesServiceClient struct {
	prefixes *connect.Client[gateway.PrefixesRequest, gateway.PrefixesResponse]
}

// Prefixes calls proto.gateway.v1.IPPrefixesService.Prefixes.
func (c *iPPrefixesServiceClient) Prefixes(ctx context.Context, req *connect.Request[gateway.PrefixesRequest]) (*connect.Response[gateway.PrefixesResponse], error) {
	return c.prefixes.CallUnary(ctx, req)
}

// IPPrefixesServiceHandler is an implementation of the proto.gateway.v1.IPPrefixesService service.
type IPPrefixesServiceHandler interface {
	Prefixes(context.Context, *connect.Request[gateway.PrefixesRequest]) (*connect.Response[gateway.PrefixesResponse], error)
}

// NewIPPrefixesServiceHandler builds an HTTP handler from the service implementation. It returns
// the path on which to mount the handler and the handler itself.
//
// By default, handlers support the Connect, gRPC, and gRPC-Web protocols with the binary Protobuf
// and JSON codecs. They also support gzip compression.
func NewIPPrefixesServiceHandler(svc IPPrefixesServiceHandler, opts ...connect.HandlerOption) (string, http.Handler) {
	iPPrefixesServiceMethods := gateway.File_proto_gateway_v1_prefix_proto.Services().ByName("IPPrefixesService").Methods()
	iPPrefixesServicePrefixesHandler := connect.NewUnaryHandler(
		IPPrefixesServicePrefixesProcedure,
		svc.Prefixes,
		connect.WithSchema(iPPrefixesServiceMethods.ByName("Prefixes")),
		connect.WithHandlerOptions(opts...),
	)
	return "/proto.gateway.v1.IPPrefixesService/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case IPPrefixesServicePrefixesProcedure:
			iPPrefixesServicePrefixesHandler.ServeHTTP(w, r)
		default:
			http.NotFound(w, r)
		}
	})
}

// UnimplementedIPPrefixesServiceHandler returns CodeUnimplemented from all methods.
type UnimplementedIPPrefixesServiceHandler struct{}

func (UnimplementedIPPrefixesServiceHandler) Prefixes(context.Context, *connect.Request[gateway.PrefixesRequest]) (*connect.Response[gateway.PrefixesResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("proto.gateway.v1.IPPrefixesService.Prefixes is not implemented"))
}
