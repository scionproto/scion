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

package grpc_test

import (
	"context"
	"log"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	pb "google.golang.org/grpc/examples/helloworld/helloworld"
	"google.golang.org/grpc/resolver"

	"github.com/scionproto/scion/go/lib/addr"
	libgrpc "github.com/scionproto/scion/go/pkg/grpc"
)

func TestTCPDial(t *testing.T) {
	lis, err := net.Listen("tcp4", "127.0.0.1:0")
	assert.NoError(t, err)
	defer lis.Close()

	s := grpc.NewServer()
	pb.RegisterGreeterServer(s, &server{})
	go func() { s.Serve(lis) }()
	defer s.Stop()

	t.Run("cases", func(t *testing.T) {
		testCases := map[string]struct {
			svcResolve func(addr.HostSVC) []resolver.Address
			dst        net.Addr
			asserError assert.ErrorAssertionFunc
		}{
			"valid tcp address": {
				dst: lis.Addr(),
				svcResolve: func(addr.HostSVC) []resolver.Address {
					return nil
				},
				asserError: assert.NoError,
			},
			"valid cs svc address": {
				dst: addr.SvcCS,
				svcResolve: func(addr.HostSVC) []resolver.Address {
					return []resolver.Address{
						{Addr: lis.Addr().String()},
						{Addr: "127.0.0.1:9898"},
					}
				},
				asserError: assert.NoError,
			},
			"invalid": {
				dst: addr.SvcCS,
				svcResolve: func(addr.HostSVC) []resolver.Address {
					return nil
				},
				asserError: assert.Error,
			},
		}

		for name, tc := range testCases {
			name, tc := name, tc
			t.Run(name, func(t *testing.T) {
				t.Parallel()

				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()

				dialer := libgrpc.TCPDialer{
					SvcResolver: tc.svcResolve,
				}

				for i := 0; i < 20; i++ {
					conn, err := dialer.Dial(ctx, tc.dst)
					tc.asserError(t, err)
					if err != nil {
						return
					}
					c := pb.NewGreeterClient(conn)
					_, err = c.SayHello(ctx, &pb.HelloRequest{Name: "dummy"})
					tc.asserError(t, err)
				}
			})
		}
	})

}

// server is used to implement helloworld.GreeterServer.
type server struct {
	pb.UnimplementedGreeterServer
}

// SayHello implements helloworld.GreeterServer
func (s *server) SayHello(ctx context.Context, in *pb.HelloRequest) (*pb.HelloReply, error) {
	log.Printf("Received: %v", in.GetName())
	return &pb.HelloReply{Message: "Hello " + in.GetName()}, nil
}
