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
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	helloworldpb "google.golang.org/grpc/examples/helloworld/helloworld"
	"google.golang.org/grpc/resolver"

	"github.com/scionproto/scion/pkg/addr"
	libgrpc "github.com/scionproto/scion/pkg/grpc"
	"github.com/scionproto/scion/pkg/snet"
)

func TestTCPDial(t *testing.T) {
	lis, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer lis.Close()

	noGRPCLis, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer noGRPCLis.Close()

	s := grpc.NewServer()
	helloworldpb.RegisterGreeterServer(s, &server{})
	var bg errgroup.Group
	bg.Go(func() error {
		return s.Serve(lis)
	})
	defer func() {
		s.Stop()
		assert.NoError(t, bg.Wait())
	}()

	getUnusedAddr := func(t *testing.T) string {
		l, err := net.Listen("tcp4", "127.0.0.1:0")
		require.NoError(t, err)
		t.Cleanup(func() { l.Close() })
		return l.Addr().String()
	}

	t.Run("cases", func(t *testing.T) {
		testCases := map[string]struct {
			svcResolve      func(*testing.T, addr.SVC) []resolver.Address
			dst             net.Addr
			assertDialError assert.ErrorAssertionFunc
			assertCallError assert.ErrorAssertionFunc
		}{
			"valid tcp address": {
				dst: lis.Addr(),
				svcResolve: func(*testing.T, addr.SVC) []resolver.Address {
					return nil
				},
				assertDialError: assert.NoError,
				assertCallError: assert.NoError,
			},
			"valid cs svc address": {
				dst: &snet.SVCAddr{SVC: addr.SvcCS},
				svcResolve: func(*testing.T, addr.SVC) []resolver.Address {
					return []resolver.Address{
						{Addr: lis.Addr().String()},
						{Addr: getUnusedAddr(t)},
					}
				},
				assertDialError: assert.NoError,
				assertCallError: assert.NoError,
			},
			"valid cs svc address second": {
				dst: &snet.SVCAddr{SVC: addr.SvcCS},
				svcResolve: func(*testing.T, addr.SVC) []resolver.Address {
					return []resolver.Address{
						{Addr: getUnusedAddr(t)},
						{Addr: lis.Addr().String()},
					}
				},
				assertDialError: assert.NoError,
				assertCallError: assert.NoError,
			},
			"valid, one server with no gRPC": {
				dst: &snet.SVCAddr{SVC: addr.SvcCS},
				svcResolve: func(*testing.T, addr.SVC) []resolver.Address {
					return []resolver.Address{
						{Addr: noGRPCLis.Addr().String()},
						{Addr: lis.Addr().String()},
					}
				},
				assertDialError: assert.NoError,
				assertCallError: assert.NoError,
			},
			"invalid": {
				dst: &snet.SVCAddr{SVC: addr.SvcCS},
				svcResolve: func(*testing.T, addr.SVC) []resolver.Address {
					return nil
				},
				assertDialError: assert.Error,
				assertCallError: assert.Error,
			},
		}

		for name, tc := range testCases {
			name, tc := name, tc
			t.Run(name, func(t *testing.T) {
				t.Parallel()

				timeout := time.Second
				if _, ok := os.LookupEnv("CI"); ok {
					timeout = 10 * time.Second
				}
				ctx, cancel := context.WithTimeout(context.Background(), timeout)
				defer cancel()

				dialer := libgrpc.TCPDialer{
					SvcResolver: func(svc addr.SVC) []resolver.Address {
						return tc.svcResolve(t, svc)
					},
				}

				for i := 0; i < 20; i++ {
					conn, err := dialer.Dial(ctx, tc.dst)
					tc.assertDialError(t, err)
					if err != nil {
						return
					}
					c := helloworldpb.NewGreeterClient(conn)
					_, err = c.SayHello(ctx, &helloworldpb.HelloRequest{Name: "dummy"})
					tc.assertCallError(t, err)
				}
			})
		}
	})
}

// server is used to implement helloworld.GreeterServer.
type server struct {
	helloworldpb.UnimplementedGreeterServer
}

// SayHello implements helloworld.GreeterServer
func (s *server) SayHello(ctx context.Context,
	in *helloworldpb.HelloRequest) (*helloworldpb.HelloReply, error) {

	log.Printf("Received: %v", in.GetName())
	return &helloworldpb.HelloReply{Message: "Hello " + in.GetName()}, nil
}
