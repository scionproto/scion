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

package squic_test

import (
	"context"
	"crypto/tls"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/lucas-clemente/quic-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/scionproto/scion/go/lib/snet/squic"
	cppb "github.com/scionproto/scion/go/pkg/proto/control_plane"
	mock_cp "github.com/scionproto/scion/go/pkg/proto/control_plane/mock_control_plane"
)

func TestGRPCQUIC(t *testing.T) {
	mctrl := gomock.NewController(t)
	defer mctrl.Finish()

	handler := mock_cp.NewMockTrustMaterialServiceServer(mctrl)
	handler.EXPECT().TRC(gomock.Any(), gomock.Any()).Return(
		&cppb.TRCResponse{
			Trc: []byte("hello"),
		},
		nil,
	)
	grpcServer := grpc.NewServer()
	cppb.RegisterTrustMaterialServiceServer(grpcServer, handler)

	srv, srvConn := netListener(t)
	go func() {
		err := grpcServer.Serve(srv)
		require.NoError(t, err)
	}()

	dialer := connDialer(t)
	conn, err := grpc.DialContext(context.Background(), "server",
		grpc.WithInsecure(),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return dialer.Dial(ctx, srvConn.LocalAddr())
		}),
	)
	require.NoError(t, err)
	defer conn.Close()

	client := cppb.NewTrustMaterialServiceClient(conn)
	rep, err := client.TRC(context.Background(), &cppb.TRCRequest{})
	require.NoError(t, err)
	assert.Equal(t, "hello", string(rep.Trc))
}

func TestEstablishConnection(t *testing.T) {
	t.Run("conn is closed", func(t *testing.T) {
		_, srvConn := netListener(t)
		err := srvConn.Close()
		require.NoError(t, err)

		dialer := connDialer(t)

		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_, err = dialer.Dial(ctx, srvConn.LocalAddr())
		assert.Error(t, err)
	})
	t.Run("server listens", func(t *testing.T) {
		srv, srvPacketConn := netListener(t)

		// Accept only returns when the first bytes from the client stream are
		// received. Add a wait group that protects read access to srvConn.
		var srvConn net.Conn
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			var err error
			srvConn, err = srv.Accept()
			require.NoError(t, err)
		}()

		dialer := connDialer(t)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		clientConn, err := dialer.Dial(ctx, srvPacketConn.LocalAddr())
		require.NoError(t, err)

		exchange := func(s, d *net.Conn, msg string) {
			n, err := (*s).Write([]byte(msg))
			require.NoError(t, err)
			require.Equal(t, n, len(msg))

			// Only the client->server call needs to wait here.
			wg.Wait()
			buf := make([]byte, len(msg))
			n, err = (*d).Read(buf)
			require.NoError(t, err)
			require.Equal(t, n, len(msg))
		}
		exchange(&clientConn, &srvConn, "client hello")
		exchange(&srvConn, &clientConn, "server hello")

		err = srvConn.Close()
		require.NoError(t, err)
		buf := make([]byte, 100)
		_, err = clientConn.Read(buf)
		assert.Error(t, err)

		err = clientConn.Close()
		require.NoError(t, err)
	})
}

func netListener(t *testing.T) (net.Listener, *net.UDPConn) {
	srvConn := newConn(t)
	listener, err := quic.Listen(srvConn, tlsConfig(t), nil)
	require.NoError(t, err)
	return squic.NewConnListener(listener), srvConn
}

func connDialer(t *testing.T) *squic.ConnDialer {
	return &squic.ConnDialer{
		Conn:      newConn(t),
		TLSConfig: tlsConfig(t),
	}
}

func newConn(t *testing.T) *net.UDPConn {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IP{127, 0, 0, 1}})
	require.NoError(t, err)
	return c
}

func tlsConfig(t *testing.T) *tls.Config {
	cert, err := tls.LoadX509KeyPair("testdata/tls.pem", "testdata/tls.key")
	require.NoError(t, err)
	return &tls.Config{
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true,
		NextProtos:         []string{"SCION"},
	}
}
