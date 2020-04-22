// Copyright 2019 ETH Zurich
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

package rpc

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	capnp "zombiezen.com/go/capnproto2"
	"zombiezen.com/go/capnproto2/pogs"

	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/proto"
)

var _ Handler = (*handler)(nil)

type handler struct {
	t testing.TB
}

func (h *handler) ServeRPC(rw ReplyWriter, request *Request) {
	reply := &Reply{Message: getMessage(h.t)}
	err := rw.WriteReply(reply)
	require.NoError(h.t, err)
}

const (
	defKeyPath = "testdata/tls.key"
	defPemPath = "testdata/tls.pem"
)

func TestServer(t *testing.T) {
	cliConn, srvConn := getTestUDPConns(t, 60000, 60001)
	defer cliConn.Close()
	defer srvConn.Close()

	server := &Server{
		Conn: srvConn,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{
				MustLoadCertificate(defPemPath, defKeyPath),
			},
			NextProtos: []string{"SCION"},
		},
		Handler: &handler{t: t},
	}
	go server.ListenAndServe()
	time.Sleep(40 * time.Millisecond)
	t.Run("Double listen returns an error", func(t *testing.T) {
		err := server.ListenAndServe()
		assert.Error(t, err)
	})
	t.Run("Closing does not return an error", func(t *testing.T) {
		err := server.Close()
		assert.NoError(t, err)
	})
}

func TestClientServer(t *testing.T) {
	client, server, _ := getCliSrv(t, 60002, 60003)
	go func() {
		err := server.ListenAndServe()
		require.NoError(t, err)
	}()
	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()
	reply, err := client.Request(
		ctx,
		&Request{Message: getMessage(t)},
		&net.UDPAddr{IP: net.IP{127, 0, 0, 1}, Port: 60003},
	)
	require.NoError(t, err)
	assert.Equal(t, mustMarshalMessage(t, getMessage(t)), mustMarshalMessage(t, reply.Message))
}

func MustLoadCertificate(pem, key string) tls.Certificate {
	cert, err := tls.LoadX509KeyPair(pem, key)
	if err != nil {
		panic(err)
	}
	return cert
}

func getCliSrv(t testing.TB, cliPort, srvPort int) (*Client, *Server, func()) {
	cliConn, srvConn := getTestUDPConns(t, cliPort, srvPort)

	cleaner := func() {
		cliConn.Close()
		srvConn.Close()
	}
	client := &Client{
		Conn: cliConn,
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"SCION"},
		},
	}
	server := &Server{
		Conn: srvConn,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{
				MustLoadCertificate(defPemPath, defKeyPath),
			},
			NextProtos: []string{"SCION"},
		},
		Handler: &handler{t: t},
	}
	return client, server, cleaner
}

func getTestUDPConns(t testing.TB, cliPort, srvPort int) (net.PacketConn, net.PacketConn) {
	srvConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IP{127, 0, 0, 1}, Port: srvPort})
	require.NoError(t, err)
	cliConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IP{127, 0, 0, 1}, Port: cliPort})
	require.NoError(t, err)
	return cliConn, srvConn
}

func getMessage(t testing.TB) *capnp.Message {
	signedPld := &ctrl.SignedPld{}
	msg, seg, err := capnp.NewMessage(capnp.SingleSegment(nil))
	require.NoError(t, err)
	root, err := proto.NewRootSignedCtrlPld(seg)
	require.NoError(t, err)
	err = pogs.Insert(proto.SignedCtrlPld_TypeID, root.Struct, signedPld)
	require.NoError(t, err)
	return msg
}

func mustMarshalMessage(t *testing.T, msg *capnp.Message) []byte {
	b, err := msg.Marshal()
	require.NoError(t, err)
	return b
}
