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

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/xtest"
)

var _ Handler = (*handler)(nil)

type handler struct {
	t testing.TB
}

func (h *handler) ServeRPC(rw ReplyWriter, request *Request) {
	reply := &Reply{SignedPld: &ctrl.SignedPld{}}
	err := rw.WriteReply(reply)
	xtest.FailOnErr(h.t, err)
}

const (
	defKeyPath = "testdata/tls.key"
	defPemPath = "testdata/tls.pem"
)

func TestServer(t *testing.T) {
	Convey("Given a server", t, func() {
		cliConn, srvConn := getTestUDPConns(t, 60000, 60001)
		defer cliConn.Close()
		defer srvConn.Close()

		server := &Server{
			Conn: srvConn,
			TLSConfig: &tls.Config{
				Certificates: []tls.Certificate{
					MustLoadCertificate(defPemPath, defKeyPath),
				},
			},
			Handler: &handler{t: t},
		}
		go server.ListenAndServe()
		time.Sleep(40 * time.Millisecond)
		Convey("Double listen returns an error", func() {
			err := server.ListenAndServe()
			So(err, ShouldNotBeNil)
		})
		Convey("Closing does not return an error", func() {
			err := server.Close()
			So(err, ShouldBeNil)
		})
	})
}

func TestClientServer(t *testing.T) {
	Convey("", t, func() {
		client, server, _ := getCliSrv(t, 60002, 60003)
		go func() {
			err := server.ListenAndServe()
			xtest.FailOnErr(t, err)
		}()
		ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
		defer cancelF()
		reply, err := client.Request(
			ctx,
			&Request{SignedPld: &ctrl.SignedPld{}},
			&net.UDPAddr{IP: net.IP{127, 0, 0, 1}, Port: 60003},
		)
		xtest.FailOnErr(t, err)
		So(reply, ShouldResemble, &Reply{SignedPld: &ctrl.SignedPld{}})
	})
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
		Conn:      cliConn,
		TLSConfig: &tls.Config{InsecureSkipVerify: true},
	}
	server := &Server{
		Conn: srvConn,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{
				MustLoadCertificate(defPemPath, defKeyPath),
			},
		},
		Handler: &handler{t: t},
	}
	return client, server, cleaner
}

func getTestUDPConns(t testing.TB, cliPort, srvPort int) (net.PacketConn, net.PacketConn) {
	srvConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IP{127, 0, 0, 1}, Port: srvPort})
	xtest.FailOnErr(t, err)
	cliConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IP{127, 0, 0, 1}, Port: cliPort})
	xtest.FailOnErr(t, err)
	return cliConn, srvConn
}
