// Copyright 2021 ETH Zurich
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
	"crypto/tls"
	"net"

	"google.golang.org/grpc/credentials"
)

type ConnectionStater interface {
	ConnectionState() tls.ConnectionState
}

// PassThroughCredentials implements the grpc/credentials.TransportCredentials interface.
// It allows to pass the TLS connection state of an underlying TLS connection,
// e.g. from an underlying QUIC session, into the grpc stack. This allows accessing
// this information in the context of grpc/peer.Peer.AuthInfo.
// The handshake methods only extract the TLS state and otherwise simply
// pass-through the underlying connection object. The underlying connection
// must implement the ConnectionStater interface.
type PassThroughCredentials struct{}

func (c PassThroughCredentials) ClientHandshake(
	ctx context.Context,
	authority string,
	conn net.Conn,
) (net.Conn, credentials.AuthInfo, error) {

	authInfo := credentials.TLSInfo{
		State: conn.(ConnectionStater).ConnectionState(),
	}
	return conn, authInfo, nil
}

func (c PassThroughCredentials) ServerHandshake(
	conn net.Conn,
) (net.Conn, credentials.AuthInfo, error) {

	authInfo := credentials.TLSInfo{
		State: conn.(ConnectionStater).ConnectionState(),
	}
	return conn, authInfo, nil
}

func (c PassThroughCredentials) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{
		SecurityProtocol: "tls", // copied from grpc/credentials.tlsCreds.Info.
		SecurityVersion:  "1.2", // ditto
		ServerName:       "",    // XXX(matzf) do we need to set this???
	}
}

func (c PassThroughCredentials) Clone() credentials.TransportCredentials {
	return PassThroughCredentials{}
}

func (c PassThroughCredentials) OverrideServerName(string) error {
	panic("not implemented")
}
