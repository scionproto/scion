// Copyright 2017 ETH Zurich
// Copyright 2019 ETH Zurich, Anapaya Systems
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

// QUIC/SCION implementation.
package squic

import (
	"context"
	"crypto/tls"
	"net"

	"github.com/lucas-clemente/quic-go"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/snet"
)

const (
	defKeyPath = "gen-certs/tls.key"
	defPemPath = "gen-certs/tls.pem"
)

var (
	// Don't verify the server's cert, as we are not using the TLS PKI.
	cliTlsCfg = &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"SCION"}}
	srvTlsCfg = &tls.Config{NextProtos: []string{"SCION"}}
)

func Init(keyPath, pemPath string) error {
	if keyPath == "" {
		keyPath = defKeyPath
	}
	if pemPath == "" {
		pemPath = defPemPath
	}
	cert, err := tls.LoadX509KeyPair(pemPath, keyPath)
	if err != nil {
		return common.NewBasicError("squic: Unable to load TLS cert/key", err)
	}
	srvTlsCfg.Certificates = []tls.Certificate{cert}
	return nil
}

// Dial dials using quic over the scion network.
func Dial(network *snet.SCIONNetwork, listen *net.UDPAddr, remote *snet.UDPAddr,
	svc addr.HostSVC, quicConfig *quic.Config) (quic.Session, error) {

	sconn, err := sListen(network, listen, svc)
	if err != nil {
		return nil, err
	}
	// Use dummy hostname, as it's used for SNI, and we're not doing cert verification.
	return quic.Dial(sconn, remote, "host:0", cliTlsCfg, quicConfig)
}

func Listen(network *snet.SCIONNetwork, listen *net.UDPAddr,
	svc addr.HostSVC, quicConfig *quic.Config) (quic.Listener, error) {

	if len(srvTlsCfg.Certificates) == 0 {
		return nil, serrors.New("squic: No server TLS certificate configured")
	}
	sconn, err := sListen(network, listen, svc)
	if err != nil {
		return nil, err
	}
	return quic.Listen(sconn, srvTlsCfg, quicConfig)
}

func sListen(network *snet.SCIONNetwork, listen *net.UDPAddr,
	svc addr.HostSVC) (*snet.Conn, error) {

	if network == nil {
		return nil, serrors.New("squic:  SCION network must not be nil")
	}
	return network.Listen(context.Background(), "udp", listen, svc)
}
