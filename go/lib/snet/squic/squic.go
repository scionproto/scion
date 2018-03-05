// Copyright 2017 ETH Zurich
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

// +build ignore

// QUIC/SCION implementation.
package squic

import (
	"crypto/tls"

	//log "github.com/inconshreveable/log15"
	//"github.com/lucas-clemente/quic-go"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/snet"
)

const (
	defKeyPath = "gen-certs/tls.key"
	defPemPath = "gen-certs/tls.pem"
)

var (
	// Don't verify the server's cert, as we are not using the TLS PKI.
	cliTlsCfg = &tls.Config{InsecureSkipVerify: true}
	srvTlsCfg = &tls.Config{}
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

func DialSCION(network *snet.Network, laddr, raddr *snet.Addr) /*quic.Session, */ error {
	return DialSCIONWithBindSVC(network, laddr, raddr, nil, addr.SvcNone)
}

func DialSCIONWithBindSVC(network *snet.Network, laddr, raddr, baddr *snet.Addr,
	svc addr.HostSVC) /*quic.Session, */ error {
	sconn, err := sListen(network, laddr, baddr, svc)
	if err != nil {
		return nil, err
	}
	// Use dummy hostname, as it's used for SNI, and we're not doing cert verification.
	return //quic.Dial(sconn, raddr, "host:0", cliTlsCfg, nil)
}

func ListenSCION(network *snet.Network, laddr *snet.Addr) /*quic.Listener, */ error {
	return ListenSCIONWithBindSVC(network, laddr, nil, addr.SvcNone)
}

func ListenSCIONWithBindSVC(network *snet.Network, laddr, baddr *snet.Addr,
	svc addr.HostSVC) /*quic.Listener, */ error {
	if len(srvTlsCfg.Certificates) == 0 {
		return nil, common.NewBasicError("squic: No server TLS certificate configured", nil)
	}
	sconn, err := sListen(network, laddr, baddr, svc)
	if err != nil {
		return nil, err
	}
	return //quic.Listen(sconn, srvTlsCfg, nil)
}

func sListen(network *snet.Network, laddr, baddr *snet.Addr,
	svc addr.HostSVC) (*snet.Conn, error) {
	if network == nil {
		network = snet.DefNetwork
	}
	return network.ListenSCIONWithBindSVC("udp4", laddr, baddr, svc)
}
