// Copyright 2018 ETH Zurich, Anapaya Systems
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

// Package infraenv contains convenience function common to SCION infra
// services.
package infraenv

import (
	"crypto/tls"
	"net"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/env"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/disp"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/infra/transport"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/pathmgr"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/snet/snetproxy"
	"github.com/scionproto/scion/go/lib/sock/reliable"
)

const (
	ErrAppUnableToInitMessenger = "Unable to initialize SCION Infra Messenger"
)

// NetworkConfig describes the networking configuration of a SCION
// control-plane RPC endpoint.
type NetworkConfig struct {
	// IA is the local AS number.
	IA addr.IA
	// Public is the Internet-reachable address in the case where the service
	// is behind NAT.
	Public *snet.Addr
	// Bind is the local address the server should listen on.
	Bind *snet.Addr
	// SVC registers this server to receive packets with the specified SVC
	// destination address.
	SVC addr.HostSVC
	// TrustStore is the crypto backend for control-plane verification.
	TrustStore infra.TrustStore
	// ReconnectToDispatcher sets up sockets that automatically reconnect if
	// the dispatcher closes the connection (e.g., if the dispatcher goes
	// down).
	ReconnectToDispatcher bool
	// EnableQUICTest can be used to enable the QUIC RPC implementation.
	EnableQUICTest bool
	// SCIOND tells the stack it can use the local SCIOND daemon for certain
	// operations. If the default value is used, no SCIOND connections are ever
	// set up.
	SCIOND env.SciondClient
}

// Messenger initializes a SCION control-plane RPC endpoint using the specified
// configuration.
func (nc *NetworkConfig) Messenger() (infra.Messenger, error) {
	// TODO(scrye): Ignore path resolver for now, but use it later to
	// initialize path-related modules in the messenger and trust store.
	conn, _, err := nc.initNetworking()
	if err != nil {
		return nil, err
	}
	msgerCfg := &messenger.Config{
		IA:         nc.IA,
		TrustStore: nc.TrustStore,
	}
	if nc.EnableQUICTest {
		var err error
		msgerCfg.QUIC, err = buildQUICConfig(conn)
		if err != nil {
			return nil, err
		}
	} else {
		msgerCfg.Dispatcher = disp.New(
			transport.NewPacketTransport(conn),
			messenger.DefaultAdapter,
			log.Root(),
		)
	}
	msger := messenger.NewMessengerWithMetrics(msgerCfg)
	nc.TrustStore.SetMessenger(msger)
	return msger, nil

}

func (nc *NetworkConfig) initNetworking() (net.PacketConn, pathmgr.Resolver, error) {
	network, err := nc.initNetwork()
	if err != nil {
		return nil, nil, common.NewBasicError("Unable to create network", err)
	}
	// FIXME(scrye): create a new path resolver here, as sharing path state
	// with the snet backend path store is rarely useful in the same app.
	pathResolver := network.(*snet.SCIONNetwork).PathResolver()
	if nc.ReconnectToDispatcher {
		network = snetproxy.NewProxyNetwork(network)
	}
	conn, err := network.ListenSCIONWithBindSVC("udp4", nc.Public, nc.Bind, nc.SVC, 0)
	if err != nil {
		return nil, nil, common.NewBasicError("Unable to listen on SCION", err)
	}
	return conn, pathResolver, nil
}

func (nc *NetworkConfig) initNetwork() (snet.Network, error) {
	var err error
	var network snet.Network
	ticker := time.NewTicker(time.Second)
	timer := time.NewTimer(nc.SCIOND.InitialConnectPeriod.Duration)
	defer ticker.Stop()
	defer timer.Stop()
	// XXX(roosd): Initial retrying is implemented here temporarily.
	// In https://github.com/scionproto/scion/issues/1974 this will be
	// done transparently and pushed to snet.NewNetwork.
Top:
	for {
		network, err = snet.NewNetwork(nc.IA, nc.SCIOND.Path, reliable.NewDispatcherService(""))
		if err == nil || nc.SCIOND.Path == "" {
			break
		}
		select {
		case <-ticker.C:
		case <-timer.C:
			break Top
		}
	}
	return network, err
}

func buildQUICConfig(conn net.PacketConn) (*messenger.QUICConfig, error) {
	// FIXME(scrye): Hardcode the crypto for now, because this is only used for
	// testing. To make QUIC RPC deployable, these need to be specified in the
	// configuration file.
	cert, err := tls.LoadX509KeyPair("gen-certs/tls.pem", "gen-certs/tls.key")
	if err != nil {
		return nil, err
	}

	return &messenger.QUICConfig{
		Conn: conn,
		TLSConfig: &tls.Config{
			Certificates:       []tls.Certificate{cert},
			InsecureSkipVerify: true,
		},
	}, nil
}

func InitInfraEnvironment(topologyPath string) *env.Env {
	return InitInfraEnvironmentFunc(topologyPath, nil)
}

// InitInfraEnvironmentFunc sets up the environment by first calling
// env.RealoadTopology and then the provided function.
func InitInfraEnvironmentFunc(topologyPath string, f func()) *env.Env {
	return env.SetupEnv(
		func() {
			env.ReloadTopology(topologyPath)
			if f != nil {
				f()
			}
		},
	)
}
