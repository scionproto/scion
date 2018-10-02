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
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/env"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/disp"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/infra/transport"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/snet/snetproxy"
)

const (
	ErrAppUnableToInitMessenger = "Unable to initialize SCION Infra Messenger"
)

func InitMessenger(ia addr.IA, public, bind *snet.Addr, svc addr.HostSVC,
	reconnectToDispatcher bool, store infra.TrustStore) (infra.Messenger, error) {

	conn, err := initNetworking(ia, public, bind, svc, reconnectToDispatcher)
	if err != nil {
		return nil, err
	}
	msger := messenger.New(
		ia,
		disp.New(
			transport.NewPacketTransport(conn),
			messenger.DefaultAdapter,
			log.Root(),
		),
		store,
		log.Root(),
		nil,
	)
	store.SetMessenger(msger)
	return msger, nil
}

func initNetworking(ia addr.IA, public, bind *snet.Addr, svc addr.HostSVC,
	reconnectToDispatcher bool) (snet.Conn, error) {

	var network snet.Network
	network, err := snet.NewNetwork(ia, "", "")
	if err != nil {
		return nil, common.NewBasicError("Unable to create network", err)
	}
	if reconnectToDispatcher {
		network = snetproxy.NewProxyNetwork(network)
	}
	conn, err := network.ListenSCIONWithBindSVC("udp4", public, bind, svc, 0)
	if err != nil {
		return nil, common.NewBasicError("Unable to listen on SCION", err)
	}
	return conn, nil
}

func InitInfraEnvironment(topologyPath string) *env.Env {
	return env.SetupEnv(
		func() {
			env.ReloadTopology(topologyPath)
		},
	)
}
