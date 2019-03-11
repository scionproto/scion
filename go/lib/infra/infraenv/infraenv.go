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
	"time"

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
	"github.com/scionproto/scion/go/lib/sock/reliable"
)

const (
	ErrAppUnableToInitMessenger = "Unable to initialize SCION Infra Messenger"
)

func InitMessenger(ia addr.IA, public, bind *snet.Addr, svc addr.HostSVC,
	reconnectToDispatcher bool, store infra.TrustStore) (infra.Messenger, error) {

	return InitMessengerWithSciond(ia, public, bind, svc, reconnectToDispatcher,
		store, env.SciondClient{})
}

func InitMessengerWithSciond(ia addr.IA, public, bind *snet.Addr, svc addr.HostSVC,
	reconnectToDispatcher bool, store infra.TrustStore,
	sciond env.SciondClient) (infra.Messenger, error) {

	conn, err := initNetworking(ia, public, bind, svc, reconnectToDispatcher, sciond)
	if err != nil {
		return nil, err
	}
	msger := messenger.NewMessengerWithMetrics(
		&messenger.Config{
			IA: ia,
			Dispatcher: disp.New(
				transport.NewPacketTransport(conn),
				messenger.DefaultAdapter,
				log.Root(),
			),
			TrustStore: store,
		},
	)
	store.SetMessenger(msger)
	return msger, nil
}

func initNetworking(ia addr.IA, public, bind *snet.Addr, svc addr.HostSVC,
	reconnectToDispatcher bool, sciond env.SciondClient) (snet.Conn, error) {

	var network snet.Network
	network, err := initNetwork(ia, sciond)
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

func initNetwork(ia addr.IA, sciond env.SciondClient) (snet.Network, error) {
	var err error
	var network snet.Network
	ticker := time.NewTicker(time.Second)
	timer := time.NewTimer(sciond.InitialConnectPeriod.Duration)
	defer ticker.Stop()
	defer timer.Stop()
	// XXX(roosd): Initial retrying is implemented here temporarily.
	// In https://github.com/scionproto/scion/issues/1974 this will be
	// done transparently and pushed to snet.NewNetwork.
Top:
	for {
		network, err = snet.NewNetwork(ia, sciond.Path, reliable.NewDispatcherService(""))
		if err == nil || sciond.Path == "" {
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
