// Copyright 2017 ETH Zurich
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

package sigcmn

import (
	"context"
	"net"
	"time"

	"github.com/scionproto/scion/go/godispatcher/dispatcher"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/sig_mgmt"
	"github.com/scionproto/scion/go/lib/env"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/pathmgr"
	"github.com/scionproto/scion/go/lib/sciond/fake"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/sock/reliable"
	"github.com/scionproto/scion/go/sig/internal/sigconfig"
	"github.com/scionproto/scion/go/sig/internal/snetmigrate"
)

const (
	MaxPort    = (1 << 16) - 1
	SIGHdrSize = 8
)

var (
	DefV4Net = &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, net.IPv4len*8)}
	DefV6Net = &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, net.IPv6len*8)}
)

var (
	IA   addr.IA
	Host addr.HostAddr

	PathMgr    pathmgr.Resolver
	Dispatcher reliable.Dispatcher
	Network    *snet.SCIONNetwork
	CtrlConn   snet.Conn
	MgmtAddr   *sig_mgmt.Addr
	encapPort  uint16
)

func Init(cfg sigconfig.SigConf, sdCfg env.SCIONDClient) error {
	IA = cfg.IA
	Host = addr.HostFromIP(cfg.IP)
	MgmtAddr = sig_mgmt.NewAddr(Host, cfg.CtrlPort, cfg.EncapPort)
	encapPort = cfg.EncapPort

	network, resolver, err := initNetwork(cfg, sdCfg)
	if err != nil {
		return common.NewBasicError("Error creating local SCION Network context", err)
	}
	conn, err := network.Listen(context.Background(), "udp",
		&net.UDPAddr{IP: Host.IP(), Port: int(cfg.CtrlPort)}, addr.SvcSIG)
	if err != nil {
		return common.NewBasicError("Error creating ctrl socket", err)
	}

	CtrlConn = conn
	Network = network
	PathMgr = resolver

	return nil
}

func initNetwork(cfg sigconfig.SigConf,
	sdCfg env.SCIONDClient) (*snet.SCIONNetwork, pathmgr.Resolver, error) {

	var err error
	Dispatcher, err = newDispatcher(cfg)
	if err != nil {
		return nil, nil, serrors.WrapStr("unable to initialize SCION dispatcher", err)
	}
	if sdCfg.FakeData != "" {
		return initNetworkWithFakeSCIOND(cfg, sdCfg)
	}
	return initNetworkWithRealSCIOND(cfg, sdCfg)
}

func initNetworkWithFakeSCIOND(cfg sigconfig.SigConf,
	sdCfg env.SCIONDClient) (*snet.SCIONNetwork, pathmgr.Resolver, error) {

	sciondConn, err := fake.NewFromFile(sdCfg.FakeData)
	if err != nil {
		return nil, nil, serrors.WrapStr("unable to initialize fake SCIOND service", err)
	}
	pathResolver := pathmgr.New(sciondConn, pathmgr.Timers{}, sdCfg.PathCount)
	network := snet.NewNetworkWithPR(cfg.IA, Dispatcher, &snetmigrate.PathQuerier{
		Resolver: pathResolver,
		IA:       cfg.IA,
	}, pathResolver)
	return network, pathResolver, nil
}

func initNetworkWithRealSCIOND(cfg sigconfig.SigConf,
	sdCfg env.SCIONDClient) (*snet.SCIONNetwork, pathmgr.Resolver, error) {

	// TODO(karampok). To be kept until https://github.com/scionproto/scion/issues/3377
	deadline := time.Now().Add(sdCfg.InitialConnectPeriod.Duration)
	var retErr error
	for tries := 0; time.Now().Before(deadline); tries++ {
		resolver, err := snetmigrate.ResolverFromSD(sdCfg.Address, sdCfg.PathCount)
		if err == nil {
			return snet.NewNetworkWithPR(cfg.IA, Dispatcher, &snetmigrate.PathQuerier{
				Resolver: resolver,
				IA:       cfg.IA,
			}, resolver), resolver, nil
		}
		log.Debug("SIG is retrying to get NewNetwork", "err", err)
		retErr = err
		time.Sleep(time.Second)
	}
	return nil, nil, retErr
}

func newDispatcher(cfg sigconfig.SigConf) (reliable.Dispatcher, error) {
	if cfg.DispatcherBypass == "" {
		log.Info("Regular SCION dispatcher", "addr", cfg.DispatcherBypass)
		return reliable.NewDispatcher(cfg.Dispatcher), nil
	}
	// Initialize dispatcher bypass.
	log.Info("Bypassing SCION dispatcher", "addr", cfg.DispatcherBypass)
	dispServer, err := dispatcher.NewServer(cfg.DispatcherBypass)
	if err != nil {
		return nil, serrors.WrapStr("unable to initialize bypass dispatcher", err)
	}
	go func() {
		defer log.HandlePanic()
		err := dispServer.Serve()
		if err != nil {
			log.Error("Bypass dispatcher failed", "err", err)
		}
	}()
	return dispServer, nil
}

func EncapSnetAddr() *snet.UDPAddr {
	return &snet.UDPAddr{IA: IA, Host: &net.UDPAddr{IP: Host.IP(), Port: int(encapPort)}}
}

func ValidatePort(desc string, port int) error {
	if port < 1 || port > MaxPort {
		return common.NewBasicError("Invalid port", nil,
			"min", 1, "max", MaxPort, "actual", port, "desc", desc)
	}
	return nil
}
