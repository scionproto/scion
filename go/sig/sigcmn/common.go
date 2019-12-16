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
	"net"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/env"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/sock/reliable"
	"github.com/scionproto/scion/go/sig/internal/pathmgr"
	"github.com/scionproto/scion/go/sig/internal/sigconfig"
	"github.com/scionproto/scion/go/sig/internal/snetmigrate"
	"github.com/scionproto/scion/go/sig/mgmt"
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

	PathMgr   pathmgr.Resolver
	Network   *snet.SCIONNetwork
	CtrlConn  snet.Conn
	MgmtAddr  *mgmt.Addr
	encapPort uint16
)

func Init(cfg sigconfig.SigConf, sdCfg env.SciondClient) error {
	IA = cfg.IA
	Host = addr.HostFromIP(cfg.IP)
	MgmtAddr = mgmt.NewAddr(Host, cfg.CtrlPort, cfg.EncapPort)
	encapPort = cfg.EncapPort

	ds := reliable.NewDispatcher(cfg.Dispatcher)
	// TODO(karampok). To be kept until https://github.com/scionproto/scion/issues/3377
	wait := func() (*snet.SCIONNetwork, pathmgr.Resolver, error) {
		deadline := time.Now().Add(sdCfg.InitialConnectPeriod.Duration)
		var retErr error
		for tries := 0; time.Now().Before(deadline); tries++ {
			resolver, err := snetmigrate.ResolverFromSD(sdCfg.Path)
			if err == nil {
				return snet.NewNetworkWithPR(cfg.IA, ds, &snetmigrate.PathQuerier{
					Resolver: resolver,
					IA:       cfg.IA,
				}, resolver), resolver, nil
			}
			log.Debug("SIG is retrying to get NewNetwork", err)
			retErr = err
			time.Sleep(time.Second)
		}
		return nil, nil, retErr
	}
	network, resolver, err := wait()
	if err != nil {
		return common.NewBasicError("Error creating local SCION Network context", err)
	}
	conn, err := network.Listen("udp",
		&net.UDPAddr{IP: Host.IP(), Port: int(cfg.CtrlPort)}, addr.SvcSIG, 0)
	if err != nil {
		return common.NewBasicError("Error creating ctrl socket", err)
	}

	CtrlConn = conn
	Network = network
	PathMgr = resolver

	return nil
}

func EncapSnetAddr() *snet.Addr {
	return &snet.Addr{IA: IA, Host: &addr.AppAddr{L3: Host, L4: uint16(encapPort)}}
}

func ValidatePort(desc string, port int) error {
	if port < 1 || port > MaxPort {
		return common.NewBasicError("Invalid port", nil,
			"min", 1, "max", MaxPort, "actual", port, "desc", desc)
	}
	return nil
}
