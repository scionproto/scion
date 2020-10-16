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

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/sig_mgmt"
	"github.com/scionproto/scion/go/lib/env"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/pathmgr"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/sciond/fake"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/snet/addrutil"
	"github.com/scionproto/scion/go/lib/sock/reliable"
	sigconfig "github.com/scionproto/scion/go/pkg/sig/config"
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
	PathMgr    pathmgr.Resolver
	Dispatcher reliable.Dispatcher
	Network    *snet.SCIONNetwork
	CtrlAddr   net.IP
	CtrlPort   int
	DataAddr   net.IP
	DataPort   int
	CtrlConn   *snet.Conn
)

func Init(cfg sigconfig.SigConf, sdCfg env.SCIONDClient, features env.Features) error {
	network, sciondConn, resolver, err := initNetwork(cfg, sdCfg, features)
	if err != nil {
		return common.NewBasicError("Error creating local SCION Network context", err)
	}

	ip := cfg.CtrlAddr
	if len(ip) == 0 || ip.IsUnspecified() {
		ip, err = findDefaultLocalIP(context.Background(), sciondConn)
		if err != nil {
			return serrors.WrapStr("unable to determine default local IP", err)
		}
	}

	CtrlAddr = ip
	CtrlPort = int(cfg.CtrlPort)
	DataAddr = ip
	DataPort = int(cfg.DataPort)
	conn, err := network.Listen(context.Background(), "udp",
		&net.UDPAddr{IP: CtrlAddr, Port: CtrlPort}, addr.SvcSIG)
	if err != nil {
		return common.NewBasicError("Error creating ctrl socket", err)
	}

	CtrlConn = conn
	Network = network
	PathMgr = resolver

	return nil
}

func initNetwork(cfg sigconfig.SigConf, sdCfg env.SCIONDClient,
	features env.Features) (*snet.SCIONNetwork, sciond.Connector, pathmgr.Resolver, error) {

	var err error
	Dispatcher = reliable.NewDispatcher("")
	var sciondConn sciond.Connector
	if sdCfg.FakeData != "" {
		sciondConn, err = initFakeSCIOND(cfg, sdCfg, features)
		if err != nil {
			return nil, nil, nil, serrors.WrapStr("unable to initialize fake SCIOND service", err)
		}
	} else {
		sciondConn, err = initRealSCIOND(cfg, sdCfg, features)
		if err != nil {
			return nil, nil, nil, serrors.WrapStr("unable to initialize SCIOND service", err)
		}
	}

	ia, err := sciondConn.LocalIA(context.Background())
	if err != nil {
		return nil, nil, nil, serrors.WrapStr("discovering local ISD-AS", err)
	}
	pathResolver := pathmgr.New(sciondConn, pathmgr.Timers{})
	network := &snet.SCIONNetwork{
		LocalIA: ia,
		Dispatcher: &snet.DefaultPacketDispatcherService{
			Dispatcher: Dispatcher,
			SCMPHandler: snet.DefaultSCMPHandler{
				RevocationHandler: pathResolver,
			},
		},
	}
	return network, sciondConn, pathResolver, nil
}

func initFakeSCIOND(cfg sigconfig.SigConf,
	sdCfg env.SCIONDClient, features env.Features) (sciond.Connector, error) {

	return fake.NewFromFile(sdCfg.FakeData)
}

func initRealSCIOND(cfg sigconfig.SigConf,
	sdCfg env.SCIONDClient, features env.Features) (sciond.Connector, error) {

	// TODO(karampok). To be kept until https://github.com/scionproto/scion/issues/3377
	deadline := time.Now().Add(sdCfg.InitialConnectPeriod.Duration)
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	var retErr error
	for tries := 0; time.Now().Before(deadline); tries++ {
		sciondConn, err := sciond.NewService(sdCfg.Address).Connect(ctx)
		if err == nil {
			return sciondConn, nil
		}
		log.Debug("SIG is retrying to get NewNetwork", "err", err)
		retErr = err
		time.Sleep(time.Second)
	}
	return nil, retErr
}

func ValidatePort(desc string, port int) error {
	if port < 1 || port > MaxPort {
		return common.NewBasicError("Invalid port", nil,
			"min", 1, "max", MaxPort, "actual", port, "desc", desc)
	}
	return nil
}

func GetMgmtAddr() sig_mgmt.Addr {
	return *sig_mgmt.NewAddr(addr.HostFromIP(CtrlAddr), uint16(CtrlPort),
		addr.HostFromIP(DataAddr), uint16(DataPort))
}

// TODO(matzf): this is a simple, hopefully temporary, workaround to not having
// wildcard addresses in snet.
// Here we just use a seemingly sensible default IP, but in the general case
// the local IP would depend on the next hop of selected path. This approach
// will not work in more complicated setups where e.g. different network
// interface are used to talk to different AS interfaces.
// Once a available, a wildcard address should be used and this should simply
// be removed.
//
// findDefaultLocalIP returns _a_ IP of this host in the local AS.
func findDefaultLocalIP(ctx context.Context, sciondConn sciond.Connector) (net.IP, error) {
	hostInLocalAS, err := findAnyHostInLocalAS(ctx, sciondConn)
	if err != nil {
		return nil, err
	}
	return addrutil.ResolveLocal(hostInLocalAS)
}

// findAnyHostInLocalAS returns the IP address of some (infrastructure) host in the local AS.
func findAnyHostInLocalAS(ctx context.Context, sciondConn sciond.Connector) (net.IP, error) {
	addr, err := sciond.TopoQuerier{Connector: sciondConn}.UnderlayAnycast(ctx, addr.SvcCS)
	if err != nil {
		return nil, err
	}
	return addr.IP, nil
}
