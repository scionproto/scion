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
	"fmt"
	"net"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/pathmgr"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/sig/internal/sigconfig"
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
	IA        addr.IA
	Host      addr.HostAddr
	PathMgr   pathmgr.Resolver
	CtrlConn  snet.Conn
	MgmtAddr  *mgmt.Addr
	encapPort uint16
)

const (
	initAttempts = 100
	initInterval = time.Second
)

func Init(cfg sigconfig.Conf) error {
	var err error
	IA = cfg.IA
	Host = addr.HostFromIP(cfg.IP)
	MgmtAddr = mgmt.NewAddr(Host, cfg.CtrlPort, cfg.EncapPort)
	encapPort = cfg.EncapPort

	// Initialize SCION local networking module
	err = initSNET(cfg, initAttempts, initInterval)
	if err != nil {
		return common.NewBasicError("Error creating local SCION Network context", err)
	}
	PathMgr = snet.DefNetwork.PathResolver()
	l4 := addr.NewL4UDPInfo(cfg.CtrlPort)
	CtrlConn, err = snet.ListenSCIONWithBindSVC("udp4",
		&snet.Addr{IA: IA, Host: &addr.AppAddr{L3: Host, L4: l4}}, nil, addr.SvcSIG)
	if err != nil {
		return common.NewBasicError("Error creating ctrl socket", err)
	}
	return nil
}

func EncapSnetAddr() *snet.Addr {
	l4 := addr.NewL4UDPInfo(uint16(encapPort))
	return &snet.Addr{IA: IA, Host: &addr.AppAddr{L3: Host, L4: l4}}
}

func ValidatePort(desc string, port int) error {
	if port < 1 || port > MaxPort {
		return common.NewBasicError(fmt.Sprintf("Invalid %s port", desc), nil,
			"min", 1, "max", MaxPort, "actual", port)
	}
	return nil
}

// initSNET initializes snet. The number of attempts is specified, as well as the sleep duration.
// This allows the service to wait for a limited time for sciond to become available
func initSNET(cfg sigconfig.Conf, attempts int, sleep time.Duration) (err error) {
	// Initialize SCION local networking module
	for i := 0; i < attempts; i++ {
		if err = snet.Init(cfg.IA, cfg.Sciond, cfg.Dispatcher); err == nil {
			break
		}
		log.Error("Unable to initialize snet", "Retry interval", sleep, "err", err)
		time.Sleep(sleep)
	}
	return err
}
