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

package sigcmn

import (
	"flag"
	"fmt"
	"net"

	//log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/pathmgr"
	"github.com/netsec-ethz/scion/go/lib/snet"
	"github.com/netsec-ethz/scion/go/sig/mgmt"
)

const (
	DefaultCtrlPort  = 10081
	DefaultEncapPort = 10080
	MaxPort          = (1 << 16) - 1
	SIGHdrSize       = 8
)

var (
	CtrlPort       = flag.Int("ctrlport", DefaultCtrlPort, "control data port (e.g., keepalives)")
	EncapPort      = flag.Int("encapport", DefaultEncapPort, "encapsulation data port")
	sciondPath     = flag.String("sciond", "", "SCIOND socket path")
	dispatcherPath = flag.String("dispatcher", "/run/shm/dispatcher/default.sock",
		"SCION Dispatcher path")
)

var (
	IA       *addr.ISD_AS
	Host     addr.HostAddr
	PathMgr  *pathmgr.PR
	CtrlConn *snet.Conn
	MgmtAddr *mgmt.Addr
)

func Init(ia *addr.ISD_AS, ip net.IP) error {
	var err error
	IA = ia
	Host = addr.HostFromIP(ip)
	if err = ValidatePort("local ctrl", *CtrlPort); err != nil {
		return err
	}
	if err = ValidatePort("local encap", *EncapPort); err != nil {
		return err
	}
	MgmtAddr = mgmt.NewAddr(Host, uint16(*CtrlPort), uint16(*EncapPort))
	if *sciondPath == "" {
		*sciondPath = fmt.Sprintf("/run/shm/sciond/sd%s.sock", ia)
	}
	// Initialize SCION local networking module
	err = snet.Init(ia, *sciondPath, *dispatcherPath)
	if err != nil {
		return common.NewCError("Error creating local SCION Network context", "err", err)
	}
	PathMgr = snet.DefNetwork.PathResolver()
	CtrlConn, err = snet.ListenSCION(
		"udp4", &snet.Addr{IA: IA, Host: Host, L4Port: uint16(*CtrlPort)})
	if err != nil {
		return common.NewCError("Error creating ctrl socket", "err", err)
	}
	return nil
}

func CtrlSnetAddr() *snet.Addr {
	return &snet.Addr{
		IA: IA, Host: Host, L4Port: uint16(*CtrlPort),
	}
}

func EncapSnetAddr() *snet.Addr {
	return &snet.Addr{
		IA: IA, Host: Host, L4Port: uint16(*EncapPort),
	}
}

func ValidatePort(desc string, port int) error {
	if port < 1 || port > MaxPort {
		return common.NewCError(fmt.Sprintf("Invalid %s port", desc),
			"min", 1, "max", MaxPort, "actual", port)
	}
	return nil
}
