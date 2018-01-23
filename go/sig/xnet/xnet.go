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

// Package xnet contains low level Linux networking calls (generally related to netlink and tunneling)
package xnet

import (
	"io"
	"net"

	//log "github.com/inconshreveable/log15"
	"github.com/songgao/water"
	"github.com/vishvananda/netlink"

	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/sig/sigcmn"
)

const (
	SIGRTable    = 11
	SIGRPriority = 100
	SIGTxQlen    = 1000
)

// ConnectTun creates (or opens) interface name, and then sets its state to up
func ConnectTun(name string) (netlink.Link, io.ReadWriteCloser, error) {
	tun, err := water.New(water.Config{
		DeviceType:             water.TUN,
		PlatformSpecificParams: water.PlatformSpecificParams{Name: name}})
	if err != nil {
		return nil, nil, err
	}
	link, err := netlink.LinkByName(tun.Name())
	if err != nil {
		tun.Close()
		// Should clean up the tun device, but if we can't find it...
		return nil, nil, common.NewCError("Unable to find new TUN device",
			"name", name, "err", err)
	}
	err = netlink.LinkSetUp(link)
	if err != nil {
		err = common.NewCError("Unable to set new TUN device Up", "name", name, "err", err)
		goto Cleanup
	}
	err = netlink.LinkSetTxQLen(link, SIGTxQlen)
	if err != nil {
		err = common.NewCError("Unable to set Tx queue lenght on new TUN device",
			"name", name, "err", err)
		goto Cleanup
	}
	return link, tun, nil
Cleanup:
	// Don't check for errors, as we're already handling one.
	tun.Close()
	netlink.LinkDel(link)
	return nil, nil, err
}

func NewRoute(link netlink.Link, dest *net.IPNet) *netlink.Route {
	return &netlink.Route{
		LinkIndex: link.Attrs().Index, Src: sigcmn.Host.IP(), Dst: dest,
		Priority: SIGRPriority, Table: SIGRTable,
	}
}
