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

// Package xnet contains low level Linux networking calls (generally related to
// netlink and tunneling)
package xnet

import (
	"io"
	"net"

	"github.com/songgao/water"
	"github.com/vishvananda/netlink"

	"github.com/scionproto/scion/go/lib/common"
)

const (
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
		return nil, nil, common.NewBasicError("Unable to find new TUN device", err, "name", name)
	}
	err = netlink.LinkSetUp(link)
	if err != nil {
		err = common.NewBasicError("Unable to set new TUN device Up", err, "name", name)
		goto Cleanup
	}
	err = netlink.LinkSetTxQLen(link, SIGTxQlen)
	if err != nil {
		err = common.NewBasicError("Unable to set Tx queue length on new TUN device", err,
			"name", name)
		goto Cleanup
	}
	return link, tun, nil
Cleanup:
	// Don't check for errors, as we're already handling one.
	tun.Close()
	netlink.LinkDel(link)
	return nil, nil, err
}

func AddRoute(rTable int, link netlink.Link, dest *net.IPNet, src net.IP) error {
	route := &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       dest,
		Priority:  SIGRPriority,
		Table:     rTable,
	}
	if len(src) > 0 {
		route.Src = src
	}
	if err := netlink.RouteAdd(route); err != nil {
		return common.NewBasicError("EgressReader: Unable to add SIG route", err,
			"route", route)
	}
	return nil
}
