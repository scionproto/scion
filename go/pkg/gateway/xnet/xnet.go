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

	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/pkg/gateway/control"
)

const (
	// SIGRPriority is the metric to use when inserting routes in the Linux routing table.
	// This follows the convention of FRR, where BGP routes are inserted with a metric
	// equal to the administrative distance (in the case of BGP, this would be 20).
	// For Gateway routes, the administrative distance is 15, hence the priority.
	SIGRPriority = 15
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
		return nil, nil, serrors.WrapStr("unable to find new TUN device", err, "name", name)
	}
	err = netlink.LinkSetUp(link)
	if err != nil {
		err = serrors.WrapStr("unable to set new TUN device Up", err, "name", name)
		goto Cleanup
	}
	err = netlink.LinkSetTxQLen(link, SIGTxQlen)
	if err != nil {
		err = serrors.WrapStr("unable to set Tx queue length on new TUN device", err,
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

// Open creates a new DeviceHandle backed by a Linux network interface of type tun.
// The interface will have the specified name.
func Open(name string) (control.DeviceHandle, error) {
	link, rwc, err := ConnectTun(name)
	if err != nil {
		return nil, err
	}
	return &deviceHandle{
		link:            link,
		ReadWriteCloser: rwc,
	}, nil
}

type deviceHandle struct {
	link netlink.Link
	io.ReadWriteCloser
}

func (h deviceHandle) AddRoute(r *control.Route) error {
	return AddRoute(0, h.link, r.Prefix, r.Source)
}

func (h deviceHandle) DeleteRoute(r *control.Route) error {
	return DeleteRoute(0, h.link, r.Prefix, r.Source)
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
		return serrors.WrapStr("EgressReader: Unable to add SIG route", err,
			"route", route)
	}
	return nil
}

func DeleteRoute(rTable int, link netlink.Link, dest *net.IPNet, src net.IP) error {
	route := &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       dest,
		Priority:  SIGRPriority,
		Table:     rTable,
	}
	if len(src) > 0 {
		route.Src = src
	}
	if err := netlink.RouteDel(route); err != nil {
		return serrors.WrapStr("EgressReader: Unable to delete SIG route", err,
			"route", route)
	}
	return nil
}
