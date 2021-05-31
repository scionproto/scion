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

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/log"
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

// connectTun creates (or opens) interface name, and then sets its state to up
func connectTun(name string) (netlink.Link, io.ReadWriteCloser, error) {
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
	return open(name)
}

// OpenerWithOptions returns an Open implementation with the desired options attached.
func OpenerWithOptions(options ...DeviceOption) DeviceOpener {
	f := func(name string) (control.Device, error) {
		return open(name, options...)
	}
	return DeviceOpenerFunc(f)
}

// DeviceOpener opens Linux tunnels.
type DeviceOpener interface {
	Open(string) (control.Device, error)
}

type DeviceOpenerFunc func(name string) (control.Device, error)

func (f DeviceOpenerFunc) Open(name string) (control.Device, error) {
	return f(name)
}

// UseNameResolver constructs a control.DeviceOpener implementation that opens
// Linux devices with names resolved using the selected naming function.
func UseNameResolver(namer func(addr.IA) string, opener DeviceOpener) control.DeviceOpener {
	f := func(ia addr.IA) (control.Device, error) {
		n := namer(ia)
		return opener.Open(n)
	}
	return control.DeviceOpenerFunc(f)
}

func open(name string, options ...DeviceOption) (control.Device, error) {
	o := applyDeviceOptions(options)

	if o.routingOnlyNoCreate {
		link, err := netlink.LinkByName(name)
		if err != nil {
			log.SafeDebug(o.logger, "Failed to open tun device", "name", name, "err", err)
			return nil, err
		}
		log.SafeDebug(o.logger, "Successfully opened tun device", "name", name)
		return &deviceHandle{
			link:            link,
			ReadWriteCloser: &errorReadWriteCloser{},
			logger:          o.logger,
		}, nil
	}

	link, rwc, err := connectTun(name)
	if err != nil {
		log.SafeDebug(o.logger, "Failed to open tun device", "name", name, "err", err)
		return nil, err
	}
	log.SafeDebug(o.logger, "Successfully opened tun device", "name", name)

	return &deviceHandle{
		link:            link,
		ReadWriteCloser: rwc,
		logger:          o.logger,
	}, nil
}

type deviceHandle struct {
	link   netlink.Link
	logger log.Logger
	io.ReadWriteCloser
}

func (h deviceHandle) AddRoute(r *control.Route) error {
	err := addRoute(0, h.link, r.Prefix, r.Source)
	if err != nil {
		log.SafeDebug(h.logger, "Failed to add route",
			"tun", h.link.Attrs().Name, "route", r, "err", err)
		return err
	}
	log.SafeDebug(h.logger,
		"Successfully added route", "tun", h.link.Attrs().Name, "route", r)
	return nil
}

func (h deviceHandle) DeleteRoute(r *control.Route) error {
	err := deleteRoute(0, h.link, r.Prefix, r.Source)
	if err != nil {
		log.SafeDebug(h.logger, "Failed to delete route",
			"tun", h.link.Attrs().Name, "route", r, "err", err)
		return err
	}
	log.SafeDebug(h.logger,
		"Successfully deleted route", "tun", h.link.Attrs().Name, "route", r)
	return nil
}

func (h deviceHandle) Close() error {
	err := h.ReadWriteCloser.Close()
	if err != nil {
		log.SafeDebug(h.logger, "Failed to close tun device",
			"tun", h.link.Attrs().Name, "err", err)
		return err
	}
	log.SafeDebug(h.logger, "Successfully closed tun device", "tun", h.link.Attrs().Name)
	return nil
}

func addRoute(rTable int, link netlink.Link, dest *net.IPNet, src net.IP) error {
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

func deleteRoute(rTable int, link netlink.Link, dest *net.IPNet, src net.IP) error {
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

type deviceOptions struct {
	logger              log.Logger
	routingOnlyNoCreate bool
}

type DeviceOption func(*deviceOptions)

func applyDeviceOptions(fs []DeviceOption) deviceOptions {
	o := deviceOptions{}
	for _, f := range fs {
		f(&o)
	}
	return o
}

// WithLogger adds logging to device operations. If the logger is nil, no
// logging is performed.
func WithLogger(logger log.Logger) DeviceOption {
	return func(o *deviceOptions) {
		o.logger = logger
	}
}

// WithRoutingOnlyNoCreate signals to create a device handle that supports
// routing but reading and writing return errors. This can be used for
// implementations where data-plane forwarding is done by other applications.
// The device must already exist, and an error will be returned if it does not.
func WithRoutingOnlyNoCreate() DeviceOption {
	return func(o *deviceOptions) {
		o.routingOnlyNoCreate = true
	}
}

type errorReadWriteCloser struct{}

func (*errorReadWriteCloser) Read(b []byte) (int, error) {
	return 0, serrors.New("bug: attempt read on object that does not support read")
}

func (*errorReadWriteCloser) Write(b []byte) (int, error) {
	return 0, serrors.New("bug: attempt write on object that does not support write")
}

func (*errorReadWriteCloser) Close() error {
	return nil
}
