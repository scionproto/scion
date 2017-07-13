// Package xnet contains low level Linux networking calls (generally related to netlink and tunneling)
package xnet

import (
	"io"
	"net"

	log "github.com/inconshreveable/log15"
	"github.com/songgao/water"
	"github.com/vishvananda/netlink"
)

// ConnectTun creates (or opens) interface name, and then sets its state to up
func ConnectTun(name string) (io.ReadWriteCloser, error) {
	iface, err := water.New(water.Config{
		DeviceType:             water.TUN,
		PlatformSpecificParams: water.PlatformSpecificParams{Name: name}})
	if err != nil {
		return nil, err
	}
	log.Debug("Created tun interface", "name", iface.Name())

	link, err := netlink.LinkByName(name)
	if err != nil {
		return nil, err
	}
	err = netlink.LinkSetUp(link)
	if err != nil {
		return nil, err
	}

	return iface, nil
}

// AddRouteIF adds a new route to destination through device ifname in the Linux Routing Table
func AddRouteIF(destination *net.IPNet, ifname string) error {
	link, err := netlink.LinkByName(ifname)
	if err != nil {
		log.Error("Unable to get device", "name", ifname)
		return err
	}

	index := link.Attrs().Index

	// NOTE: SCION injected routes have a metric of 100
	route := netlink.Route{LinkIndex: index, Dst: destination, Priority: 100}
	err = netlink.RouteAdd(&route)
	if err != nil {
		log.Error("Unable to add route", "route", route)
		return err
	}
	return nil
}

// OpenUDP returns a connection for reading UDP datagrams on 0.0.0.0:port
func OpenUDP(port int) (net.Conn, error) {
	// Listen for data on port 10080
	addr := &net.UDPAddr{IP: net.IPv4zero, Port: 10080}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, err
	}

	return conn, nil
}
