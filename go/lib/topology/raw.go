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

package topology

import (
	"net"

	"github.com/scionproto/scion/go/lib/serrors"
	jsontopo "github.com/scionproto/scion/go/lib/topology/json"
	"github.com/scionproto/scion/go/lib/topology/underlay"
)

func rawAddrMapToTopoAddr(ram jsontopo.NATSCIONAddressMap) (*TopoAddr, error) {
	addressInfo, mustBeIPv6 := rawAddrMapExtractAddressInfo(ram)
	mustBeIPv4 := !mustBeIPv6
	if addressInfo == nil {
		return nil, serrors.WithCtx(errAtLeastOnePub, "address", ram)
	}
	if addressInfo.Bind != nil {
		return nil, serrors.WithCtx(errBindNotSupported, "address", addressInfo.Bind)
	}
	if addressInfo.Public.UnderlayPort != 0 {
		return nil, serrors.WithCtx(errCustomUnderlayPort,
			"port", addressInfo.Public.UnderlayPort)
	}

	ipAddr, err := net.ResolveIPAddr("ip", addressInfo.Public.Address.Addr)
	if err != nil {
		return nil, serrors.Wrap(errInvalidPub, err, "address", addressInfo.Public.Address.Addr)
	}
	// This can happen if the address is empty.
	if ipAddr.IP == nil {
		return nil, serrors.WithCtx(errInvalidPub, "address", addressInfo.Public.Address.Addr)
	}

	if mustBeIPv6 && ipAddr.IP.To4() != nil {
		return nil, serrors.WithCtx(errInvalidPub, "address", addressInfo.Public.Address.Addr)
	}
	if mustBeIPv4 {
		// Convert to 4-byte format to simplify testing
		if ipAddr.IP = ipAddr.IP.To4(); ipAddr.IP == nil {
			return nil, serrors.WithCtx(errInvalidPub,
				"address", addressInfo.Public.Address.Addr)
		}
	}

	return &TopoAddr{
		SCIONAddress: &net.UDPAddr{
			IP:   ipAddr.IP,
			Port: addressInfo.Public.Address.L4Port,
			Zone: ipAddr.Zone,
		},
		UnderlayAddress: &net.UDPAddr{
			IP:   append(ipAddr.IP[:0:0], ipAddr.IP...),
			Port: EndhostPort,
			Zone: ipAddr.Zone,
		},
	}, nil
}

func rawAddrMapExtractAddressInfo(
	ram jsontopo.NATSCIONAddressMap) (info *jsontopo.NATSCIONAddress, is6 bool) {

	a, ok := ram["IPv6"]
	if ok {
		return a, true
	}
	a, ok = ram["IPv4"]
	if ok {
		return a, false
	}
	return nil, false
}

func rawBRAddrMapToUDPAddr(m jsontopo.UnderlayAddressMap) (*net.UDPAddr, error) {
	addressInfo, mustBeIPv6 := rawBRAddrMapExtractAddressInfo(m)
	mustBeIPv4 := !mustBeIPv6
	if addressInfo == nil {
		return nil, serrors.WithCtx(errAtLeastOnePub, "address", m)
	}
	if addressInfo.BindUnderlay != nil {
		return nil, serrors.WithCtx(errBindNotSupported, "address", addressInfo.BindUnderlay)
	}

	ipAddr, err := net.ResolveIPAddr("ip", addressInfo.PublicUnderlay.Addr)
	if err != nil {
		return nil, serrors.Wrap(errInvalidPub, err, "address", addressInfo.PublicUnderlay.Addr)
	}
	// This can happen if the address is empty.
	if ipAddr.IP == nil {
		return nil, serrors.WithCtx(errInvalidPub, "address", addressInfo.PublicUnderlay.Addr)
	}

	if mustBeIPv6 && ipAddr.IP.To4() != nil {
		return nil, serrors.WithCtx(errInvalidPub, "address", addressInfo.PublicUnderlay.Addr)
	}
	if mustBeIPv4 {
		// Convert to 4-byte format to simplify testing
		if ipAddr.IP = ipAddr.IP.To4(); ipAddr.IP == nil {
			return nil, serrors.WithCtx(errInvalidPub, "address", addressInfo.PublicUnderlay.Addr)
		}
	}

	return &net.UDPAddr{
		IP:   append(ipAddr.IP[:0:0], ipAddr.IP...),
		Port: addressInfo.PublicUnderlay.UnderlayPort,
		Zone: ipAddr.Zone,
	}, nil
}

func rawBRAddrMapExtractAddressInfo(
	m jsontopo.UnderlayAddressMap) (info *jsontopo.NATUnderlayAddress, is6 bool) {

	a, ok := m["IPv6"]
	if ok {
		return a, true
	}
	a, ok = m["IPv4"]
	if ok {
		return a, false
	}
	return nil, false
}

func rawBRIntfRemoteBRAddr(b *jsontopo.BRInterface, o underlay.Type) (*net.UDPAddr, error) {
	l3, err := net.ResolveIPAddr("ip", b.RemoteUnderlay.Addr)
	if err != nil {
		return nil, serrors.WrapStr("could not parse remote IP from string", err,
			"input", b.RemoteUnderlay.Addr)
	}
	if l3.IP == nil {
		return nil, serrors.New("empty remote IP", "input", b.RemoteUnderlay.Addr)
	}
	if !o.IsUDP() && (b.RemoteUnderlay.UnderlayPort != 0) {
		return nil, serrors.WithCtx(errUnderlayPort, "addr", b.RemoteUnderlay)
	}
	// Convert to 4-byte format to simplify testing
	if ipv4 := l3.IP.To4(); ipv4 != nil {
		l3.IP = ipv4
	}
	return &net.UDPAddr{
		IP:   l3.IP,
		Port: b.RemoteUnderlay.UnderlayPort,
		Zone: l3.Zone,
	}, nil
}

func rawBRIntfTopoBRAddr(i *jsontopo.BRInterface) (*net.UDPAddr, error) {
	if i.Underlay != "UDP/IPv4" && i.Underlay != "UDP/IPv6" {
		return nil, serrors.WithCtx(errUnsupportedUnderlay, "underlay", i.Underlay)
	}

	mustBeIPv4 := i.Underlay == "UDP/IPv4"
	mustBeIPv6 := i.Underlay == "UDP/IPv6"

	var input string
	if i.BindUnderlay != nil {
		input = i.BindUnderlay.Addr
	} else if i.PublicUnderlay != nil {
		input = i.PublicUnderlay.Addr
	} else {
		return nil, serrors.WithCtx(errUnderlayAddrNotFound, "underlay", i.Underlay)
	}

	ipAddr, err := net.ResolveIPAddr("ip", input)
	if err != nil {
		return nil, serrors.WithCtx(err, "underlay", i.Underlay)
	}
	if ipAddr.IP == nil {
		return nil, serrors.WithCtx(errInvalidPub, "address", i.PublicUnderlay.Addr)
	}
	udpAddr := &net.UDPAddr{
		IP:   ipAddr.IP,
		Zone: ipAddr.Zone,
	}
	if i.PublicUnderlay != nil {
		udpAddr.Port = i.PublicUnderlay.UnderlayPort
	}
	if mustBeIPv4 {
		// Convert to 4-byte format to simplify testing
		if udpAddr.IP = udpAddr.IP.To4(); udpAddr.IP == nil {
			return nil, serrors.WithCtx(errExpectedIPv4FoundIPv6, "address", i.PublicUnderlay.Addr)
		}
	}
	if mustBeIPv6 && udpAddr.IP.To4() != nil {
		return nil, serrors.WithCtx(errExpectedIPv6FoundIPv4, "address", i.PublicUnderlay.Addr)
	}
	return udpAddr, nil
}
