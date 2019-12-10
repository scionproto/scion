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

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/serrors"
	jsontopo "github.com/scionproto/scion/go/lib/topology/json"
	"github.com/scionproto/scion/go/lib/topology/overlay"
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

	ip := net.ParseIP(addressInfo.Public.Address.Addr)
	if ip == nil {
		return nil, serrors.WithCtx(errInvalidPub, "address", addressInfo.Public.Address.Addr)
	}

	if mustBeIPv6 && ip.To4() != nil {
		return nil, serrors.WithCtx(errInvalidPub, "address", addressInfo.Public.Address.Addr)
	}
	if mustBeIPv4 {
		// Convert to 4-byte format to simplify testing
		ip = ip.To4()
		if ip == nil {
			return nil, serrors.WithCtx(errInvalidPub,
				"address", addressInfo.Public.Address.Addr)
		}
	}

	return &TopoAddr{
		SCIONAddress: &net.UDPAddr{
			IP:   ip,
			Port: addressInfo.Public.Address.L4Port,
		},
		UnderlayAddress: &net.UDPAddr{
			IP:   append(ip[:0:0], ip...),
			Port: EndhostPort,
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

	ip := net.ParseIP(addressInfo.PublicUnderlay.Addr)
	if ip == nil {
		return nil, serrors.WithCtx(errInvalidPub, "address", addressInfo.PublicUnderlay.Addr)
	}

	if mustBeIPv6 && ip.To4() != nil {
		return nil, serrors.WithCtx(errInvalidPub, "address", addressInfo.PublicUnderlay.Addr)
	}
	if mustBeIPv4 {
		// Convert to 4-byte format to simplify testing
		ip = ip.To4()
		if ip == nil {
			return nil, serrors.WithCtx(errInvalidPub, "address", addressInfo.PublicUnderlay.Addr)
		}
	}

	return &net.UDPAddr{
		IP:   append(ip[:0:0], ip...),
		Port: addressInfo.PublicUnderlay.UnderlayPort,
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

func rawBRIntfRemoteBRAddr(b *jsontopo.BRInterface, o overlay.Type) (*net.UDPAddr, error) {
	l3 := addr.HostFromIPStr(b.RemoteUnderlay.Addr)
	if l3 == nil {
		return nil, common.NewBasicError("Could not parse remote IP from string", nil,
			"ip", b.RemoteUnderlay.Addr)
	}
	if !o.IsUDP() && (b.RemoteUnderlay.UnderlayPort != 0) {
		return nil, serrors.WithCtx(errUnderlayPort, "addr", b.RemoteUnderlay)
	}
	return &net.UDPAddr{IP: l3.IP(), Port: b.RemoteUnderlay.UnderlayPort}, nil
}

func rawBRIntfTopoBRAddr(i *jsontopo.BRInterface) (*net.UDPAddr, error) {
	if i.Underlay != "UDP/IPv4" && i.Underlay != "UDP/IPv6" {
		return nil, serrors.WithCtx(errUnsupportedUnderlay, "underlay", i.Underlay)
	}

	mustBeIPv4 := i.Underlay == "UDP/IPv4"
	mustBeIPv6 := i.Underlay == "UDP/IPv6"

	var udpAddr net.UDPAddr
	if i.BindUnderlay != nil {
		udpAddr.IP = net.ParseIP(i.BindUnderlay.Addr)
	} else {
		if i.PublicUnderlay == nil {
			return nil, serrors.WithCtx(errUnderlayAddrNotFound, "underlay", i.Underlay)
		}
		udpAddr.IP = net.ParseIP(i.PublicUnderlay.Addr)
	}
	if i.PublicUnderlay != nil {
		udpAddr.Port = i.PublicUnderlay.UnderlayPort
	}

	if udpAddr.IP == nil {
		return nil, serrors.WithCtx(errInvalidPub, "address", i.PublicUnderlay.Addr)
	}
	if mustBeIPv4 {
		udpAddr.IP = udpAddr.IP.To4()
		if udpAddr.IP == nil {
			return nil, serrors.WithCtx(errExpectedIPv4FoundIPv6, "address", i.PublicUnderlay.Addr)
		}
	}
	if mustBeIPv6 && udpAddr.IP.To4() != nil {
		return nil, serrors.WithCtx(errExpectedIPv6FoundIPv4, "address", i.PublicUnderlay.Addr)
	}
	return &udpAddr, nil
}
