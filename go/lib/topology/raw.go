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
	"strconv"

	"github.com/scionproto/scion/go/lib/serrors"
	jsontopo "github.com/scionproto/scion/go/lib/topology/json"
)

func rawAddrToTopoAddr(rawAddr string) (*TopoAddr, error) {
	a, err := rawAddrToUDPAddr(rawAddr)
	if err != nil {
		return nil, err
	}
	return &TopoAddr{
		SCIONAddress: a,
		UnderlayAddress: &net.UDPAddr{
			IP:   append(a.IP[:0:0], a.IP...),
			Port: EndhostPort,
			Zone: a.Zone,
		},
	}, nil
}

func rawBRIntfTopoBRAddr(i *jsontopo.BRInterface) (*net.UDPAddr, error) {
	rh, port, err := splitHostPort(i.Underlay.Public)
	if err != nil {
		return nil, err
	}
	var rawIP string
	if i.Underlay.Bind != "" {
		rawIP = i.Underlay.Bind
	} else if rh != "" {
		rawIP = rh
	} else {
		return nil, serrors.WithCtx(errUnderlayAddrNotFound, "underlay", i.Underlay)
	}
	return resolveToUDPAddr(rawIP, port)
}

func splitHostPort(rawAddr string) (string, int, error) {
	rh, rp, err := net.SplitHostPort(rawAddr)
	if err != nil {
		return "", 0, serrors.WrapStr("failed to split host port", err)
	}
	port, err := strconv.Atoi(rp)
	if err != nil {
		return "", 0, serrors.WrapStr("failed to parse port", err)
	}
	return rh, port, nil
}

func resolveToUDPAddr(rawIP string, port int) (*net.UDPAddr, error) {
	ipAddr, err := net.ResolveIPAddr("ip", rawIP)
	if err != nil {
		return nil, serrors.WrapStr("failed to resolve ip", err, "raw", rawIP)
	}
	if ipAddr.IP == nil {
		return nil, serrors.New("missing/invalid IP", "raw", rawIP)
	}
	// Convert to 4-byte format to simplify testing
	if ip4 := ipAddr.IP.To4(); ip4 != nil {
		ipAddr.IP = ip4
	}
	return &net.UDPAddr{
		IP:   append(ipAddr.IP[:0:0], ipAddr.IP...),
		Port: port,
		Zone: ipAddr.Zone,
	}, nil
}

func rawAddrToUDPAddr(rawAddr string) (*net.UDPAddr, error) {
	rh, port, err := splitHostPort(rawAddr)
	if err != nil {
		return nil, err
	}
	return resolveToUDPAddr(rh, port)
}
