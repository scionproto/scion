// Copyright 2020 Anapaya Systems
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

package control

import (
	"io"
	"net"
	"sync"

	"github.com/google/gopacket/layers"
)

// NewPublishingRoutingTable publishes routes from rt via the routePublisher. The methods
// of the returned object can safely be used concurrently by multiple goroutines.
func NewPublishingRoutingTable(rcs []*RoutingChain, rt RoutingTable,
	routePublisher Publisher, nextHop, sourceIPv4, sourceIPv6 net.IP) RoutingTable {

	var remoteSites []*remoteSite
	for _, rc := range rcs {
		site := &remoteSite{
			prefixes:       rc.Prefixes,
			trafficClasses: make(map[int]PktWriter),
		}
		for _, tm := range rc.TrafficMatchers {
			site.trafficClasses[tm.ID] = nil
		}
		remoteSites = append(remoteSites, site)
	}

	return &publishingRoutingTable{
		routingTable:   rt,
		routePublisher: routePublisher,
		nextHop:        nextHop,
		sourceIPv4:     sourceIPv4,
		sourceIPv6:     sourceIPv6,
		active:         false,
		routes:         make(map[int]PktWriter),
		remoteSites:    remoteSites,
	}
}

type publishingRoutingTable struct {
	mutex          sync.RWMutex
	routingTable   RoutingTable
	routePublisher Publisher
	nextHop        net.IP
	sourceIPv4     net.IP
	sourceIPv6     net.IP
	// active is true, if the routing table is being actively used at the moment.
	active bool
	// routes keeps track of routes while routing table is in inactive state.
	routes map[int]PktWriter
	// remoteSites is a list of remote sites. Site is a part of remote AS serving
	// particular set of prefixes.
	remoteSites []*remoteSite
}

type remoteSite struct {
	prefixes       []*net.IPNet
	trafficClasses map[int]PktWriter
}

func (r *remoteSite) healthy() bool {
	// This is the core of the health-determination mechanism.
	// If remote site is unhealthy, the corresponding routes will be retracted.
	// Note that there's no good solution here. Either we consider remote site
	// unhealthy if all traffic classes can't get through or if one of the traffic
	// classes can't. In the former case (the currently used solution) a single
	// healthy traffic class overrides all the unhealthy ones and the unhealthy
	// traffic classes get blackholed. In the latter case a single unhealthy traffic
	// class results in retraction of prefixes and even healhy traffic classes may
	// stop working (depending on whether user's backup solution works or not).
	for _, session := range r.trafficClasses {
		if session != nil {
			return true
		}
	}
	return false
}

func (rtw *publishingRoutingTable) Activate() {
	rtw.mutex.Lock()
	defer rtw.mutex.Unlock()

	if rtw.active {
		panic("activating active routing table")
	}
	rtw.routingTable.Activate()
	rtw.active = true
	// Activate sessions that have been added while in inactive state.
	for index, session := range rtw.routes {
		rtw.setSessionLocked(index, session)
	}
}

func (rtw *publishingRoutingTable) Deactivate() {
	rtw.mutex.Lock()
	defer rtw.mutex.Unlock()

	if !rtw.active {
		panic("deactivating inactive routing table")
	}
	rtw.routingTable.Deactivate()
	// Retract the published routes.
	rtw.routePublisher.Close()
	rtw.routePublisher = nil
	rtw.active = false
}

func (rtw *publishingRoutingTable) RouteIPv4(pkt layers.IPv4) PktWriter {
	rtw.mutex.RLock()
	defer rtw.mutex.RUnlock()

	return rtw.routingTable.RouteIPv4(pkt)
}

func (rtw *publishingRoutingTable) RouteIPv6(pkt layers.IPv6) PktWriter {
	rtw.mutex.RLock()
	defer rtw.mutex.RUnlock()

	return rtw.routingTable.RouteIPv6(pkt)
}

func (rtw *publishingRoutingTable) SetSession(index int, session PktWriter) error {
	rtw.mutex.Lock()
	defer rtw.mutex.Unlock()

	return rtw.setSessionLocked(index, session)
}

func (rtw *publishingRoutingTable) setSessionLocked(index int, session PktWriter) error {
	if !rtw.active {
		rtw.routes[index] = session
		return nil
	}
	if err := rtw.routingTable.SetSession(index, session); err != nil {
		return err
	}
	for _, site := range rtw.remoteSites {
		_, ok := site.trafficClasses[index]
		if !ok {
			continue
		}
		wasHealthy := site.healthy()
		site.trafficClasses[index] = session
		isHealthy := site.healthy()
		if !wasHealthy && isHealthy {
			for _, prefix := range site.prefixes {
				rtw.routePublisher.AddRoute(Route{
					Prefix:  prefix,
					Source:  rtw.sourceForPrefix(prefix),
					NextHop: rtw.nextHop,
				})
			}
		}
	}
	return nil
}

func (rtw *publishingRoutingTable) ClearSession(index int) error {
	rtw.mutex.Lock()
	defer rtw.mutex.Unlock()

	if !rtw.active {
		delete(rtw.routes, index)
		return nil
	}
	if err := rtw.routingTable.ClearSession(index); err != nil {
		return err
	}
	for _, site := range rtw.remoteSites {
		_, ok := site.trafficClasses[index]
		if !ok {
			continue
		}
		wasHealthy := site.healthy()
		site.trafficClasses[index] = nil
		isHealthy := site.healthy()
		if wasHealthy && !isHealthy {
			for _, prefix := range site.prefixes {
				rtw.routePublisher.DeleteRoute(Route{
					Prefix:  prefix,
					Source:  rtw.sourceForPrefix(prefix),
					NextHop: rtw.nextHop,
				})
			}
		}
	}
	return nil
}

func (rtw *publishingRoutingTable) DiagnosticsWrite(w io.Writer) {
	if dw, ok := rtw.routingTable.(DiagnosticsWriter); ok {
		dw.DiagnosticsWrite(w)
	}
}

// sourceForPrefix returns the appropriate source hint for IPv4/IPv6 prefixes
func (rtw *publishingRoutingTable) sourceForPrefix(prefix *net.IPNet) net.IP {
	if prefix.IP.To4() == nil {
		return rtw.sourceIPv6
	} else {
		return rtw.sourceIPv4
	}
}
