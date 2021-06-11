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
	"bytes"
	"io"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/pktcls"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/pkg/worker"
)

// TrafficMatcher is a traffic matcher with an ID.
type TrafficMatcher struct {
	ID      int
	Matcher pktcls.Cond
}

// RoutingChain defines a chain in the routing table. It links a list of
// prefixes and a traffic class chain, defined via the TrafficMatchers list.
type RoutingChain struct {
	// RemoteIA is the remote ISD-AS to which this routing chain routes, it is
	// set for informational purposes.
	RemoteIA addr.IA
	// The list of prefixes, the order is not relevant.
	Prefixes []*net.IPNet
	// TrafficMatchers defines the traffic matchers in this routing chain. The
	// matchers are evaluated in order within the chain.
	TrafficMatchers []TrafficMatcher
}

// RoutingTableFactory is used by the engine controller to create a fresh routing table.
type RoutingTableFactory interface {
	// New should create a routing table based on the routing chains. The
	// implementation must implement a 2 level based routing: 1. it must do a
	// longest prefix match over all prefixes, 2. for the selected prefix it
	// must evaluate the corresponding traffic matcher list, the first match
	// must be selected.
	New([]*RoutingChain) (RoutingTable, error)
}

// EngineController listens to session configuration updates received from the configuration
// modules. There are no partial updates; once a new configuration comes in, the EngineController
// creates a new engine and replaces the old one.
//
// The EngineController is expected to run for the lifetime of the application and does not support
// shutdown.
//
// Add factories to this type if required for testing.
type EngineController struct {
	// ConfigurationUpdates is the channel on which new configurations for the Gateway sessions
	// are received. Every update will lead to a fresh instance of the forwarding engine,
	// together with a new data-plane configuration. The channel must not be nil.
	ConfigurationUpdates <-chan []*SessionConfig

	// RoutingTableSwapper permits the concurrency-safe swapping of an entire routing table in the
	// data-plane. When the session builder creates a new control-plane engine, it creates a fresh
	// routing table. Once the engine is ready, the fresh routing table is swapped in place of the
	// old one. It must not be nil.
	RoutingTableSwapper RoutingTableSwapper

	// RoutingTableFactory is used by the engine controller to create a fresh routing table.
	// It must not be nil.
	RoutingTableFactory RoutingTableFactory

	// EngineFactory is used to build new engines. It must not be nil.
	EngineFactory EngineFactory

	// RoutePublisherFactory allows to publish routes from the gateway.
	// If nil, no routes will be published.
	RoutePublisherFactory PublisherFactory

	// RouteSourceIPv4 is the source hint for IPv4 routes added to the Linux routing table.
	RouteSourceIPv4 net.IP
	// RouteSourceIPv6 is the source hint for IPv6 routes added to the Linux routing table.
	RouteSourceIPv6 net.IP

	// SwapDelay is the interval between creating a new engine and setting it to be the active
	// engine. If 0, the new engine is immediately swapped in.
	SwapDelay time.Duration

	// Logger is used by the controller to write messages about internal operation. If nil,
	// no logging messages are printed.
	Logger log.Logger

	stateMtx sync.RWMutex
	// engine holds a reference to the forwarding engine currently in use. If nil (such as at
	// startup before the first configuration update arrives), it means no forwarding is currently
	// in effect.
	engine Worker

	workerBase worker.Base
}

// Run starts listening on the channel for updates, and processing existing updates.
func (c *EngineController) Run() error {
	return c.workerBase.RunWrapper(c.validate, c.run)
}

// DiagnosticsWrite writes diagnostics to the writer.
func (c *EngineController) DiagnosticsWrite(w io.Writer) {
	c.stateMtx.RLock()
	defer c.stateMtx.RUnlock()

	if dw, ok := c.engine.(DiagnosticsWriter); ok {
		dw.DiagnosticsWrite(w)
	}
}

// Status prints the status page.
func (c *EngineController) Status(w io.Writer) {
	c.stateMtx.RLock()
	defer c.stateMtx.RUnlock()
	if sw, ok := c.engine.(interface{ Status(io.Writer) }); ok {
		sw.Status(w)
	}
}

func (c *EngineController) validate() error {
	if c.ConfigurationUpdates == nil {
		return serrors.New("configuration update channel must not be nil")
	}
	if c.RoutingTableSwapper == nil {
		return serrors.New("routing table swapper must not be nil")
	}
	if c.RoutingTableFactory == nil {
		return serrors.New("routing table factory must not be nil")
	}
	if c.EngineFactory == nil {
		return serrors.New("engine factory must not be nil")
	}
	return nil
}

func (c *EngineController) run() error {
	for update := range c.ConfigurationUpdates {
		log.SafeDebug(c.Logger, "New forwarding engine configuration found.", "update", update)

		rcs, rcMapping := buildRoutingChains(update)
		// The new forwarding engine uses a completely fresh routing table
		// for the data-plane, built based on the data collected in the new
		// session configurations.
		rt, err := c.RoutingTableFactory.New(rcs)
		if err != nil {
			return serrors.WrapStr("creating routing table", err)
		}
		routingTable := NewPublishingRoutingTable(rcs, rt,
			c.RoutePublisherFactory.NewPublisher(), net.IP{}, c.RouteSourceIPv4, c.RouteSourceIPv6)

		newEngine := c.EngineFactory.New(routingTable, update, rcMapping)

		log.SafeDebug(c.Logger, "Starting new forwarding engine.")
		go func() {
			defer log.HandlePanic()
			if err := newEngine.Run(); err != nil {
				panic(err) // application can't recover from an error here
			}
		}()

		time.Sleep(c.SwapDelay)

		log.SafeDebug(c.Logger, "Swapping data-plane routing to use new forwarding engine.")
		c.RoutingTableSwapper.SetRoutingTable(routingTable)

		if c.engine != nil {
			log.SafeDebug(c.Logger, "Shutting down old forwarding engine.")
			if err := c.engine.Close(); err != nil {
				return serrors.WrapStr("shutting down engine", err)
			}
			log.SafeDebug(c.Logger, "Shut down old forwarding engine")
		}

		c.stateMtx.Lock()
		c.engine = newEngine
		c.stateMtx.Unlock()
	}
	return nil
}

// EngineFactory can be used to create a control-plane engine for a set of session
// configurations. The engine will push updates to the routing table.
type EngineFactory interface {
	New(table RoutingTable, sessions []*SessionConfig, routingTableIndices map[int][]uint8) Worker
}

// DefaultEngineFactory is a template for creating control-plane routing engines.
type DefaultEngineFactory struct {
	// PathMonitor is used by engines to construct registrations for path discovery.
	PathMonitor PathMonitor

	// ProbeConnFactory is used by engines to construct connections for sending and receiving probe
	// packets.
	ProbeConnFactory PacketConnFactory

	// DeviceManager is used to construct tunnel devices needed for forwarding and/or routing.
	DeviceManager DeviceManager

	// DataplaneSessionFactory is used to construct dataplane sessions.
	DataplaneSessionFactory DataplaneSessionFactory

	// Logger is used by engines to write messages about internal operation. If nil,
	// no logging messages are printed. Child engines will inherit this logger.
	Logger log.Logger

	// Metrics contains the metrics that will be modified during engine operation. If empty, no
	// metrics are reported.
	Metrics EngineMetrics
}

func (f *DefaultEngineFactory) New(table RoutingTable,
	sessions []*SessionConfig, routingTableIndices map[int][]uint8) Worker {

	return &Engine{
		SessionConfigs: sessions,
		// The new forwarding engine uses a completely fresh routing table
		// for the data-plane, built based on the data collected in the new
		// session configurations.
		RoutingTable:            table,
		RoutingTableIndices:     routingTableIndices,
		PathMonitor:             f.PathMonitor,
		ProbeConnFactory:        f.ProbeConnFactory,
		DeviceManager:           f.DeviceManager,
		DataplaneSessionFactory: f.DataplaneSessionFactory,
		Logger:                  f.Logger,
		Metrics:                 f.Metrics,
	}
}

// Worker is a generic interface for goroutines used by the control-plane.
type Worker interface {
	// Run starts the worker's task and blocks until the worker has finished or it has been
	// shut down via Close.
	Run() error
	// Close stops a running worker. If called before the worker has started, the worker
	// will skip its task. In this case, both Run and Close will return nil.
	Close() error
}

type gatewaySet map[string]struct{}

func buildRoutingChains(sessionConfigs []*SessionConfig) ([]*RoutingChain, map[int][]uint8) {
	if len(sessionConfigs) == 0 {
		return nil, nil
	}
	routingChains := []*RoutingChain{}
	sessionMap := make(map[int][]uint8)
	trafficMatcherID := 1

	// first we group by IA:
	iaConfigs := make(map[addr.IA][]*SessionConfig)
	var sortedIAs []addr.IA
	for _, sc := range sessionConfigs {
		if _, ok := iaConfigs[sc.IA]; !ok {
			sortedIAs = append(sortedIAs, sc.IA)
		}
		iaConfigs[sc.IA] = append(iaConfigs[sc.IA], sc)
	}
	sort.Slice(sortedIAs, func(i, j int) bool {
		return sortedIAs[i].IAInt() < sortedIAs[j].IAInt()
	})
	// For each prefix, compute the set of gateways that serves it. For each
	// distinct gateway set we need a routing chain.
	for _, ia := range sortedIAs {
		iaSessions := iaConfigs[ia]
		// First for each prefix find the remote gateways that can be used
		// to serve this prefix.
		prefixToGWs := buildPrefixToGatewayMapping(iaSessions)
		// For each gateway set find a unique group ID. The group ID will
		// essentially be the index in the routing chain.
		prefixGroups := buildPrefixGroups(iaSessions, prefixToGWs, len(routingChains))

		// With the group IDs assignment build the routing chains.
		for _, sc := range iaSessions {
			for _, prefix := range sc.Prefixes {
				groupID := prefixGroups[prefix.String()]
				if groupID == len(routingChains) {
					routingChains = append(routingChains, &RoutingChain{
						RemoteIA: ia,
					})
				}
				routingChains[groupID].Prefixes = nonDuplicateAppendNet(
					routingChains[groupID].Prefixes, prefix)
				tmID, ok := findTrafficMatcherID(routingChains[groupID].TrafficMatchers,
					sc.TrafficMatcher)
				if !ok {
					tmID = trafficMatcherID
					routingChains[groupID].TrafficMatchers = append(
						routingChains[groupID].TrafficMatchers,
						TrafficMatcher{ID: tmID, Matcher: sc.TrafficMatcher})
					trafficMatcherID++
				}
				sessionMap[tmID] = nonDuplicateAppendID(sessionMap[tmID], sc.ID)
			}
		}
	}
	return routingChains, sessionMap
}

func buildPrefixToGatewayMapping(iaSessions []*SessionConfig) map[string]gatewaySet {
	prefixToGWs := make(map[string]gatewaySet)
	for _, sc := range iaSessions {
		for _, prefix := range sc.Prefixes {
			prefixKey := prefix.String()
			if _, ok := prefixToGWs[prefixKey]; !ok {
				prefixToGWs[prefixKey] = make(gatewaySet)
			}
			prefixToGWs[prefixKey][sc.Gateway.Control.String()] = struct{}{}
		}
	}
	return prefixToGWs
}

// buildPrefixGroups determines for each prefix in the iaSessions to which
// groupID it belongs. For each unique gateway set we need a different groupID.
// The lowest groupID created will have the value of startID.
func buildPrefixGroups(iaSessions []*SessionConfig,
	prefixToGWs map[string]gatewaySet, startID int) map[string]int {

	findExisting := func(gwSet gatewaySet, prefixGroups map[string]int,
		prefixes []*net.IPNet) (int, bool) {

		for _, prefix := range prefixes {
			if equalSet(gwSet, prefixToGWs[prefix.String()]) {
				return prefixGroups[prefix.String()], true
			}
		}
		return 0, false
	}

	prefixGroups := make(map[string]int)
	groupCount := 0
	for _, sc := range iaSessions {
		for i := range sc.Prefixes {
			prefixKey := sc.Prefixes[i].String()
			// check if a previous session already determined a group ID for
			// this prefix.
			if _, ok := prefixGroups[prefixKey]; ok {
				continue
			}
			// check if a previous prefix is in the same gateway set and thus
			// has the same groupID.
			groupID, ok := findExisting(prefixToGWs[prefixKey], prefixGroups, sc.Prefixes[:i])
			if !ok {
				groupID = startID + groupCount
				groupCount++
			}
			prefixGroups[prefixKey] = groupID
		}
	}
	return prefixGroups
}

func findTrafficMatcherID(options []TrafficMatcher, search pktcls.Cond) (int, bool) {
	key := search.String()
	for _, tm := range options {
		if tm.Matcher.String() == key {
			return tm.ID, true
		}
	}
	return 0, false
}

func nonDuplicateAppendNet(nets []*net.IPNet, add *net.IPNet) []*net.IPNet {
	equalCIDR := func(a, b *net.IPNet) bool {
		return a.IP.Equal(b.IP) && bytes.Equal(a.Mask, b.Mask)
	}
	for _, existing := range nets {
		if equalCIDR(existing, add) {
			return nets
		}
	}
	return append(nets, add)
}

func nonDuplicateAppendID(ids []uint8, add uint8) []uint8 {
	for _, existing := range ids {
		if existing == add {
			return ids
		}
	}
	return append(ids, add)
}

func equalSet(a, b map[string]struct{}) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if _, ok := b[k]; !ok {
			return false
		}
	}
	return true
}
