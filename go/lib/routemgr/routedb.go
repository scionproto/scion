// Copyright 2021 Anapaya Systems
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

package routemgr

import (
	"bytes"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/metrics"
)

const (
	updateChannelSize      = 256
	defaultCleanupInterval = time.Second
)

// Diagnostics is the diagnostic information about the RouteDB.
type Diagnostics struct {
	Routes []Route
}

type Route struct {
	// Prefix is the IP address prefix of the route.
	Prefix *net.IPNet
	// Source is the (optional) source hint for the IP route.
	Source net.IP
}

// RouteUpdate is used to inform consumers about changes in the route database.
type RouteUpdate struct {
	Route
	// IsAdd is true if the route is added. It is false when the route is removed.
	IsAdd bool
}

// Publisher is the interface for announcing prefixes to other routing backends.
type Publisher interface {
	// AddRoute will export route to another routing backend. Duplicates are a no-op.
	AddRoute(route Route)
	// DeleteRoute will delete a route from another routing backend. If the route
	// doesn't exist, the deletion is a silent no-op. Only a network that is an exact
	// match (network address, subnet mask, next hop) is removed.
	DeleteRoute(route Route)
	// Close retracts all the routes published via this publisher.
	Close()
}

type PublisherFactory interface {
	NewPublisher() Publisher
}

type Consumer interface {
	// Updates returns a channel that can be used to receive route updates.
	Updates() <-chan RouteUpdate
	// Stops receiving updates.
	Close()
}

type ConsumerFactory interface {
	NewConsumer() Consumer
}

type routeEntry struct {
	Route
	refCount  int
	deletedAt time.Time
}

type RouteDBMetrics struct {
	// Unresponsive is increased if published routes cannot be sent to the consumer.
	// (Consumer is slow/stuck and doesn't read routes from the channel.)
	Unresponsive metrics.Counter
}

// RouteDB is a one-way channel between route publisher(s) and route
// consumer(s). Routes in the database are reference counted. When the last reference is
// deleted, the route will remain in the database for some time before in expires.
type RouteDB struct {
	// RouteExpiration specifies how long it takes for an unreferenced route to
	// expire. Zero means expire immediately. Default 0.
	RouteExpiration time.Duration
	// CleanupInterval specifies how often should the cleanup be done.
	// Default 1 second. Set this to a small value in tests to make them run faster.
	CleanupInterval time.Duration
	// Metrics are metrics related to this route database.
	Metrics RouteDBMetrics

	mtx       sync.Mutex
	routes    map[string]*routeEntry
	consumers map[*RouteConsumer]struct{}
	closeChan chan struct{}
}

func (db *RouteDB) Run() {
	db.init()
	ticker := time.NewTicker(db.CleanupInterval)
	for {
		select {
		case <-ticker.C:
			db.cleanUp()
		case <-db.closeChan:
			db.closeConsumerChannels()
			return
		}
	}
}

func (db *RouteDB) initLocked() {
	if db.closeChan != nil {
		return
	}
	if db.CleanupInterval == 0 {
		db.CleanupInterval = defaultCleanupInterval
	}
	db.routes = make(map[string]*routeEntry)
	db.consumers = make(map[*RouteConsumer]struct{})
	db.closeChan = make(chan struct{})
}

func (db *RouteDB) init() {
	db.mtx.Lock()
	defer db.mtx.Unlock()
	db.initLocked()
}

func (db *RouteDB) closeConsumerChannels() {
	db.mtx.Lock()
	defer db.mtx.Unlock()
	for consumer := range db.consumers {
		close(consumer.updateChan)
	}
}

// Close shuts down worker goroutines. It also closes update channels for all
// associated consumers.
func (db *RouteDB) Close() {
	db.mtx.Lock()
	defer db.mtx.Unlock()
	db.initLocked()
	close(db.closeChan)
}

// NewPublisher creates a new publisher that can be used to insert routes to the
// database. Calling the function after Close results in undefined behavior.
func (db *RouteDB) NewPublisher() Publisher {
	db.mtx.Lock()
	defer db.mtx.Unlock()
	db.initLocked()

	return &RoutePublisher{
		db:     db,
		routes: make(map[string]*publisherRouteEntry),
	}
}

// NewConsumer creates a new consumer that can be used to get route updates from
// the database. Calling the function after Close results in undefined behavior.
func (db *RouteDB) NewConsumer() Consumer {
	db.mtx.Lock()
	defer db.mtx.Unlock()
	db.initLocked()

	// Size update channel in such a way that all current routes can be pushed to it
	// without blocking.
	channelSize := len(db.routes)
	if channelSize < updateChannelSize {
		channelSize = updateChannelSize
	}
	c := &RouteConsumer{db: db, updateChan: make(chan RouteUpdate, channelSize)}
	db.consumers[c] = struct{}{}

	// Push all the currently existing routes into the update channel.
	for _, entry := range db.routes {
		db.publishToUpdateChan(c.updateChan, RouteUpdate{
			IsAdd: true,
			Route: Route{
				Prefix: entry.Prefix,
				Source: entry.Source,
			},
		})
	}

	return c
}

func (db *RouteDB) addRoute(route Route) {
	db.mtx.Lock()
	defer db.mtx.Unlock()

	key := makeKey(route.Prefix, route.Source)
	entry, ok := db.routes[key]
	if ok {
		entry.refCount++
		return
	}
	db.routes[key] = &routeEntry{
		Route:    route,
		refCount: 1,
	}
	for consumer := range db.consumers {
		db.publishToUpdateChan(consumer.updateChan, RouteUpdate{
			IsAdd: true,
			Route: route,
		})
	}
}

func (db *RouteDB) deleteRoute(route Route) {
	db.mtx.Lock()
	defer db.mtx.Unlock()

	key := makeKey(route.Prefix, route.Source)
	entry, ok := db.routes[key]
	if !ok {
		panic("RouteDB: Removing route that hasn't been added.")
	}
	entry.refCount--
	if entry.refCount == 0 {
		entry.deletedAt = time.Now()
	}
}

func (db *RouteDB) publishToUpdateChan(ch chan RouteUpdate, ru RouteUpdate) {
	after := time.After(time.Minute)
	for {
		select {
		case ch <- ru:
			return
		case <-after:
			log.Error("RouteDB: Update channel full.")
			metrics.CounterInc(db.Metrics.Unresponsive)
		}
	}
}

func (db *RouteDB) cleanUp() {
	db.mtx.Lock()
	defer db.mtx.Unlock()

	for key, entry := range db.routes {
		if entry.refCount == 0 && time.Now().Sub(entry.deletedAt) > db.RouteExpiration {
			for consumer := range db.consumers {
				db.publishToUpdateChan(consumer.updateChan, RouteUpdate{
					IsAdd: false,
					Route: Route{
						Prefix: entry.Prefix,
						Source: entry.Source,
					},
				})
			}
			delete(db.routes, key)
		}
	}
}

func (db *RouteDB) closeConsumer(c *RouteConsumer) {
	db.mtx.Lock()
	defer db.mtx.Unlock()

	delete(db.consumers, c)
}

// Diagnostics takes a diagnostic snapshot of the RouteDB.
func (db *RouteDB) Diagnostics() Diagnostics {
	routes := db.snapshot()
	if len(routes) == 0 {
		return Diagnostics{}
	}
	sortRoutes(routes)
	return Diagnostics{Routes: routes}
}

func (db *RouteDB) snapshot() []Route {
	db.mtx.Lock()
	defer db.mtx.Unlock()
	routes := make([]Route, 0, len(db.routes))
	for _, route := range db.routes {
		routes = append(routes, route.Route)
	}
	return routes
}

func sortRoutes(routes []Route) {
	sort.Slice(routes, func(i, j int) bool {
		a := routes[i].Prefix.IP.Mask(routes[i].Prefix.Mask)
		b := routes[j].Prefix.IP.Mask(routes[j].Prefix.Mask)
		a, b = canonicalIP(a), canonicalIP(b)

		// Sort according to IP family.
		if aLen, bLen := len(a), len(b); aLen != bLen {
			return aLen < bLen
		}
		if c := bytes.Compare(a, b); c != 0 {
			return c == -1
		}
		aOnes, _ := routes[i].Prefix.Mask.Size()
		bOnes, _ := routes[j].Prefix.Mask.Size()
		if aOnes != bOnes {
			return aOnes < bOnes
		}
		aSrc := canonicalIP(routes[i].Source)
		bSrc := canonicalIP(routes[j].Source)
		if c := bytes.Compare(aSrc, bSrc); c != 0 {
			return c == -1
		}
		return false
	})
}

func canonicalIP(ip net.IP) net.IP {
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	return ip
}

type publisherRouteEntry struct {
	Route
	refCount int
}

type RoutePublisher struct {
	db     *RouteDB
	routes map[string]*publisherRouteEntry
}

// AddRoute adds a route to the database. Inserting the same route multiple
// times is OK. The routes are reference counted. Calling the function
// after Close results in undefined behavior.
func (p *RoutePublisher) AddRoute(route Route) {
	key := makeKey(route.Prefix, route.Source)
	entry, ok := p.routes[key]
	if ok {
		entry.refCount++
		return
	}
	p.routes[key] = &publisherRouteEntry{
		Route:    route,
		refCount: 1,
	}
	p.db.addRoute(route)
}

// DeleteRoute removes a route from the database. If the route in question
// hasn't been added via this publisher the function will panic. Calling the function
// after Close results in undefined behavior.
func (p *RoutePublisher) DeleteRoute(route Route) {
	key := makeKey(route.Prefix, route.Source)
	entry, ok := p.routes[key]
	if !ok || entry.refCount == 0 {
		panic("RouteDB: Removing route that hasn't been added.")
	}
	entry.refCount--
	if entry.refCount > 0 {
		return
	}
	delete(p.routes, key)
	p.db.deleteRoute(route)
}

// Close closes the publisher, deleting all the routes that have been added
// through it.
func (p *RoutePublisher) Close() {
	for _, entry := range p.routes {
		p.db.deleteRoute(entry.Route)
	}
}

type RouteConsumer struct {
	db         *RouteDB
	updateChan chan RouteUpdate
}

// Updates returns a channel for route updates. When the database is closed this
// channel will be closed as well.
func (c *RouteConsumer) Updates() <-chan RouteUpdate {
	return c.updateChan
}

// Close closes the consumer. This will also close the update channel.
func (c *RouteConsumer) Close() {
	c.db.closeConsumer(c)
	close(c.updateChan)
}

func makeKey(prefix *net.IPNet, nextHop net.IP) string {
	return fmt.Sprintf("%s %s", prefix, nextHop)
}
