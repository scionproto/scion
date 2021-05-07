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

package fake

import (
	"net"

	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/routemgr"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/pkg/gateway/control"
)

// Gateway is a fake gateway. It uses the configurations provided by the
// configuration updates channel to configure a dataplane.
type Gateway struct {
	// RoutingTableSwapper permits the concurrency-safe swapping of an entire
	// routing table in the data-plane. When the session builder creates a new
	// control-plane engine, it creates a fresh routing table. Once the engine
	// is ready, the fresh routing table is swapped in place of the old one. It
	// must not be nil.
	RoutingTableSwapper control.RoutingTableSwapper

	// RoutingTableFactory is used by the engine controller to create a fresh
	// routing table. It must not be nil.
	RoutingTableFactory control.RoutingTableFactory

	// DataplaneSessionFactory is used to construct dataplane sessions.
	DataplaneSessionFactory control.DataplaneSessionFactory

	// ConfigurationUpdates is the channel where new configurations are
	// published.
	ConfigurationUpdates <-chan *Config

	// Logger is used to print information, if it is nil no information is
	// printed.
	Logger log.Logger

	// RoutingPublisherFactory is used to push routes to make the posix gateway
	// to work.
	RoutingPublisherFactory control.PublisherFactory

	sessions map[int]control.DataplaneSession
}

// Run runs the fake gateway, it reads configurations from the configuration
// channel.
func (g *Gateway) Run() error {
	for c := range g.ConfigurationUpdates {
		log.SafeDebug(g.Logger, "New forwarding engine configuration found", "c", c)
		routingTable, err := g.RoutingTableFactory.New(c.Chains)
		if err != nil {
			return serrors.WrapStr("creating routing table", err)
		}

		var pub control.PublisherFactory
		if g.RoutingPublisherFactory != nil {
			pub = g.RoutingPublisherFactory
		} else {
			pub = &routemgr.Dummy{}
		}
		rt := control.NewPublishingRoutingTable(c.Chains, routingTable,
			pub.NewPublisher(), net.IP{}, net.IP{}, net.IP{})
		newSessions := make(map[int]control.DataplaneSession, len(c.Sessions))
		for _, s := range c.Sessions {
			newSessions[s.ID] = g.DataplaneSessionFactory.
				New(uint8(s.ID), s.PolicyID, s.RemoteIA, s.RemoteAddr)
			if err := newSessions[s.ID].SetPaths(s.Paths); err != nil {
				return err
			}
			if s.IsUp {
				if err := rt.SetSession(s.ID, newSessions[s.ID]); err != nil {
					return serrors.WrapStr("adding route", err, "session_id", s.ID)
				}
			}
		}
		g.RoutingTableSwapper.SetRoutingTable(rt)
		for _, sess := range g.sessions {
			sess.Close()
		}
		g.sessions = newSessions
	}
	return nil
}
