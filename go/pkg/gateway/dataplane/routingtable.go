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

package dataplane

import (
	"fmt"
	"io"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/scionproto/scion/go/lib/pktcls"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/pkg/gateway/control"
)

type entry struct {
	Prefix *net.IPNet
	Table  []*subEntry
}

func (e *entry) String() string {
	ret := ""
	for _, l := range e.Table {
		ret += fmt.Sprintf("%s %s\n", e.Prefix, l)
	}
	return ret
}

func (e *entry) route(pkt gopacket.Layer) control.PktWriter {
	for _, sub := range e.Table {
		if sub.Class.Eval(pkt) {
			return sub.Session
		}
	}
	return nil
}

type subEntry struct {
	Class   pktcls.Cond
	Session control.PktWriter
}

func (se *subEntry) String() string {
	sess := "DROP"
	if se.Session != nil {
		sess = fmt.Sprintf("%s", se.Session)
	}
	return fmt.Sprintf("condition: %s\n  session: %s", se.Class, sess)
}

// RoutingTable contains the data-plane routing table for the gateway. The same
// routing table is used for both IPv4 and IPv6 traffic.
type RoutingTable struct {
	indexToSubEntry map[int]*subEntry
	indexToEntries  map[int][]*entry
	table           []*entry
}

// NewRoutingTable creates a new routing table and initializes it with the given
// chains.
func NewRoutingTable(chains []*control.RoutingChain) *RoutingTable {
	indexToSubEntry := make(map[int]*subEntry)
	indexToEntries := make(map[int][]*entry)
	var table []*entry
	for _, chain := range chains {
		for _, prefix := range chain.Prefixes {
			e := &entry{
				Prefix: prefix,
			}
			for _, tm := range chain.TrafficMatchers {
				se, ok := indexToSubEntry[tm.ID]
				if !ok {
					se = &subEntry{Class: tm.Matcher, Session: nil}
					indexToSubEntry[tm.ID] = se
				}
				indexToEntries[tm.ID] = append(indexToEntries[tm.ID], e)
				e.Table = append(e.Table, se)
			}
			table = append(table, e)
		}
	}

	return &RoutingTable{
		indexToSubEntry: indexToSubEntry,
		indexToEntries:  indexToEntries,
		table:           table,
	}
}

func (rt *RoutingTable) DiagnosticsWrite(w io.Writer) {
	raw := ""
	for _, e := range rt.table {
		raw += e.String()
	}

	w.Write([]byte(raw))
}

// RouteIPv4 returns the session the IPv4 packet should be routed on. It returns after doing a
// longest prefix match on the destination IP address. Once the longest prefix match is found, the
// matching traffic class for the prefix with lowest index is found. Finally, the associated Session
// for the match is returned. If no routing prefix is matched, or no traffic class is matched,
// routing will return `nil`.
func (rt *RoutingTable) RouteIPv4(pkt layers.IPv4) control.PktWriter {
	return rt.route(pkt.DstIP, &pkt)
}

// RouteIPv6 returns the session the IPv6 packet should be routed on. It returns after doing a
// longest prefix match on the destination IP address. Once the longest prefix match is found, the
// matching traffic class for the prefix with lowest index is found. Finally, the associated Session
// for the match is returned. If no routing prefix is matched, or no traffic class is matched,
// routing will return `nil`.
func (rt *RoutingTable) RouteIPv6(pkt layers.IPv6) control.PktWriter {
	return rt.route(pkt.DstIP, &pkt)
}

func (rt *RoutingTable) route(dst net.IP, pkt gopacket.Layer) control.PktWriter {
	var ret control.PktWriter
	highestMask := 0
	for _, e := range rt.table {
		if !e.Prefix.Contains(dst) {
			continue
		}

		m, _ := e.Prefix.Mask.Size()
		if m < highestMask {
			continue
		}
		highestMask = m
		ret = e.route(pkt)
	}
	return ret
}

func (rt *RoutingTable) SetSession(index int, session control.PktWriter) error {
	if session == nil {
		return serrors.New("nil session")
	}
	se, ok := rt.indexToSubEntry[index]
	if !ok {
		return serrors.New("invalid index")
	}
	se.Session = session
	return nil
}

func (rt *RoutingTable) ClearSession(index int) error {
	se, ok := rt.indexToSubEntry[index]
	if !ok {
		return serrors.New("invalid index")
	}
	se.Session = nil
	return nil
}

// Activate should be called to mark the routing table as active.
func (rt *RoutingTable) Activate() {}

// Deactivate should be called when the routing table is no longer needed.
func (rt *RoutingTable) Deactivate() {}
