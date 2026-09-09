// Copyright 2026 SCION Association
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

//go:build linux && (amd64 || arm64)

package afxdpudpip

import (
	"net/netip"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/private/underlay/afxdp"
	"github.com/scionproto/scion/router"
)

// TestStatsCollectorEmpty verifies that the collector can be Describe'd and
// Collect'd against an underlay with no interfaces or connections without
// panicking or blocking. The empty state must emit zero metrics.
func TestStatsCollectorEmpty(t *testing.T) {
	u := &underlay{
		allLinks:       make(map[netip.AddrPort]udpLink),
		allConnections: make(map[connectionKey]*udpConnection),
		allInterfaces:  make(map[int]*afxdp.Interface),
		svc:            router.NewServices[netip.AddrPort](),
	}
	c := newStatsCollector(u)

	reg := prometheus.NewRegistry()
	require.NoError(t, reg.Register(c))

	families, err := reg.Gather()
	require.NoError(t, err)

	// Describe registered both series, but Collect with empty state emits
	// nothing, so Gather returns no families.
	require.Empty(t, families,
		"expected no metric families with empty underlay, got %d", len(families))
}

// TestStatsCollectorDescribe verifies both descriptors are advertised.
func TestStatsCollectorDescribe(t *testing.T) {
	u := &underlay{
		allConnections: make(map[connectionKey]*udpConnection),
		allInterfaces:  make(map[int]*afxdp.Interface),
	}
	c := newStatsCollector(u)

	descs := make(chan *prometheus.Desc, 4)
	c.Describe(descs)
	close(descs)

	var got []string
	for d := range descs {
		got = append(got, d.String())
	}
	require.Len(t, got, 2)
}
