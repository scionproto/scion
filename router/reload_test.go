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

package router_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/ptr"
	"github.com/scionproto/scion/pkg/segment/iface"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/path"
	"github.com/scionproto/scion/private/env"
	"github.com/scionproto/scion/private/topology"
	jsontopo "github.com/scionproto/scion/private/topology/json"
	"github.com/scionproto/scion/router"
	"github.com/scionproto/scion/router/config"
	"github.com/scionproto/scion/router/control"
)

// TestReloadTopology runs a router on loopback sockets.
// While packets keep coming in through interface 1, interface 2 moves to
// another neighbor address, then makes room for interface 3.
func TestReloadTopology(t *testing.T) {
	neighbor1, neighbor2, moved2, neighbor3 := listen(t), listen(t), listen(t), listen(t)
	local1, local2, local3, internal := freeAddr(t), freeAddr(t), freeAddr(t), freeAddr(t)

	dir := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(dir, "keys"), 0o755))
	for _, name := range []string{"master0.key", "master1.key"} {
		require.NoError(t, os.WriteFile(
			filepath.Join(dir, "keys", name), []byte("WBwuhjeRhrAyNMQnc7cxfw=="), 0o600))
	}
	// writeTopology writes a topology with the given interfaces
	// and returns what the loader would.
	writeTopology := func(ifs map[iface.ID]*jsontopo.BRInterface) topology.Topology {
		raw, err := json.Marshal(jsontopo.Topology{
			IA:  "1-ff00:0:110",
			MTU: 1472,
			BorderRouters: map[string]*jsontopo.BRInfo{
				"br1": {InternalAddr: internal, Interfaces: ifs},
			},
		})
		require.NoError(t, err)
		file := filepath.Join(dir, "topology.json")
		require.NoError(t, os.WriteFile(file, raw, 0o644))
		topo, err := topology.FromJSONFile(file)
		require.NoError(t, err)
		return topo
	}
	interface1 := loopbackInterface(local1, neighbor1, "parent")

	cfg, err := control.NewConfig("br1", writeTopology(map[iface.ID]*jsontopo.BRInterface{
		1: interface1,
		2: loopbackInterface(local2, neighbor2, "child"),
	}), dir)
	require.NoError(t, err)
	c := router.NewConnector(config.RouterConfig{
		NumProcessors:         1,
		NumSlowPathProcessors: 1,
		BatchSize:             8,
	}, env.Features{})
	iaCtx := &control.IACtx{Config: cfg, DP: c}
	require.NoError(t, iaCtx.Configure())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		assert.NoError(t, c.DataPlane.Run(ctx))
	}()
	key := control.DeriveHFMacKey(cfg.MasterKeys.Key0)

	// forward sends a packet in through interface 1 to leave through egress,
	// and returns what arrives at to.
	forward := func(egress uint16, to *net.UDPConn) []byte {
		t.Helper()
		pkt := transitPacket(t, key, egress)
		_, err := neighbor1.WriteToUDPAddrPort(pkt, netip.MustParseAddrPort(local1))
		require.NoError(t, err)
		require.NoError(t, to.SetReadDeadline(time.Now().Add(2*time.Second)))
		buf := make([]byte, 9000)
		n, err := to.Read(buf)
		require.NoError(t, err, "nothing arrived")
		return buf[:n]
	}
	isTransit := func(b []byte) bool {
		return bytes.HasSuffix(b, []byte("actualpayloadbytes"))
	}

	assert.True(t, isTransit(forward(2, neighbor2)))

	require.NoError(t,
		iaCtx.UpdateTopology(
			writeTopology(map[iface.ID]*jsontopo.BRInterface{
				1: interface1,
				2: loopbackInterface(local2, moved2, "child"),
			})))
	assert.True(t, isTransit(forward(2, moved2)))

	require.NoError(t,
		iaCtx.UpdateTopology(writeTopology(map[iface.ID]*jsontopo.BRInterface{
			1: interface1,
			3: loopbackInterface(local3, neighbor3, "child"),
		})))
	assert.True(t, isTransit(forward(3, neighbor3)))
	// Interface 2 is unknown now.
	reply := gopacket.NewPacket(
		forward(2, neighbor1), slayers.LayerTypeSCION, gopacket.Default,
	)
	scmp, ok := reply.Layer(slayers.LayerTypeSCMP).(*slayers.SCMP)
	require.True(t, ok, "no SCMP reply")
	assert.Equal(t, slayers.SCMPTypeParameterProblem, scmp.TypeCode.Type())
	assert.Equal(t, slayers.SCMPCodeUnknownHopFieldEgress, scmp.TypeCode.Code())
}

func listen(t *testing.T) *net.UDPConn {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	t.Cleanup(func() { c.Close() })
	return c
}

// freeAddr returns a loopback address that the router can bind to.
func freeAddr(t *testing.T) string {
	c := listen(t)
	a := c.LocalAddr().String()
	c.Close()
	return a
}

func loopbackInterface(
	local string, neighbor *net.UDPConn, linkTo string,
) *jsontopo.BRInterface {
	return &jsontopo.BRInterface{
		Underlay: jsontopo.Underlay{
			Local:  local,
			Remote: neighbor.LocalAddr().String(),
		},
		IA:     "1-ff00:0:111",
		LinkTo: linkTo,
		MTU:    1472,
		// The neighbors don't speak BFD, and egress links that are down drop packets.
		BFD: &jsontopo.BFD{Disable: ptr.To(true)},
	}
}

// transitPacket returns a packet that enters through
// interface 1 and leaves through egress.
func transitPacket(t *testing.T, key []byte, egress uint16) []byte {
	spkt, dpath := prepBaseMsg(time.Now())
	require.NoError(t, spkt.SetSrcAddr(addr.MustParseHost("192.0.2.1")))
	require.NoError(t, spkt.SetDstAddr(addr.MustParseHost("192.0.2.2")))
	dpath.HopFields = []path.HopField{
		{ConsIngress: 31, ConsEgress: 30},
		{ConsIngress: 1, ConsEgress: egress},
		{ConsIngress: 40, ConsEgress: 41},
	}
	dpath.HopFields[1].Mac = computeMAC(t, key, dpath.InfoFields[0], dpath.HopFields[1])
	return toBytes(t, spkt, dpath)
}
