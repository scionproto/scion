// Copyright 2026 ETH Zurich
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//   http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"time"

	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/metrics"
)

// -daemon 127.0.0.19:30255 -remote 1-ff00:0:110,172.20.0.18:12345
func main() {
	ctx, cancelF := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelF()

	var daemonAddr, localAddr, blastDuration string
	var remote snet.UDPAddr
	var payloadSize int

	flag.StringVar(&daemonAddr, "daemon", "", "local daemon address")
	flag.StringVar(&localAddr, "local", "127.0.0.1:0", "local address")
	flag.Var(&remote, "remote", "address to send to")
	flag.StringVar(&blastDuration, "duration", "1s", "duration of the SCION UDP blast")
	flag.IntVar(&payloadSize, "payloadsize", 1100, "size of the payload in bytes")
	flag.Parse()

	// Duration:
	duration, err := time.ParseDuration(blastDuration)
	panicOnError(err)

	// Find daemon.
	daemonConn, err := daemon.NewService(daemonAddr).Connect(ctx)
	panicOnError(err)

	fmt.Printf("remote: %s\n", &remote)

	// Where am I?
	localIA, err := daemonConn.LocalIA(ctx)
	panicOnError(err)
	// local := net.UDPAddrFromAddrPort(
	// 	netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}),
	// 		0))
	local, err := net.ResolveUDPAddr("udp", localAddr)
	panicOnError(err)
	fmt.Printf("On local IA: %s, host: %s\n", localIA, local)

	// Network:
	metrics := metrics.NewSCIONPacketConnMetrics()
	topo, err := daemon.LoadTopology(ctx, daemonConn)
	panicOnError(err)
	network := &snet.SCIONNetwork{
		SCMPHandler: snet.DefaultSCMPHandler{
			RevocationHandler: daemon.RevHandler{Connector: daemonConn},
			SCMPErrors:        metrics.SCMPErrors,
		},
		PacketConnMetrics: metrics,
		Topology:          topo,
	}

	// Get paths.
	paths, err := daemonConn.Paths(ctx, remote.IA, localIA, daemon.PathReqFlags{})
	panicOnError(err)
	if len(paths) == 0 {
		panic("no paths")
	}
	path := paths[0]
	remote.Path = path.Dataplane()
	remote.NextHop = path.UnderlayNextHop()

	// Blast the remote endpoint with packets.
	conn, err := network.Dial(ctx, "udp", local, &remote)
	panicOnError(err)
	payload := make([]byte, payloadSize)
	var packetCount int
	t0 := time.Now()
	for packetCount = 0; ; packetCount++ {
		n, err := conn.Write(payload)
		panicOnError(err)
		if n != len(payload) {
			panic(fmt.Errorf("only sent %d out of %d", n, len(payload)))
		}
		if time.Since(t0) >= duration {
			break
		}
	}
	fmt.Printf("sent %d packets (%d bytes payload) in total to %s.\n",
		packetCount, len(payload), remote.String())
}

func panicOnError(err error) {
	if err != nil {
		panic(err)
	}
}
