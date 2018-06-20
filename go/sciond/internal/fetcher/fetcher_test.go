// Copyright 2018 ETH Zurich
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

// +build infrarunning

package fetcher

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/crypto/trc"
	"github.com/scionproto/scion/go/lib/infra/disp"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/infra/modules/trust"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/trustdb"
	"github.com/scionproto/scion/go/lib/infra/transport"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/pathdb"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/lib/xtest"
)

type TestQuery struct {
	Name       string
	Request    *sciond.PathReq
	EarlyReply time.Duration
}

type Parameters struct {
	pathDBPath   string
	trustDBPath  string
	topologyPath string
	localSnet    string
	localIA      addr.IA
	dispatcher   string
}

func TestFetch(t *testing.T) {
	testCases := []struct {
		name       string
		parameters *Parameters
		queries    []*TestQuery
	}{
		{
			name: "non-core AS",
			parameters: &Parameters{
				pathDBPath:   "/tmp/test1.pathdb",
				trustDBPath:  "/tmp/test1.trustdb",
				topologyPath: "testdata/topology1.json",
				localSnet:    "1-ff00:0:133,[127.0.0.1]:60001",
				localIA:      xtest.MustParseIA("1-ff00:0:133"),
				dispatcher:   "/run/shm/dispatcher/default.sock",
			},
			queries: []*TestQuery{
				{
					Name: "just up",
					Request: &sciond.PathReq{
						Src:      xtest.MustParseIA("1-ff00:0:133").IAInt(),
						Dst:      xtest.MustParseIA("1-ff00:0:130").IAInt(),
						MaxPaths: 5,
						Flags:    sciond.PathReqFlags{Flush: false, Sibra: false},
					},
					EarlyReply: 10 * time.Second,
				},
				{
					Name: "up core",
					Request: &sciond.PathReq{
						Src:      xtest.MustParseIA("1-ff00:0:133").IAInt(),
						Dst:      xtest.MustParseIA("2-ff00:0:210").IAInt(),
						MaxPaths: 5,
						Flags:    sciond.PathReqFlags{Flush: false, Sibra: false},
					},
					EarlyReply: 10 * time.Second,
				},
				{
					Name: "up core down",
					Request: &sciond.PathReq{
						Src:      xtest.MustParseIA("1-ff00:0:133").IAInt(),
						Dst:      xtest.MustParseIA("2-ff00:0:222").IAInt(),
						MaxPaths: 5,
						Flags:    sciond.PathReqFlags{Flush: false, Sibra: false},
					},
					EarlyReply: 10 * time.Second,
				},
			},
		},
		{
			name: "core AS",
			parameters: &Parameters{
				pathDBPath:   "/tmp/test2.pathdb",
				trustDBPath:  "/tmp/test2.trustdb",
				topologyPath: "testdata/topology2.json",
				localSnet:    "1-ff00:0:110,[127.0.0.1]:60002",
				localIA:      xtest.MustParseIA("1-ff00:0:110"),
				dispatcher:   "/run/shm/dispatcher/default.sock",
			},
			queries: []*TestQuery{
				{
					Name: "just core",
					Request: &sciond.PathReq{
						Src:      xtest.MustParseIA("1-ff00:0:110").IAInt(),
						Dst:      xtest.MustParseIA("2-ff00:0:220").IAInt(),
						MaxPaths: 5,
						Flags:    sciond.PathReqFlags{Flush: false, Sibra: false},
					},
					EarlyReply: 10 * time.Second,
				},
				{
					Name: "core down",
					Request: &sciond.PathReq{
						Src:      xtest.MustParseIA("1-ff00:0:110").IAInt(),
						Dst:      xtest.MustParseIA("2-ff00:0:212").IAInt(),
						MaxPaths: 5,
						Flags:    sciond.PathReqFlags{Flush: false, Sibra: false},
					},
					EarlyReply: 10 * time.Second,
				},
			},
		},
	}

	// Initialize outside of Goconvey block because we want each test tree
	// exploration to be independent, but want shared state within the same
	// test tree.
	for i, tc := range testCases {
		fetcher := Init(t, tc.parameters)

		Convey(fmt.Sprintf("Initialize test environment %d", i), t, func() {
			ctx, cancelF := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancelF()

			for _, query := range tc.queries {
				Convey(query.Name, func() {
					_, err := fetcher.GetPaths(ctx, query.Request, query.EarlyReply)
					SoMsg("err", err, ShouldBeNil)
				})
			}

		})
	}
}

func Init(t *testing.T, parameters *Parameters) *Fetcher {
	t.Helper()

	// Nuke pathDB to get better code coverage
	os.Remove(parameters.pathDBPath)

	topo, err := topology.LoadFromFile(parameters.topologyPath)
	xtest.FailOnErr(t, err)
	pathDB, err := pathdb.New(parameters.pathDBPath, "sqlite")
	xtest.FailOnErr(t, err)
	trustDB, err := trustdb.New(parameters.trustDBPath)
	xtest.FailOnErr(t, err)
	trcobjA, err := trc.TRCFromFile("testdata/ISD1-V1.trc", false)
	xtest.FailOnErr(t, err)
	_, err = trustDB.InsertTRC(trcobjA)
	xtest.FailOnErr(t, err)
	trcobjB, err := trc.TRCFromFile("testdata/ISD2-V1.trc", false)
	xtest.FailOnErr(t, err)
	_, err = trustDB.InsertTRC(trcobjB)
	xtest.FailOnErr(t, err)
	trustStore, err := trust.NewStore(trustDB, parameters.localIA, 1337, log.Root())
	xtest.FailOnErr(t, err)
	network, err := snet.NewNetwork(parameters.localIA, "", parameters.dispatcher)
	xtest.FailOnErr(t, err)
	snetAddress, err := snet.AddrFromString(parameters.localSnet)
	xtest.FailOnErr(t, err)
	conn, err := network.ListenSCION("udp4", snetAddress)
	xtest.FailOnErr(t, err)

	msger := messenger.New(
		disp.New(
			transport.NewPacketTransport(conn),
			messenger.DefaultAdapter,
			log.Root(),
		),
		trustStore,
		log.Root(),
	)
	trustStore.SetMessenger(msger)
	return NewFetcher(topo, msger, pathDB, trcobjA, trustStore)
}
