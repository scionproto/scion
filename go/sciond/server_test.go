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

package main

import (
	"flag"
	"fmt"
	"html/template"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/trustdb"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/scrypto/trc"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/proto"
)

func TestPaths(t *testing.T) {
	// XXX(scrye): this does not contain expected values because due to the
	// random IFIDs, setup and checking are too clumsy.
	conn, _, cleanF := Setup(t, "testdata/sciond.toml")
	defer cleanF()
	testCases := []struct {
		Name     string
		Dst      addr.IA
		Src      addr.IA
		MaxPaths uint16
	}{
		{
			Name:     "just up",
			Src:      xtest.MustParseIA("1-ff00:0:133"),
			Dst:      xtest.MustParseIA("1-ff00:0:130"),
			MaxPaths: 5,
		},
		{
			Name:     "up core",
			Src:      xtest.MustParseIA("1-ff00:0:133"),
			Dst:      xtest.MustParseIA("2-ff00:0:210"),
			MaxPaths: 5,
		},
		{
			Name:     "up core down",
			Src:      xtest.MustParseIA("1-ff00:0:133"),
			Dst:      xtest.MustParseIA("2-ff00:0:222"),
			MaxPaths: 5,
		},
	}
	for _, tc := range testCases {
		Convey(tc.Name, t, func() {
			reply, err := conn.Paths(tc.Dst, tc.Src, tc.MaxPaths, sciond.PathReqFlags{})
			SoMsg("err", err, ShouldBeNil)
			if testing.Verbose() {
				fmt.Println(reply)
			}
		})
	}
}

func TestASInfo(t *testing.T) {
	conn, _, cleanF := Setup(t, "testdata/sciond.toml")
	defer cleanF()
	testCases := []struct {
		Name     string
		IA       addr.IA
		Expected *sciond.ASInfoReply
	}{
		{
			Name: "zero IA",
			IA:   xtest.MustParseIA("0-0"),
			Expected: &sciond.ASInfoReply{
				Entries: []sciond.ASInfoReplyEntry{
					{
						RawIsdas: xtest.MustParseIA("1-ff00:0:133").IAInt(),
						Mtu:      1472,
						IsCore:   false,
					},
				},
			},
		},
		{
			Name: "local IA",
			IA:   xtest.MustParseIA("1-ff00:0:133"),
			Expected: &sciond.ASInfoReply{
				Entries: []sciond.ASInfoReplyEntry{
					{
						RawIsdas: xtest.MustParseIA("1-ff00:0:133").IAInt(),
						Mtu:      1472,
						IsCore:   false,
					},
				},
			},
		},
		{
			Name: "core IA",
			IA:   xtest.MustParseIA("1-ff00:0:110"),
			Expected: &sciond.ASInfoReply{
				Entries: []sciond.ASInfoReplyEntry{
					{
						RawIsdas: xtest.MustParseIA("1-ff00:0:110").IAInt(),
						Mtu:      0,
						IsCore:   true,
					},
				},
			},
		},
	}
	for _, tc := range testCases {
		Convey(tc.Name, t, func() {
			reply, err := conn.ASInfo(tc.IA)
			SoMsg("err", err, ShouldBeNil)
			SoMsg("reply", reply, ShouldResemble, tc.Expected)
		})
	}
}

func TestIFInfo(t *testing.T) {
	conn, topo, cleanF := Setup(t, "testdata/sciond.toml")
	defer cleanF()

	// XXX: This depends on the test having a single IFID in this AS. Also, it
	// will panic if there are none.
	var ifids []common.IFIDType
	for ifid := range topo.IFInfoMap {
		ifids = append(ifids, ifid)
	}
	testCases := []struct {
		Name     string
		IFIDs    []common.IFIDType
		Expected *sciond.IFInfoReply
	}{
		{
			Name:  "one ifid",
			IFIDs: []common.IFIDType{ifids[0]},
			Expected: &sciond.IFInfoReply{
				RawEntries: []sciond.IFInfoReplyEntry{
					{
						IfID: ifids[0],
						HostInfo: sciond.HostInfoFromTopoBRAddr(
							*topo.IFInfoMap[ifids[0]].InternalAddrs),
					},
				},
			},
		},
		{
			Name:  "two ifids",
			IFIDs: []common.IFIDType{},
			Expected: &sciond.IFInfoReply{
				RawEntries: []sciond.IFInfoReplyEntry{
					{
						IfID: ifids[0],
						HostInfo: sciond.HostInfoFromTopoBRAddr(
							*topo.IFInfoMap[ifids[0]].InternalAddrs),
					},
					{
						IfID: ifids[1],
						HostInfo: sciond.HostInfoFromTopoBRAddr(
							*topo.IFInfoMap[ifids[1]].InternalAddrs),
					},
				},
			},
		},
		{
			Name:     "bad ifid",
			IFIDs:    []common.IFIDType{0},
			Expected: &sciond.IFInfoReply{},
		},
	}
	for _, tc := range testCases {
		Convey(tc.Name, t, func() {
			reply, err := conn.IFInfo(tc.IFIDs)
			SoMsg("err", err, ShouldBeNil)
			SoMsg("len", len(reply.RawEntries), ShouldEqual, len(tc.Expected.RawEntries))
			for i, v := range tc.Expected.RawEntries {
				SoMsg(fmt.Sprintf("%d", i), v, ShouldBeIn, reply.RawEntries)
			}
		})
	}
}

func TestSVCInfo(t *testing.T) {
	conn, topo, cleanF := Setup(t, "testdata/sciond.toml")
	defer cleanF()

	// XXX: To keep this simple, this depends on the test having a single
	// BS/CS/PS in this AS. Also, it will panic if there are none.  Note that
	// due to the randomly generated topology, expected value initialization
	// uses some of the same functions the SCIOND server itself uses. This can
	// hide some bugs related to topology parsing.

	testCases := []struct {
		Name     string
		SVCTypes []proto.ServiceType
		Expected *sciond.ServiceInfoReply
	}{
		{
			Name:     "ask for BS",
			SVCTypes: []proto.ServiceType{proto.ServiceType_bs},
			Expected: &sciond.ServiceInfoReply{
				Entries: []sciond.ServiceInfoReplyEntry{
					{
						ServiceType: proto.ServiceType_bs,
						Ttl:         300,
						HostInfos: []sciond.HostInfo{
							sciond.HostInfoFromTopoAddr(topo.BS[topo.BSNames[0]]),
						},
					},
				},
			},
		},
		{
			Name:     "ask for CS and PS",
			SVCTypes: []proto.ServiceType{proto.ServiceType_cs, proto.ServiceType_ps},
			Expected: &sciond.ServiceInfoReply{
				Entries: []sciond.ServiceInfoReplyEntry{
					{
						ServiceType: proto.ServiceType_cs,
						Ttl:         300,
						HostInfos: []sciond.HostInfo{
							sciond.HostInfoFromTopoAddr(topo.CS[topo.CSNames[0]]),
						},
					},
					{
						ServiceType: proto.ServiceType_ps,
						Ttl:         300,
						HostInfos: []sciond.HostInfo{
							sciond.HostInfoFromTopoAddr(topo.PS[topo.PSNames[0]]),
						},
					},
				},
			},
		},
		{
			Name:     "ask for nothing",
			SVCTypes: []proto.ServiceType{},
			Expected: &sciond.ServiceInfoReply{},
		},
	}
	for _, tc := range testCases {
		Convey(tc.Name, t, func() {
			reply, err := conn.SVCInfo(tc.SVCTypes)
			SoMsg("err", err, ShouldBeNil)
			SoMsg("reply", reply, ShouldResemble, tc.Expected)
		})
	}
}

func Setup(t *testing.T, configTmpl string) (sciond.Connector, *topology.Topo, func()) {
	// Load config template
	tmpl, err := template.ParseFiles(configTmpl)
	xtest.FailOnErr(t, err)
	// Create temporary dir and test files
	dir, dirCleanF := xtest.MustTempDir("", "sciond")
	testParams := struct {
		Dir      string
		Config   string
		Reliable string
		TrustDB  string
		Topology string
	}{
		Dir:      dir,
		Config:   filepath.Join(dir, "sciond.toml"),
		Reliable: filepath.Join(dir, "test-reliable.sock"),
		TrustDB:  filepath.Join(dir, "trust.db"),
		Topology: "../../gen/ISD1/ASff00_0_133/endhost/topology.json",
	}
	file, err := os.Create(testParams.Config)
	xtest.FailOnErr(t, err)
	err = tmpl.Execute(file, testParams)
	xtest.FailOnErr(t, err)
	err = file.Close()
	xtest.FailOnErr(t, err)
	// FIXME(scrye): The TrustStore doesn't resolve trails yet, so prepopulate
	// the DB with all the TRCs in the test topology.
	trustDB, err := trustdb.New(testParams.TrustDB)
	xtest.FailOnErr(t, err)
	trcobjA, err := trc.TRCFromFile(
		"../../gen/ISD1/ASff00_0_110/endhost/certs/ISD1-V1.trc", false)
	xtest.FailOnErr(t, err)
	_, err = trustDB.InsertTRC(trcobjA)
	xtest.FailOnErr(t, err)
	trcobjB, err := trc.TRCFromFile(
		"../../gen/ISD2/ASff00_0_220/endhost/certs/ISD2-V1.trc", false)
	xtest.FailOnErr(t, err)
	_, err = trustDB.InsertTRC(trcobjB)
	err = trustDB.Close()
	xtest.FailOnErr(t, err)
	// Start SCIOND server under test
	cmd := exec.Command(
		"../../bin/sciond",
		"-config", testParams.Config,
	)
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	err = cmd.Start()
	xtest.FailOnErr(t, err)
	// Give the server time to start
	time.Sleep(time.Second)
	// Also load the topology because IF tests need access to the randomly generated IFIDs.
	topo, err := topology.LoadFromFile(testParams.Topology)
	xtest.FailOnErr(t, err)

	// Start client
	sd := sciond.NewService(testParams.Reliable)
	conn, err := sd.Connect()
	xtest.FailOnErr(t, err)
	return conn, topo, func() {
		conn.Close()
		cmd.Process.Kill()
		// Comment below to stop the test from cleaning itself up
		dirCleanF()
	}
}

func TestMain(m *testing.M) {
	// FIXME(scrye): Logging to stdout/stderr is messy in tests because logging
	// gets mixed with normal test output. Integration tests should log to
	// files instead.
	log.AddLogConsFlags()
	flag.Parse()
	if err := log.SetupFromFlags(""); err != nil {
		panic(err)
	}
	if !testing.Verbose() {
		log.Root().SetHandler(log.DiscardHandler())
	}
	os.Exit(m.Run())
}
