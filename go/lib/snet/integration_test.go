// Copyright 2017 ETH Zurich
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

package snet

import (
	"fmt"
	"math/rand"
	"net"
	"os"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/lib/xtest"
)

var _ = log.Root

var (
	asList  []addr.IA
	localIA addr.IA
)

type TestCase struct {
	srcIA addr.IA
	dstIA addr.IA

	srcLocal addr.HostAddr
	dstLocal addr.HostAddr

	srcPort uint16
	dstPort uint16

	request []byte
	reply   []byte

	expectWriteError bool
}

func generateTests(asList []addr.IA, count int, haveSciond bool) []TestCase {
	tests := make([]TestCase, 0, 0)
	var cIndex, sIndex int32
	for i := 0; i < count; i++ {
		cIndex = rand.Int31n(int32(len(asList)))
		sIndex = rand.Int31n(int32(len(asList)))
		srcIA := asList[cIndex]
		dstIA := asList[sIndex]
		tc := TestCase{
			srcIA:    srcIA,
			dstIA:    dstIA,
			srcPort:  uint16(40000 + 2*i),
			dstPort:  uint16(40001 + 2*i),
			srcLocal: addr.HostFromIP(net.IPv4(127, 0, 0, 1)),
			dstLocal: addr.HostFromIP(net.IPv4(127, 0, 0, 1)),
			request:  []byte("ping!"),
			reply:    []byte("pong!"),
			// if we don't have sciond, we can't talk to a different AS without
			// an explicit path
			expectWriteError: haveSciond == false && !srcIA.Eq(dstIA),
		}
		tests = append(tests, tc)
	}
	return tests
}

func TestIntegration(t *testing.T) {
	testCases := []struct {
		Name       string
		HaveSciond bool
		Tests      []TestCase
	}{
		{
			Name:       "SCIOND Mode",
			HaveSciond: true,
			Tests:      generateTests(asList, 100, true),
		},
		{
			Name:       "SCIOND-less Mode",
			HaveSciond: false,
			Tests:      generateTests(asList, 100, false),
		},
	}

	Convey("E2E test", t, func() {
		for _, tc := range testCases {
			Convey(tc.Name, func() {
				for idx, test := range tc.Tests {
					ClientServer(tc.HaveSciond, idx, test)
				}
			})
		}
	})
}

func ClientServer(haveSciond bool, idx int, tc TestCase) {
	Convey(fmt.Sprintf("Test %v: (%v-%v,%v):%v <-> (%v-%v,%v):%v", idx, tc.srcIA.I,
		tc.srcIA.A, tc.srcLocal, tc.srcPort, tc.dstIA.I, tc.dstIA.A, tc.dstLocal,
		tc.dstPort), func(c C) {
		b := make([]byte, 128)

		clientSciond := ""
		if haveSciond {
			clientSciond = sciond.GetDefaultSCIONDPath(&tc.srcIA)
		}
		clientNet, err := NewNetwork(tc.srcIA, clientSciond, "")
		SoMsg("Client network error", err, ShouldBeNil)

		serverSciond := ""
		if haveSciond {
			serverSciond = sciond.GetDefaultSCIONDPath(&tc.dstIA)
		}
		serverNet, err := NewNetwork(tc.dstIA, serverSciond, "")
		SoMsg("Server network error", err, ShouldBeNil)

		clientAddr, err := AddrFromString(
			fmt.Sprintf("%v,[%v]:%d", tc.srcIA, tc.srcLocal, tc.srcPort))
		SoMsg("Client address error", err, ShouldBeNil)
		serverAddr, err := AddrFromString(
			fmt.Sprintf("%v,[%v]:%d", tc.dstIA, tc.dstLocal, tc.dstPort))
		SoMsg("Server address error", err, ShouldBeNil)

		sconn, err := serverNet.ListenSCION("udp4", serverAddr)
		SoMsg("Listen error", err, ShouldBeNil)

		err = sconn.SetDeadline(time.Now().Add(5 * time.Second))
		SoMsg("Server deadline error", err, ShouldBeNil)

		cconn, err := clientNet.DialSCION("udp4", clientAddr, serverAddr)
		SoMsg("Client dial error", err, ShouldBeNil)
		cconn.SetDeadline(time.Now().Add(5 * time.Second))
		SoMsg("Client deadline error", err, ShouldBeNil)

		n, err := cconn.Write([]byte("Hello!"))
		xtest.SoMsgError("Client write error", err, tc.expectWriteError)
		// Only run the message exchange in cases where snet doesn't error out
		// due to needing a path in SCIOND-less mode of operation.
		if tc.expectWriteError == false {
			SoMsg("Client written bytes", n, ShouldEqual, len("Hello!"))

			n, raddr, err := sconn.ReadFromSCION(b)
			SoMsg("Server read error", err, ShouldBeNil)
			SoMsg("Server remote addr", clientAddr.EqAddr(raddr), ShouldBeTrue)
			SoMsg("Server read message", b[:n], ShouldResemble, []byte("Hello!"))

			n, err = sconn.WriteToSCION([]byte("Bye!"), raddr)
			SoMsg("Server write error", err, ShouldBeNil)
			SoMsg("Server written bytes", n, ShouldEqual, len("Bye!"))

			n, err = cconn.Read(b)
			SoMsg("Client read error", err, ShouldBeNil)
			SoMsg("Client read message", b[:n], ShouldResemble, []byte("Bye!"))
		}

		err = cconn.Close()
		SoMsg("Client close error", err, ShouldBeNil)

		err = sconn.Close()
		SoMsg("Server close error", err, ShouldBeNil)
	})
}

func TestListen(t *testing.T) {
	aStr := fmt.Sprintf("%v,[127.0.0.1]:80", localIA)
	zStr := fmt.Sprintf("%v,[0.0.0.0]:80", localIA)
	a, _ := AddrFromString(aStr)
	z, _ := AddrFromString(zStr)
	tests := []struct {
		desc    string
		isError bool
		proto   string
		laddr   *Addr
	}{
		{"connect to tcp", true, "tcp", nil},
		{"bind to nil laddr", true, "udp4", nil},
		{"bind to 0.0.0.0 laddr", true, "udp4", z},
		{fmt.Sprintf("bind to %v", a), false, "udp4", a},
	}
	Convey("Method Listen", t, func() {
		for _, test := range tests {
			Convey(test.desc, func() {
				conn, err := ListenSCION(test.proto, test.laddr)
				if test.isError {
					SoMsg("Error", err, ShouldNotBeNil)
				} else {
					SoMsg("Error", err, ShouldBeNil)
					laddr := conn.LocalSnetAddr()
					raddr := conn.RemoteSnetAddr()
					SoMsg("Local address", laddr.EqAddr(test.laddr), ShouldBeTrue)
					SoMsg("Remote address", raddr, ShouldBeNil)
				}
			})
		}
	})
}

func TestMain(m *testing.M) {
	var err error
	scrypto.MathRandSeed()
	// Load topology information
	asStruct, err := util.LoadASList("../../../gen/as_list.yml")
	if err != nil {
		fmt.Println("ASList load error", err)
		return
	}
	asList = append(asStruct.Core, asStruct.NonCore...)

	localIA = asList[rand.Intn(len(asList))]
	err = Init(localIA, sciond.GetDefaultSCIONDPath(&localIA), "")
	if err != nil {
		fmt.Println("Test setup error", err)
		return
	}
	// Comment the line below for logging during tests
	log.Root().SetHandler(log.DiscardHandler())
	os.Exit(m.Run())
}
