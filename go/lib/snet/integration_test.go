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
	"io/ioutil"
	"math/rand"
	"net"
	"os"
	"testing"
	"time"

	log "github.com/inconshreveable/log15"

	. "github.com/smartystreets/goconvey/convey"
	yaml "gopkg.in/yaml.v2"

	"github.com/netsec-ethz/scion/go/lib/addr"
)

var _ = log.Root

const (
	SCIONDPath = "/run/shm/sciond/sd%v.sock"
	DispPath   = "/run/shm/dispatcher/default.sock"
)

type TestCase struct {
	srcIA *addr.ISD_AS
	dstIA *addr.ISD_AS

	srcLocal addr.HostAddr
	dstLocal addr.HostAddr

	srcPort uint16
	dstPort uint16

	request []byte
	reply   []byte
}

func generateTests(asList []*addr.ISD_AS, count int) []TestCase {
	rand.Seed(time.Now().UnixNano())
	tests := make([]TestCase, 0, 0)
	var cIndex, sIndex int32
	for i := 0; i < count; i++ {
		cIndex = rand.Int31n(int32(len(asList)))
		sIndex = rand.Int31n(int32(len(asList)))
		sIndex = cIndex
		tc := TestCase{srcIA: asList[cIndex], dstIA: asList[sIndex],
			srcPort: uint16(40000 + 2*i), dstPort: uint16(40001 + 2*i),
			srcLocal: addr.HostFromIP(net.IPv4(127, 0, 0, 1)),
			dstLocal: addr.HostFromIP(net.IPv4(127, 0, 0, 1)),
			request:  []byte("ping!"), reply: []byte("pong!")}
		tests = append(tests, tc)
	}
	return tests
}

type ASData struct {
	Core    []string `yaml:"Core"`
	NonCore []string `yaml:"Non-core"`
}

func loadASList(t *testing.T) []*addr.ISD_AS {
	list := make([]*addr.ISD_AS, 0)
	Convey("Load AS list", t, func() {
		// Don't exit the context without checking for errors
		var err error
		defer So(err, ShouldEqual, nil)

		buffer, err := ioutil.ReadFile("../../../gen/as_list.yml")
		if err != nil {
			return
		}

		var locations ASData
		yaml.Unmarshal(buffer, &locations)

		for _, isdas := range locations.Core {
			as, err := addr.IAFromString(isdas)
			if err != nil {
				return
			}
			list = append(list, as)
		}

		for _, isdas := range locations.NonCore {
			as, err := addr.IAFromString(isdas)
			if err != nil {
				return
			}
			list = append(list, as)
		}
	})
	return list
}

func TestIntegration(t *testing.T) {
	asList := loadASList(t)
	tests := generateTests(asList, 100)
	Convey("E2E test", t, func() {
		for idx, test := range tests {
			ClientServer(idx, test)
		}
	})
}

func ClientServer(idx int, tc TestCase) {
	Convey(fmt.Sprintf("Test %v: (%v,%v,%v):%v <-> (%v,%v,%v):%v", idx, tc.srcIA.I,
		tc.srcIA.A, tc.srcLocal, tc.srcPort, tc.dstIA.I, tc.dstIA.A, tc.dstLocal,
		tc.dstPort), func(c C) {
		b := make([]byte, 128)

		clientNet, err := NewNetwork(tc.srcIA, fmt.Sprintf(SCIONDPath, tc.srcIA),
			DispPath)
		SoMsg("Client network error", err, ShouldBeNil)
		serverNet, err := NewNetwork(tc.dstIA, fmt.Sprintf(SCIONDPath, tc.dstIA),
			DispPath)
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
		SoMsg("Client write error", err, ShouldBeNil)
		SoMsg("Client written bytes", n, ShouldEqual, len("Hello!"))

		n, raddr, err := sconn.ReadFrom(b)
		SoMsg("Server read error", err, ShouldBeNil)
		SoMsg("Server remote addr", raddr.String(), ShouldResemble, clientAddr.String())
		SoMsg("Server read message", b[:n], ShouldResemble, []byte("Hello!"))

		n, err = sconn.WriteTo([]byte("Bye!"), raddr)
		SoMsg("Server write error", err, ShouldBeNil)
		SoMsg("Server written bytes", n, ShouldEqual, len("Bye!"))

		n, err = cconn.Read(b)
		SoMsg("Client read error", err, ShouldBeNil)
		SoMsg("Client read message", b[:n], ShouldResemble, []byte("Bye!"))

		err = cconn.Close()
		SoMsg("Client close error", err, ShouldBeNil)

		err = sconn.Close()
		SoMsg("Server close error", err, ShouldBeNil)
	})
}

func TestListen(t *testing.T) {
	a, _ := AddrFromString("1-19,[127.0.0.1]:80")
	tests := []struct {
		desc        string
		isError     bool
		proto       string
		laddr       *Addr
		laddrResult string
		raddrResult string
	}{
		{"connect to tcp", true, "tcp", nil, "", ""},
		{fmt.Sprintf("bind to %v", a), false, "udp4", a,
			"1-19,[127.0.0.1]:80",
			"<nil>"},
	}
	Convey("Method Listen", t, func() {
		for _, test := range tests {
			Convey(test.desc, func() {
				conn, err := ListenSCION(test.proto, test.laddr)
				if test.isError {
					SoMsg("Error", err, ShouldNotBeNil)
				} else {
					SoMsg("Error", err, ShouldBeNil)
					laddr := conn.LocalAddr()
					raddr := conn.RemoteAddr()
					SoMsg("Local address", laddr.String(),
						ShouldResemble, test.laddrResult)
					SoMsg("Remote address", raddr.String(),
						ShouldResemble, test.raddrResult)
				}
			})
		}
	})
}

func TestMain(m *testing.M) {
	ia, _ := addr.IAFromString("1-19")
	err := Init(ia, "/run/shm/sciond/sd1-19.sock", "/run/shm/dispatcher/default.sock")
	if err != nil {
		fmt.Println("Test setup error", err)
	}
	// Comment out below for logging during tests
	log.Root().SetHandler(log.StreamHandler(ioutil.Discard, log.LogfmtFormat()))
	os.Exit(m.Run())
}
