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

package reliable

import (
	"fmt"
	"math/rand"
	"net"
	"os"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
)

type ExitData struct {
	value []byte
	err   error
}

func Server(x chan ExitData, sockName string, timeoutOK bool) {
	os.Remove(sockName)
	defer os.Remove(sockName)
	listener, err := Listen(sockName)
	if err != nil {
		x <- ExitData{err: err}
		return
	}

	conn, err := listener.Accept()
	if err != nil {
		x <- ExitData{err: err}
		return
	}

	time.Sleep(300 * time.Millisecond)
	buf := make([]byte, 128)
	n, err := conn.UnixConn.Read(buf)
	if err != nil {
		x <- ExitData{err: err}
		return
	}

	err = conn.Close()
	if err != nil {
		x <- ExitData{err: err}
		return
	}
	x <- ExitData{value: buf[:n]}
}

func Client(x chan ExitData, sockName string, msg []byte, dst AppAddr) {
	time.Sleep(200 * time.Millisecond)
	conn, err := Dial(sockName)
	if err != nil {
		x <- ExitData{err: err}
		return
	}

	_, err = conn.WriteTo(msg, dst)
	if err != nil {
		x <- ExitData{err: err}
		return
	}

	err = conn.Close()
	if err != nil {
		x <- ExitData{err: err}
		return
	}
	x <- ExitData{}
}

func ClientRegister(x chan ExitData, sockName string, ia *addr.ISD_AS, dst AppAddr) {
	// Sleep to avoid connecting before server is up
	time.Sleep(200 * time.Millisecond)
	Register(sockName, ia, dst)
	x <- ExitData{}
}

func TestWriteTo(t *testing.T) {
	nilAddr, _ := addr.HostFromRaw(nil, addr.HostTypeNone)
	testCases := []struct {
		payload string
		dst     AppAddr
		want    []byte
	}{
		{"", AppAddr{Addr: nilAddr, Port: 0},
			[]byte{0xde, 0, 0xad, 1, 0xbe, 2, 0xef, 3, 0, 0, 0, 0, 0}},
		{"test", AppAddr{Addr: nilAddr, Port: 0},
			[]byte{0xde, 0, 0xad, 1, 0xbe, 2, 0xef, 3, 0, 0, 0, 0, 4, 't', 'e', 's', 't'}},
		{"foo", AppAddr{Addr: addr.HostFromIP(net.IPv4(127, 0, 0, 1)), Port: 80},
			[]byte{0xde, 0, 0xad, 1, 0xbe, 2, 0xef, 3, 1, 0, 0, 0, 3,
				127, 0, 0, 1, 0, 80, 'f', 'o', 'o'}},
		{"bar", AppAddr{Addr: addr.HostFromIP(net.IPv6loopback), Port: 80},
			[]byte{0xde, 0, 0xad, 1, 0xbe, 2, 0xef, 3, 2, 0, 0, 0, 3,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
				0, 80, 'b', 'a', 'r'}}}

	Convey("Client sending message to Server using WriteTo", t, func() {
		Convey("Server should receive correct raw messages", func() {
			for _, tc := range testCases {
				Convey(fmt.Sprintf("Client sent message \"%v\"", tc.payload), func() {
					sockName := fmt.Sprintf("/tmp/reliable%v.sock", rand.Uint32())

					sc := make(chan ExitData, 1)
					go Server(sc, sockName, false)
					cc := make(chan ExitData, 1)
					go Client(cc, sockName, []byte(tc.payload), tc.dst)

					var sData ExitData
					select {
					case sData = <-sc:
					case <-time.After(3 * time.Second):
						sData = ExitData{nil, common.NewError("Server timed out")}
					}
					var cData ExitData
					select {
					case cData = <-cc:
					case <-time.After(3 * time.Second):
						cData = ExitData{nil, common.NewError("Client timed out")}
					}

					So(sData.value, ShouldResemble, tc.want)
					So(sData.err, ShouldEqual, nil)
					So(cData.err, ShouldEqual, nil)
				})
			}
		})
	})
}

func TestRegister(t *testing.T) {
	nilAddr, _ := addr.HostFromRaw(nil, addr.HostTypeNone)

	testCases := []struct {
		ia        addr.ISD_AS
		dst       AppAddr
		want      []byte
		timeoutOK bool
	}{
		{addr.ISD_AS{I: 1, A: 10}, AppAddr{Addr: nilAddr, Port: 0},
			nil, true},
		{addr.ISD_AS{I: 2, A: 21}, AppAddr{Addr: addr.HostFromIP(net.IPv4(127, 0, 0, 1)), Port: 80},
			[]byte{0xde, 0, 0xad, 1, 0xbe, 2, 0xef, 3, 0, 0, 0, 0, 13,
				3, 17, 0, 32, 0, 21, 0, 80, 1, 127, 0, 0, 1}, false},
		{addr.ISD_AS{I: 2, A: 21}, AppAddr{Addr: addr.HostFromIP(net.IPv6loopback), Port: 80},
			[]byte{0xde, 0, 0xad, 1, 0xbe, 2, 0xef, 3, 0, 0, 0, 0, 25,
				3, 17, 0, 32, 0, 21, 0, 80, 2,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, false}}

	Convey("Client registering to SCIOND", t, func() {
		Convey("SCIOND should receive correct raw messages", func() {
			for _, tc := range testCases {
				Convey(fmt.Sprintf("Client registered to %v, %v", tc.ia, tc.dst), func() {
					sockName := fmt.Sprintf("/tmp/reliable%v.sock", rand.Uint32())

					sc := make(chan ExitData, 1)
					go Server(sc, sockName, false)
					cc := make(chan ExitData, 1)
					go ClientRegister(cc, sockName, &tc.ia, tc.dst)

					var sData ExitData
					select {
					case sData = <-sc:
					case <-time.After(3 * time.Second):
						sData = ExitData{nil, common.NewError("Server timed out")}
					}
					var cData ExitData
					select {
					case cData = <-cc:
					case <-time.After(3 * time.Second):
						cData = ExitData{nil, common.NewError("Client timed out")}
					}

					So(sData.value, ShouldResemble, tc.want)
					if !tc.timeoutOK {
						So(sData.err, ShouldEqual, nil)
					}
					So(cData.err, ShouldEqual, nil)
				})
			}
		})
	})
}
