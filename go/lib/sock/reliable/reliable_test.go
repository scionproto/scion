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
	"io"
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/xtest"
)

type TestCase struct {
	msg       string
	ia        *addr.ISD_AS
	dst       *AppAddr
	bind      *AppAddr
	svc       addr.HostSVC
	want      []byte
	timeoutOK bool
}

func TestRegister(t *testing.T) {
	testCases := []TestCase{
		{
			ia: &addr.ISD_AS{I: 1, A: 10},
			dst: &AppAddr{
				Addr: addr.HostNone{},
				Port: 0,
			},
			bind: nil, svc: addr.SvcNone,
			want: nil, timeoutOK: true,
		}, {
			ia: &addr.ISD_AS{I: 2, A: 21},
			dst: &AppAddr{
				Addr: addr.HostFromIP(net.IPv4(127, 0, 0, 1)),
				Port: 80,
			},
			bind: nil, svc: addr.SvcNone,
			want: []byte{0xde, 0, 0xad, 1, 0xbe, 2, 0xef, 3, 0, 0, 0, 0, 13,
				3, 17, 0, 32, 0, 21, 0, 80, 1, 127, 0, 0, 1},
			timeoutOK: false,
		}, {
			ia:   &addr.ISD_AS{I: 2, A: 21},
			dst:  &AppAddr{Addr: addr.HostFromIP(net.IPv6loopback), Port: 80},
			bind: nil, svc: addr.SvcNone,
			want: []byte{0xde, 0, 0xad, 1, 0xbe, 2, 0xef, 3, 0, 0, 0, 0, 25,
				3, 17, 0, 32, 0, 21, 0, 80, 2,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
			timeoutOK: false,
		}, {
			ia: &addr.ISD_AS{I: 2, A: 21},
			dst: &AppAddr{
				Addr: addr.HostFromIP(net.IPv4(127, 0, 0, 1)),
				Port: 80,
			},
			bind: &AppAddr{
				Addr: addr.HostFromIP(net.IPv4(127, 0, 0, 2)),
				Port: 81,
			}, svc: addr.SvcNone,
			want: []byte{0xde, 0, 0xad, 1, 0xbe, 2, 0xef, 3, 0, 0, 0, 0, 20,
				7, 17, 0, 32, 0, 21, 0, 80, 1, 127, 0, 0, 1, 0, 81, 1, 127, 0, 0, 2},
			timeoutOK: false,
		}, {
			ia: &addr.ISD_AS{I: 2, A: 21},
			dst: &AppAddr{
				Addr: addr.HostFromIP(net.IPv4(127, 0, 0, 1)),
				Port: 80,
			},
			bind: nil, svc: addr.SvcCS,
			want: []byte{0xde, 0, 0xad, 1, 0xbe, 2, 0xef, 3, 0, 0, 0, 0, 15,
				3, 17, 0, 32, 0, 21, 0, 80, 1, 127, 0, 0, 1, 0, 2},
			timeoutOK: false,
		},
	}

	sockName := getRandFile()
	Convey("Start server", t, func() {
		listener, err := Listen(sockName)
		SoMsg("listen err", err, ShouldBeNil)
		SoMsg("listener sock", listener, ShouldNotBeNil)
		listener.SetUnlinkOnClose(true)

		Reset(func() {
			err := listener.Close()
			SoMsg("listener close error", err, ShouldBeNil)
		})

		for _, tc := range testCases {
			name := fmt.Sprintf(
				"Client registers %v, %v, %v, %s", tc.ia, tc.dst, tc.bind, tc.svc)
			Convey(name, xtest.Parallel(
				func(sc *xtest.SC) {
					server(sc, &tc, listener)
				}, func(sc *xtest.SC) {
					_, _, err := RegisterTimeout(sockName, tc.ia, tc.dst,
						tc.bind, tc.svc, time.Second)
					if tc.timeoutOK {
						sc.SoMsg("register err", err, ShouldNotBeNil)
						return
					}
					// Expect EOF error because the mocked dispatcher never replies
					sc.SoMsg("register err", err, ShouldEqual, io.EOF)
				}),
			)
		}
	})
}

func TestRegisterTimeout(t *testing.T) {
	sockName := getRandFile()
	Convey("Start dummy server", t, func() {
		listener, err := Listen(sockName)
		SoMsg("listen err", err, ShouldBeNil)
		SoMsg("listener sock", listener, ShouldNotBeNil)
		listener.SetUnlinkOnClose(true)

		Reset(func() {
			err := listener.Close()
			SoMsg("listener close error", err, ShouldBeNil)
		})
		Convey("Register to \"dispatcher\" returns timeout error", func() {
			var expectedT *net.OpError
			ia := &addr.ISD_AS{I: 1, A: 10}
			appAddr := &AppAddr{Addr: addr.HostFromIP(net.IPv4(1, 2, 3, 4)), Port: 0}

			before := time.Now()
			conn, port, err := RegisterTimeout(sockName, ia, appAddr, nil,
				addr.SvcNone, 3*time.Second)
			after := time.Now()
			SoMsg("timing", after, ShouldHappenBetween, before.Add(2*time.Second), before.Add(4*time.Second))

			SoMsg("conn", conn, ShouldBeNil)
			SoMsg("port", port, ShouldEqual, 0)
			SoMsg("err underlying type", err, ShouldHaveSameTypeAs, expectedT)
			opErr := err.(*net.OpError)
			SoMsg("timeout", opErr.Timeout(), ShouldBeTrue)
		})
	})
}

func TestWriteTo(t *testing.T) {
	testCases := []TestCase{
		{
			msg: "",
			dst: &AppAddr{
				Addr: addr.HostNone{},
				Port: 0,
			},
			want: []byte{0xde, 0, 0xad, 1, 0xbe, 2, 0xef, 3, 0, 0, 0, 0, 0},
		}, {
			msg: "test",
			dst: &AppAddr{
				Addr: addr.HostNone{},
				Port: 0,
			},
			want: []byte{0xde, 0, 0xad, 1, 0xbe, 2, 0xef, 3, 0, 0, 0, 0, 4, 't', 'e', 's', 't'},
		}, {
			msg: "foo",
			dst: &AppAddr{
				Addr: addr.HostFromIP(net.IPv4(127, 0, 0, 1)),
				Port: 80,
			},
			want: []byte{0xde, 0, 0xad, 1, 0xbe, 2, 0xef, 3, 1, 0, 0, 0, 3,
				127, 0, 0, 1, 0, 80, 'f', 'o', 'o'},
		}, {
			msg: "bar",
			dst: &AppAddr{
				Addr: addr.HostFromIP(net.IPv6loopback),
				Port: 80,
			},
			want: []byte{0xde, 0, 0xad, 1, 0xbe, 2, 0xef, 3, 2, 0, 0, 0, 3,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
				0, 80, 'b', 'a', 'r'},
		},
	}

	sockName := getRandFile()
	Convey("Start server", t, func() {
		listener, err := Listen(sockName)
		SoMsg("listen err", err, ShouldBeNil)
		SoMsg("listener sock", listener, ShouldNotBeNil)
		listener.SetUnlinkOnClose(true)

		Reset(func() {
			err := listener.Close()
			SoMsg("listener close error", err, ShouldBeNil)
		})
		for _, tc := range testCases {
			Convey(fmt.Sprintf("Clients sends message %v", tc.msg), xtest.Parallel(
				func(sc *xtest.SC) {
					server(sc, &tc, listener)
				}, func(sc *xtest.SC) {
					cconn, err := DialTimeout(sockName, time.Second)
					sc.SoMsg("dial err", err, ShouldBeNil)

					n, err := cconn.WriteTo([]byte(tc.msg), *tc.dst)
					sc.SoMsg("client write err", err, ShouldBeNil)
					sc.SoMsg("client written bytes", n, ShouldEqual, len(tc.msg))

					err = cconn.Close()
					sc.SoMsg("client close", err, ShouldBeNil)
				}),
			)
		}
	})
}

func server(sc *xtest.SC, tc *TestCase, listener *Listener) {
	err := listener.SetDeadline(time.Now().Add(time.Second))
	sc.SoMsg("listener deadline err", err, ShouldBeNil)

	sconn, err := listener.Accept()
	if tc.timeoutOK {
		sc.SoMsg("accept err", err, ShouldNotBeNil)
		return
	}
	sc.SoMsg("accept err", err, ShouldBeNil)
	sc.SoMsg("server conn", sconn, ShouldNotBeNil)

	b := make([]byte, len(tc.want))
	_, err = io.ReadFull(sconn.UnixConn, b)
	sc.SoMsg("server read err", err, ShouldBeNil)
	sc.SoMsg("server read msg", b, ShouldResemble, tc.want)

	err = sconn.Close()
	sc.SoMsg("server close", err, ShouldBeNil)
}

func getRandFile() string {
	testDir := "/tmp/reliable"
	if _, err := os.Stat(testDir); os.IsNotExist(err) {
		os.Mkdir(testDir, 0700)
	}

	r := uint32(time.Now().UnixNano() + int64(os.Getpid()))
	suffix := strconv.Itoa(int(1e9 + r%1e9))[1:]
	return testDir + "/unix." + suffix
}
