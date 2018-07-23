// Copyright 2017 ETH Zurich
// Copyright 2018 Anapaya Systems
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

package disp

import (
	"context"
	"net"
	"os"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/infra/transport"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/lib/xtest/p2p"
)

var (
	testCases = []struct {
		name  string
		setup func(t *testing.T) (*Dispatcher, *Dispatcher, *customObject, *customObject,
			net.Addr, net.Addr)
		timeout time.Duration
	}{
		{
			"PacketTransport",
			packetSetup,
			50 * time.Millisecond,
		},
		{
			"QuicTransport",
			quicSetup,
			200 * time.Millisecond,
		},
	}
)

func packetSetup(t *testing.T) (*Dispatcher, *Dispatcher, *customObject, *customObject,
	net.Addr, net.Addr) {
	a2b, b2a := p2p.New()
	dispA := New(transport.NewPacketTransport(a2b), testAdapter, log.Root())
	dispB := New(transport.NewPacketTransport(b2a), testAdapter, log.Root())
	request := &customObject{8, "request"}
	reply := &customObject{8, "reply"}
	return dispA, dispB, request, reply, &p2p.Addr{}, &p2p.Addr{}
}

func quicSetup(t *testing.T) (*Dispatcher, *Dispatcher, *customObject, *customObject,
	net.Addr, net.Addr) {
	a2b, err := net.ListenPacket("udp", "127.0.0.1:")
	xtest.FailOnErr(t, err)
	b2a, err := net.ListenPacket("udp", "127.0.0.1:")
	xtest.FailOnErr(t, err)
	addrA := a2b.LocalAddr()
	addrB := b2a.LocalAddr()
	trA, err := transport.NewQuicTransport(a2b, nil, nil, "testdata/tls.pem", "testdata/tls.key")
	xtest.FailOnErr(t, err)
	log.Debug("Init a")
	trB, err := transport.NewQuicTransport(b2a, nil, nil, "testdata/tls.pem", "testdata/tls.key")
	xtest.FailOnErr(t, err)
	log.Debug("Init b")
	dispA := New(trA, testAdapter, log.Root())
	dispB := New(trB, testAdapter, log.Root())
	request := &customObject{8, "request"}
	reply := &customObject{8, "reply"}
	return dispA, dispB, request, reply, addrA, addrB
}

func TestRequestReply(t *testing.T) {
	Convey("TestRequestReply", t, func() {
		for _, tc := range testCases {
			Convey(tc.name+": Setup", func() {
				dispA, dispB, request, reply, addrA, addrB := tc.setup(t)
				Convey("Request and reply (Parallel)", xtest.Parallel(func(sc *xtest.SC) {
					ctx, cancelF := context.WithTimeout(context.Background(), tc.timeout)
					defer cancelF()
					recvReply, err := dispA.Request(ctx, request, addrB)
					sc.SoMsg("a request err", err, ShouldBeNil)
					sc.SoMsg("a request reply", recvReply, ShouldResemble, reply)
				}, func(sc *xtest.SC) {
					ctx, cancelF := context.WithTimeout(context.Background(), tc.timeout)
					defer cancelF()
					recvRequest, _, err := dispB.RecvFrom(ctx)
					sc.SoMsg("b recv err", err, ShouldBeNil)
					sc.SoMsg("b recv msg", recvRequest, ShouldResemble, request)
					err = dispB.Notify(ctx, reply, addrA)
					sc.SoMsg("b notify err", err, ShouldBeNil)
				}))
			})
		}
	})
}

func TestRequestNoReceiver(t *testing.T) {
	Convey("TestRequestNoReceiver", t, func() {
		for _, tc := range testCases {
			Convey(tc.name+": Setup", func() {
				dispA, _, request, _, _, addrB := tc.setup(t)
				Convey("Request without receiver", func() {
					ctx, cancelF := context.WithTimeout(context.Background(), tc.timeout)
					defer cancelF()
					recvReply, err := dispA.Request(ctx, request, addrB)
					SoMsg("a request err", err, ShouldNotBeNil)
					SoMsg("a request err timeout", common.IsTimeoutErr(err), ShouldBeTrue)
					SoMsg("a request reply", recvReply, ShouldBeNil)
				})
			})
		}
	})
}

func TestRequestBadReply(t *testing.T) {
	Convey("TestRequestBadReply", t, func() {
		for _, tc := range testCases {
			Convey(tc.name+":Setup", func() {
				dispA, dispB, request, _, addrA, addrB := tc.setup(t)
				Convey("Request, and receive bad reply (Parallel)",
					xtest.Parallel(func(sc *xtest.SC) {
						ctx, cancelF := context.WithTimeout(context.Background(), tc.timeout)
						defer cancelF()
						recvReply, err := dispA.Request(ctx, request, addrB)
						sc.SoMsg("a request err", err, ShouldNotBeNil)
						sc.SoMsg("a request err timeout", common.IsTimeoutErr(err), ShouldBeTrue)
						sc.SoMsg("a request reply", recvReply, ShouldBeNil)
					}, func(sc *xtest.SC) {
						ctx, cancelF := context.WithTimeout(context.Background(), tc.timeout)
						defer cancelF()
						// Create reply with bad ID
						badReply := &customObject{73, "reply"}

						recvRequest, _, err := dispB.RecvFrom(ctx)
						sc.SoMsg("b recv err", err, ShouldBeNil)
						sc.SoMsg("b recv msg", recvRequest, ShouldResemble, request)
						err = dispB.Notify(ctx, badReply, addrA)
						sc.SoMsg("b notify err", err, ShouldBeNil)
					}))
			})
		}
	})
}

func TestNotifyOk(t *testing.T) {
	Convey("TestNotifyOk", t, func() {
		for _, tc := range testCases {
			Convey(tc.name+": Setup", func() {
				dispA, dispB, notification, _, _, addrB := tc.setup(t)
				Convey("Notify and receive (Parallel)",
					xtest.Parallel(func(sc *xtest.SC) {
						ctx, cancelF := context.WithTimeout(context.Background(), tc.timeout)
						defer cancelF()
						err := dispA.Notify(ctx, notification, addrB)
						sc.SoMsg("a notify err", err, ShouldBeNil)
					}, func(sc *xtest.SC) {
						ctx, cancelF := context.WithTimeout(context.Background(), tc.timeout)
						defer cancelF()
						recvNotification, _, err := dispB.RecvFrom(ctx)
						sc.SoMsg("b recv err", err, ShouldBeNil)
						sc.SoMsg("b recv notification", recvNotification,
							ShouldResemble, notification)
					}))
			})
		}
	})
}

func TestUnreliableNotify(t *testing.T) {
	Convey("TestUnreliableNotify", t, func() {
		tc := testCases[0] // Makes only sense for un-reliable transport.
		Convey(tc.name+": Setup", func() {
			dispA, dispB, notification, _, _, addrB := tc.setup(t)
			Convey("Unreliable notify and return immediately", func() {
				// Close dispB to make sure its transport layer doesn't ACK
				ctx, cancelF := context.WithTimeout(context.Background(), tc.timeout)
				defer cancelF()
				dispB.Close(ctx)
				ctx2, cancelF2 := context.WithTimeout(context.Background(), tc.timeout)
				defer cancelF2()
				err := dispA.NotifyUnreliable(ctx2, notification, addrB)
				SoMsg("a notify err", err, ShouldBeNil)
			})
		})
	})
}

func TestMain(m *testing.M) {
	l := log.Root()
	l.SetHandler(log.DiscardHandler())
	os.Exit(m.Run())
}
