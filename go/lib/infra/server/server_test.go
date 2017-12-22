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

package server

import (
	"context"
	"net"
	"testing"
	"time"

	log "github.com/inconshreveable/log15"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/cert_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/api"
	"github.com/scionproto/scion/go/lib/infra/disp"
	"github.com/scionproto/scion/go/lib/infra/messaging"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/lib/xtest/p2p"
	"github.com/scionproto/scion/go/proto"
)

// TestCase data
var (
	mockTRC = &cert_mgmt.TRC{RawTRC: common.RawBytes("foobar")}
)

func MockTRCRequestConstructor(data interface{}, peer net.Addr) infra.Handler {
	return &MockTRCRequest{peer: peer}
}

var _ infra.Handler = (*MockTRCRequest)(nil)

type MockTRCRequest struct {
	peer net.Addr
}

func (r *MockTRCRequest) Handle(ctx context.Context) {
	v := ctx.Value(api.MessengerContextKey)
	if v == nil {
		log.Warn("Unable to service request, no Messenger interface found")
		return
	}
	messenger, ok := v.(*api.Messenger)
	if !ok {
		log.Warn("Unable to service request, bad Messenger value found")
		return
	}
	subCtx, cancelF := context.WithTimeout(ctx, 3*time.Second)
	defer cancelF()
	if err := messenger.SendTRC(subCtx, mockTRC, &MockAddress{}); err != nil {
		log.Error("Server error", "err", err)
	}
}

type MockAddress struct{}

func (m *MockAddress) Network() string {
	return "mock network"
}

func (m *MockAddress) String() string {
	return "mock address"
}

func TestTRCExchange(t *testing.T) {
	Convey("Setup", t, func() {
		c2s, s2c := p2p.New()
		clientMessenger := setupMessenger(c2s, "client")
		serverMessenger := setupMessenger(s2c, "server")
		server := New(serverMessenger, log.New("name", "server"))

		Convey("Client/server", xtest.Parallel(func(sc *xtest.SC) {
			// Client
			ctx, cancelF := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancelF()

			msg := &cert_mgmt.TRCReq{ISD: 42, Version: 1337, CacheOnly: true}
			trc, err := clientMessenger.GetTRC(ctx, msg, &MockAddress{})
			sc.SoMsg("client request err", err, ShouldBeNil)
			sc.SoMsg("client received trc", trc, ShouldResemble, mockTRC)

			// Exchange finished, shut down server
			server.Close()
		}, func(sc *xtest.SC) {
			// Server
			server.AddHandler(proto.TRCReq_TypeID, MockTRCRequestConstructor)
			server.ListenAndServe()
		}))
	})
}

func setupMessenger(conn net.PacketConn, name string) *api.Messenger {
	transport := messaging.NewRUDP(conn, log.New("name", name))
	dispatcher := disp.NewDispatcher(transport, api.DefaultAdapter, log.New("name", name))
	return api.New(dispatcher)
}
